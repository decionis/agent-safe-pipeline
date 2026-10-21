import type { ApiProfile } from "@decionis/agent-safe-pipeline";
import {
  CONSEQUENTIAL_METHODS,
  type ConsequentialMethod,
  type PrivacyMode,
  type RouteConfig,
  type UnmatchedPolicy,
} from "./GatewayConfig.js";

/**
 * What the gateway does with a read. `PASSTHROUGH` is today's: never
 * evaluated. `CHECK` checks a read a profile operation names against the
 * session's subject and passes the rest. `REFUSE_UNKNOWN` also refuses a
 * read no profile operation names.
 */
export type ReadPolicy = "PASSTHROUGH" | "CHECK" | "REFUSE_UNKNOWN";

/** What the gateway decided about one request before reading its body. */
export type RoutePlan =
  | { readonly kind: "PASSTHROUGH"; readonly reason: "SAFE_METHOD" | "UNMATCHED" | "DISABLED" }
  | {
      readonly kind: "REFUSE";
      readonly code:
        | "HTTP_METHOD_UNSUPPORTED"
        | "HTTP_PATH_AMBIGUOUS"
        | "PROFILE_OPERATION_UNMATCHED"
        | "READ_OPERATION_UNMATCHED";
    }
  | {
      /** A read a profile operation names: checked against the session's subject, never decided. */
      readonly kind: "CHECK";
      readonly action: string;
      readonly operation: string;
    }
  | {
      readonly kind: "GOVERN";
      readonly action: string;
      readonly route: RouteConfig | null;
      /** The API profile operation that named the action, when a profile did. */
      readonly operation?: string;
    };

/** A request's query, as the gateway reads it for planning: each name to one value or a list. */
export type PlanQuery = { readonly [key: string]: string | readonly string[] };

const SEGMENT_WILDCARD = "*";
const TREE_WILDCARD = "**";
const SAFE_METHODS: ReadonlySet<string> = new Set(["GET", "HEAD", "OPTIONS"]);
const AMBIGUOUS_PATH_CHARACTERS: ReadonlySet<string> = new Set(["\\", "%", ";", "?", "#"]);

/**
 * A pattern, split once at construction. `/payments` matches itself;
 * `/payments/*` one more segment; `/payments/**` anything below; `:name`
 * one segment of any value. Matching is a walk over segments, linear in
 * the path, with nothing that backtracks.
 */
interface CompiledRoute {
  readonly config: RouteConfig;
  readonly segments: readonly string[];
  readonly methods: ReadonlySet<string>;
}

function segmentsOf(path: string): readonly string[] {
  return path.split("/").filter((segment) => segment !== "");
}

/**
 * Match decoded literal characters without rewriting the forwarded path.
 * Refuse encodings that change segment boundaries or admit another decoding
 * or path-parameter interpretation at the upstream's router.
 */
function routingSegments(path: string): readonly string[] | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    return null;
  }
  if (path.split("/").length !== decoded.split("/").length) return null;
  for (const character of decoded) {
    const code = character.charCodeAt(0);
    if (AMBIGUOUS_PATH_CHARACTERS.has(character) || code < 32 || code === 127) return null;
  }
  const segments = segmentsOf(decoded);
  if (segments.some((segment) => segment === "." || segment === "..")) return null;
  return segments;
}

function matches(pattern: readonly string[], path: readonly string[]): boolean {
  let index = 0;
  for (; index < pattern.length; index += 1) {
    const expected = pattern[index] ?? "";
    if (expected === TREE_WILDCARD) return true;
    const actual = path[index];
    if (actual === undefined) return false;
    if (expected === SEGMENT_WILDCARD || expected.startsWith(":")) continue;
    if (expected !== actual) return false;
  }
  return index === path.length;
}

/** The derived action for an unsafe request no route names. */
export function derivedAction(method: ConsequentialMethod): string {
  return `http.${method.toLowerCase()}`;
}

/**
 * The route table: which requests are consequential, and what each is
 * called. A safe method is never consequential. An explicit route is tried
 * first, then the API profile's operations, when the gateway governs by one
 * (`agent-safe.profile.api/1`). An unsafe request neither names is governed
 * under a derived name unless the configuration chose passthrough, so
 * narrowing what is governed is an explicit act. In facts-only privacy the
 * profile alone names a call: what it does not name is refused, because
 * governing it would send the authority its raw path.
 */
export class RouteTable {
  private readonly routes: readonly CompiledRoute[];

  public constructor(
    routes: readonly RouteConfig[],
    private readonly unmatched: UnmatchedPolicy,
    private readonly enabled: boolean = true,
    private readonly profile: ApiProfile | null = null,
    private readonly privacy: PrivacyMode = "FULL",
    private readonly reads: ReadPolicy = "PASSTHROUGH",
  ) {
    this.routes = routes.map((config) => {
      const segments = routingSegments(config.path);
      // Pattern syntax is literal configuration. Encoded wildcards must not
      // turn into routing operators as a side effect of decoding.
      if (segments === null || config.path.includes("%")) throw new Error("ROUTE_PATH_AMBIGUOUS");
      return { config, segments, methods: new Set(config.methods) };
    });
  }

  /** Every action name this table can produce, for the registry to be sealed over. */
  public actions(): readonly string[] {
    const names = new Set<string>(CONSEQUENTIAL_METHODS.map((method) => derivedAction(method)));
    for (const route of this.routes) names.add(route.config.action);
    for (const action of this.profile?.actions() ?? []) names.add(action);
    return [...names];
  }

  /**
   * A read, when reads are checked. A `GET` a profile operation names is
   * checked. One that only resembles an operation (another letter case, an
   * encoded literal) is refused as ambiguous, since the upstream may serve
   * it as that operation. A `HEAD` or `OPTIONS` on a checked read's path is
   * refused: it has no answer to check, and its status alone says whether a
   * record exists. Anything else passes, or is refused when unknown reads are.
   */
  private planRead(method: string, pathname: string, query: PlanQuery): RoutePlan {
    if (this.reads === "PASSTHROUGH" || this.profile === null) {
      return { kind: "PASSTHROUGH", reason: "SAFE_METHOD" };
    }
    const operation = method === "GET" ? this.profile.operationFor("GET", pathname, query) : null;
    if (operation !== null) {
      return { kind: "CHECK", action: operation.action, operation: operation.id };
    }
    const resembles = this.profile.resembles("GET", pathname);
    if (this.reads === "REFUSE_UNKNOWN" || (resembles && method !== "GET")) {
      return { kind: "REFUSE", code: "READ_OPERATION_UNMATCHED" };
    }
    if (resembles) return { kind: "REFUSE", code: "HTTP_PATH_AMBIGUOUS" };
    return { kind: "PASSTHROUGH", reason: "SAFE_METHOD" };
  }

  public plan(method: string, pathname: string, query: PlanQuery = {}): RoutePlan {
    if (!this.enabled) return { kind: "PASSTHROUGH", reason: "DISABLED" };
    const upper = method.toUpperCase();
    if (SAFE_METHODS.has(upper)) return this.planRead(upper, pathname, query);
    // WebDAV and extension methods can mutate state too. A method outside
    // this execution contract cannot inherit the privilege of a safe read.
    if (!(CONSEQUENTIAL_METHODS as readonly string[]).includes(upper)) {
      return { kind: "REFUSE", code: "HTTP_METHOD_UNSUPPORTED" };
    }
    const consequential = upper as ConsequentialMethod;
    const path = routingSegments(pathname);
    if (path === null) return { kind: "REFUSE", code: "HTTP_PATH_AMBIGUOUS" };
    const factsOnly = this.privacy === "FACTS";
    for (const route of factsOnly ? [] : this.routes) {
      if (route.methods.has(consequential) && matches(route.segments, path)) {
        return { kind: "GOVERN", action: route.config.action, route: route.config };
      }
    }
    const operation = this.profile?.operationFor(consequential, pathname, query) ?? null;
    if (operation !== null) {
      return { kind: "GOVERN", action: operation.action, route: null, operation: operation.id };
    }
    if (factsOnly) return { kind: "REFUSE", code: "PROFILE_OPERATION_UNMATCHED" };
    if (this.unmatched === "PASSTHROUGH") return { kind: "PASSTHROUGH", reason: "UNMATCHED" };
    return { kind: "GOVERN", action: derivedAction(consequential), route: null };
  }
}
