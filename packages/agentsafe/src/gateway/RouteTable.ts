import {
  CONSEQUENTIAL_METHODS,
  type ConsequentialMethod,
  type RouteConfig,
  type UnmatchedPolicy,
} from "./GatewayConfig.js";

/** What the gateway decided about one request before reading its body. */
export type RoutePlan =
  | { readonly kind: "PASSTHROUGH"; readonly reason: "SAFE_METHOD" | "UNMATCHED" | "DISABLED" }
  | { readonly kind: "GOVERN"; readonly action: string; readonly route: RouteConfig | null };

const SEGMENT_WILDCARD = "*";
const TREE_WILDCARD = "**";

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
 * called. A safe method is never consequential. An unsafe request the table
 * does not name is governed under a derived name unless the configuration
 * chose passthrough, so narrowing what is governed is an explicit act.
 */
export class RouteTable {
  private readonly routes: readonly CompiledRoute[];

  public constructor(
    routes: readonly RouteConfig[],
    private readonly unmatched: UnmatchedPolicy,
    private readonly enabled: boolean = true,
  ) {
    this.routes = routes.map((config) => ({
      config,
      segments: segmentsOf(config.path),
      methods: new Set(config.methods),
    }));
  }

  /** Every action name this table can produce, for the registry to be sealed over. */
  public actions(): readonly string[] {
    const names = new Set<string>(CONSEQUENTIAL_METHODS.map((method) => derivedAction(method)));
    for (const route of this.routes) names.add(route.config.action);
    return [...names];
  }

  public plan(method: string, pathname: string): RoutePlan {
    if (!this.enabled) return { kind: "PASSTHROUGH", reason: "DISABLED" };
    const upper = method.toUpperCase();
    if (!(CONSEQUENTIAL_METHODS as readonly string[]).includes(upper)) {
      return { kind: "PASSTHROUGH", reason: "SAFE_METHOD" };
    }
    const consequential = upper as ConsequentialMethod;
    const path = segmentsOf(pathname);
    for (const route of this.routes) {
      if (route.methods.has(consequential) && matches(route.segments, path)) {
        return { kind: "GOVERN", action: route.config.action, route: route.config };
      }
    }
    if (this.unmatched === "PASSTHROUGH") return { kind: "PASSTHROUGH", reason: "UNMATCHED" };
    return { kind: "GOVERN", action: derivedAction(consequential), route: null };
  }
}
