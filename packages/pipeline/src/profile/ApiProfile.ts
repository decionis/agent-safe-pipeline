import { z } from "zod";
import type { JsonObject, JsonPrimitive, JsonValue } from "../intent/JsonValue.js";

/**
 * `agent-safe.profile.api/1`: a platform API described as data, so that every
 * component that turns one of its calls into an intent turns it into the same
 * one. A profile maps method + path (and, where an API overloads a path, an
 * exact query value) to an action type, and names the facts a decision reads
 * by JSON pointer into the call. The gateway reads it to govern an agent's
 * call; a native executor's `prepare` reads it to describe the call it is
 * about to make. One mapping, no code coupling between them.
 *
 * An operation may also say where the subject sits (the customer a call is
 * for): in the call, and, for a read, in each item of its answer. A component
 * that pins a session to one subject checks a read against it, and states the
 * subject to the authority for a write. A read is an operation only for that:
 * it is checked, never decided.
 */
export const API_PROFILE_CONTRACT = "agent-safe.profile.api/1";

export const API_PROFILE_SCHEMA_ID =
  "https://github.com/decionis/agent-safe-pipeline/blob/master/spec/profiles/api/v1/schema.json";

/** The methods a profile governs: each operation of one is decided by the authority. */
export const API_PROFILE_METHODS = ["POST", "PUT", "PATCH", "DELETE"] as const;
export type ApiProfileMethod = (typeof API_PROFILE_METHODS)[number];
/** The one read method an operation may name: checked for its subject, never decided. */
export const API_PROFILE_READ_METHOD = "GET";

/**
 * Fact names a profile may not use. The first group is what the gateway
 * already states in an intent's context; the second is what the Decionis
 * authority states itself, or reads from the request rather than the context,
 * so a fact of that name would be shadowed or refused there.
 */
export const RESERVED_FACT_NAMES: readonly string[] = [
  "request_sha256",
  "request_hmac_sha256",
  "body_sha256",
  "body_bytes",
  "content_type",
  "body_embedded",
  "ingress",
  "claimed_principal",
  "api_profile",
  "agent_safe",
  "action_context",
  "amount",
  "risk_score",
  "channel",
  "objective_profile",
  "mode",
  "decision_band",
  "transaction_type",
  "workflow_key",
  "vertical_pack",
  "policy_version",
  "org_id",
  "decision_type",
  "decision_domain",
  "signals",
  "signal_provenance",
  "history",
  "override",
  "evidence",
  "attachments",
  "attachment_count",
  "policy",
  "context",
  "intake",
  "runtime_attribution",
  "session",
];

/** The most elements one `*` pointer collects; more is not a fact, it is a payload. */
export const MAX_FACT_ELEMENTS = 100;
/** The longest string a fact carries; a longer value is not stated. */
export const MAX_FACT_STRING = 1000;
/** The longest subject: an identifier, never a payload. */
export const MAX_SUBJECT_LENGTH = 200;

const PLACEHOLDER = /\{([A-Z]\w{0,63})\}/gi;
const TEMPLATE = /^(\/[^/?#%\\\s]+)+$/;
const POINTER = /^\/(path|query|body)(\/.*)?$/;
const RESPONSE_POINTER = /^\/body(\/.*)?$/;

const name = z.string().regex(/^[a-z][a-z0-9_]{0,63}$/);
const projectionText = z.string().trim().min(1).max(120);

export const ApiPolicyProjectionSchema = z.strictObject({
  decision_type: projectionText,
  transaction_type: projectionText.nullable(),
  workflow_key: projectionText.nullable(),
  channel: projectionText.nullable(),
});

/**
 * Where an operation's subject sits: `request`, a pointer into the call like
 * a fact's, with no `*`; `response`, for a read, a pointer into its answer's
 * JSON body, where one `*` reaches every item of a list.
 */
export const ApiSubjectSchema = z.strictObject({
  request: z.string().max(300).regex(POINTER).optional(),
  response: z.string().max(300).regex(RESPONSE_POINTER).optional(),
});

export const ApiOperationSchema = z.strictObject({
  /** The operation's name in the profile, unique, dotted lower camel case. */
  id: z
    .string()
    .regex(/^[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*)*$/)
    .max(120),
  method: z.enum([...API_PROFILE_METHODS, API_PROFILE_READ_METHOD]),
  /** A path template: literal text and `{name}` placeholders, each within one segment. */
  path: z.string().max(500).regex(TEMPLATE),
  /** Exact query values the call must carry to be this operation (an API that overloads a path). */
  query: z.record(z.string().regex(/^[a-z][\w.-]{0,63}$/), z.string().max(200)).optional(),
  /** The intent's action type. */
  action: z
    .string()
    .max(120)
    .regex(/^[a-z][a-z0-9._:-]*$/),
  summary: z.string().trim().min(1).max(300),
  /** Fact name → RFC 6901 pointer into `{ path, query, body }`; one `*` segment collects an array. */
  facts: z.record(name, z.string().max(300).regex(POINTER)),
  /** The policy path the authority decides the call under, when the profile states one. */
  policy_projection: ApiPolicyProjectionSchema.nullable(),
  /** Where the call's subject sits; required of a read, optional for a write. */
  subject: ApiSubjectSchema.optional(),
});

export const ApiProfileDefinitionSchema = z.strictObject({
  profile: z.literal(API_PROFILE_CONTRACT),
  /** `<platform>/<api>/<version>`, the profile's directory under `profiles/`. */
  id: z
    .string()
    .regex(/^[a-z][a-z0-9]*\/[a-z][a-z0-9]*\/v\d+(\.\d+)?$/)
    .max(120),
  platform: z
    .string()
    .regex(/^[a-z][a-z0-9-]*$/)
    .max(80),
  title: z.string().trim().min(1).max(200),
  /** Path templates an operation's path may follow; `""` is the bare path. Tried in order. */
  prefixes: z
    .array(z.union([z.literal(""), z.string().max(300).regex(TEMPLATE)]))
    .min(1)
    .max(8),
  operations: z.array(ApiOperationSchema).min(1).max(200),
});

export type ApiPolicyProjection = z.infer<typeof ApiPolicyProjectionSchema>;
export type ApiSubject = z.infer<typeof ApiSubjectSchema>;
export type ApiOperationDefinition = z.infer<typeof ApiOperationSchema>;
export type ApiProfileDefinition = z.infer<typeof ApiProfileDefinitionSchema>;

/** One call as a component is about to make it, or as the gateway received it. */
export interface ApiRequest {
  readonly method: string;
  /** The URL path, as sent (percent-encoded); without query or fragment. */
  readonly path: string;
  readonly query?: { readonly [key: string]: string | readonly string[] };
  /** The parsed JSON body, when there is one. */
  readonly body?: JsonValue;
}

/** What a profile says about one call. */
export interface ApiProfileMatch {
  readonly profile: string;
  readonly operation: string;
  readonly action: string;
  /** Every fact whose pointer resolved to a statable value; the others are absent. */
  readonly facts: JsonObject;
  readonly policyProjection: ApiPolicyProjection | null;
  /**
   * The call's subject, when the operation names where it sits in the call:
   * a string or a finite number, as a string; null when the pointer found
   * neither. Absent when the operation names no request subject.
   */
  readonly subject?: string | null;
}

/**
 * A subject check's answer. `MATCH` is the only one that lets a call or an
 * answer through; every other is a refusal, and each says why without saying
 * whose record it was.
 */
export type ApiSubjectCheck =
  | "MATCH"
  | "SUBJECT_ABSENT"
  | "SUBJECT_MISMATCH"
  | "RESPONSE_UNREADABLE"
  | "RESPONSE_SUBJECT_ABSENT"
  | "RESPONSE_SUBJECT_MISMATCH";

export class ApiProfileError extends Error {
  public constructor(
    public readonly code: "API_PROFILE_INVALID",
    public readonly detail: string,
  ) {
    super(code);
    this.name = "ApiProfileError";
  }
}

interface CompiledOperation {
  readonly definition: ApiOperationDefinition;
  /** One matcher per prefix, in the profile's prefix order. */
  readonly matchers: readonly RegExp[];
  /** The same matchers, case-insensitive: what `resembles` asks. */
  readonly loose: readonly RegExp[];
  readonly placeholders: readonly (readonly string[])[];
}

/**
 * One profile, validated and compiled. Matching is deterministic and total:
 * the first operation, in profile order, whose method, path and query match
 * is the call's operation; a call no operation matches is not described by
 * the profile and the caller decides what that means.
 */
export class ApiProfile {
  private readonly compiled: readonly CompiledOperation[];

  private constructor(public readonly definition: ApiProfileDefinition) {
    const ids = new Set<string>();
    const signatures = new Set<string>();
    this.compiled = definition.operations.map((operation) => {
      if (ids.has(operation.id))
        throw new ApiProfileError("API_PROFILE_INVALID", `duplicate operation ${operation.id}`);
      ids.add(operation.id);
      const signature = `${operation.method} ${operation.path.replace(PLACEHOLDER, "{}")} ${JSON.stringify(
        Object.entries(operation.query ?? {}).sort(([a], [b]) => a.localeCompare(b)),
      )}`;
      if (signatures.has(signature))
        throw new ApiProfileError(
          "API_PROFILE_INVALID",
          `operation ${operation.id} repeats another operation's method, path and query`,
        );
      signatures.add(signature);
      for (const fact of Object.keys(operation.facts)) {
        if (RESERVED_FACT_NAMES.includes(fact))
          throw new ApiProfileError(
            "API_PROFILE_INVALID",
            `operation ${operation.id} names the reserved fact ${fact}`,
          );
      }
      for (const pointer of Object.values(operation.facts))
        ApiProfile.pointerSegments(pointer, operation.id);
      ApiProfile.subjectRules(operation);
      const matchers: RegExp[] = [];
      const placeholders: string[][] = [];
      for (const prefix of definition.prefixes) {
        const { pattern, names } = ApiProfile.compile(`${prefix}${operation.path}`, operation.id);
        matchers.push(pattern);
        placeholders.push(names);
      }
      return {
        definition: operation,
        matchers,
        loose: matchers.map((matcher) => new RegExp(matcher.source, "i")),
        placeholders,
      };
    });
  }

  /** Validates a definition (closed schema, unique operations, pointers, reserved names) and compiles it. */
  public static parse(value: unknown): ApiProfile {
    const parsed = ApiProfileDefinitionSchema.safeParse(value);
    if (!parsed.success)
      throw new ApiProfileError(
        "API_PROFILE_INVALID",
        parsed.error.issues
          .slice(0, 3)
          .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
          .join("; "),
      );
    return new ApiProfile(parsed.data);
  }

  public get id(): string {
    return this.definition.id;
  }

  public get platform(): string {
    return this.definition.platform;
  }

  /**
   * Every action type the profile's writes can produce, for a registry to be
   * sealed over. A read's action names it in reports; it is never an intent.
   */
  public actions(): readonly string[] {
    return [
      ...new Set(
        this.definition.operations
          .filter((operation) => !ApiProfile.isRead(operation))
          .map((operation) => operation.action),
      ),
    ];
  }

  /** Whether an operation is a read: checked for its subject, never decided. */
  public static isRead(operation: ApiOperationDefinition): boolean {
    return operation.method === API_PROFILE_READ_METHOD;
  }

  /** A call's subject against the session's: `MATCH`, or why not. */
  public static checkRequest(
    match: ApiProfileMatch,
    subject: string,
  ): "MATCH" | "SUBJECT_ABSENT" | "SUBJECT_MISMATCH" {
    if (match.subject === undefined) return "MATCH";
    if (match.subject === null) return "SUBJECT_ABSENT";
    return match.subject === subject ? "MATCH" : "SUBJECT_MISMATCH";
  }

  /**
   * A read's answer against the session's subject, before any of it is
   * relayed: every item the operation's response pointer reaches must name
   * the subject. One item naming another is `RESPONSE_SUBJECT_MISMATCH`, one
   * naming none `RESPONSE_SUBJECT_ABSENT`, and an answer the pointer cannot
   * be walked into (not JSON, or no list where the `*` stands)
   * `RESPONSE_UNREADABLE`. Nothing is filtered: a partial answer would look
   * complete. An empty list names no one and matches. Null when the
   * operation names no response subject, so there is nothing to check.
   */
  public checkResponse(
    operationId: string,
    body: JsonValue | undefined,
    subject: string,
  ): ApiSubjectCheck | null {
    const pointer = this.operation(operationId)?.subject?.response;
    if (pointer === undefined) return null;
    if (body === undefined) return "RESPONSE_UNREADABLE";
    const tokens = ApiProfile.pointerSegments(pointer, operationId);
    const root: JsonObject = { body };
    const wildcard = tokens.indexOf("*");
    const items =
      wildcard === -1
        ? [ApiProfile.walk(root, tokens)]
        : ApiProfile.walkList(root, tokens.slice(0, wildcard), tokens.slice(wildcard + 1));
    if (items === null) return "RESPONSE_UNREADABLE";
    let absent = false;
    for (const item of items) {
      const named = ApiProfile.subjectOf(item);
      if (named === null) absent = true;
      else if (named !== subject) return "RESPONSE_SUBJECT_MISMATCH";
    }
    return absent ? "RESPONSE_SUBJECT_ABSENT" : "MATCH";
  }

  public operation(id: string): ApiOperationDefinition | null {
    return this.definition.operations.find((operation) => operation.id === id) ?? null;
  }

  /**
   * The operation a method, path and query select, before any body is read:
   * what the gateway needs to decide whether to govern a call.
   */
  public operationFor(
    method: string,
    path: string,
    query: ApiRequest["query"] = {},
  ): ApiOperationDefinition | null {
    return this.select(method, path, query)?.operation.definition ?? null;
  }

  /**
   * Whether a call reads like one of this method's operations without
   * matching it exactly: its path in another letter case, or with a literal
   * percent-encoded. An upstream that folds case or decodes before it routes
   * would serve it as that operation, so a component that checks reads
   * refuses it rather than let it through unchecked. A path that does not
   * decode resembles everything.
   */
  public resembles(method: string, path: string): boolean {
    let decoded: string;
    try {
      decoded = decodeURIComponent(path);
    } catch {
      return true;
    }
    const upper = method.toUpperCase();
    return this.compiled.some(
      (operation) =>
        operation.definition.method === upper &&
        operation.loose.some((matcher) => matcher.test(path) || matcher.test(decoded)),
    );
  }

  /** The operation, action type, facts and policy projection of one call; null when no operation matches. */
  public match(request: ApiRequest): ApiProfileMatch | null {
    const selected = this.select(request.method, request.path, request.query ?? {});
    if (selected === null) return null;
    const { operation, parameters } = selected;
    const root: JsonObject = {
      path: parameters,
      query: ApiProfile.queryRoot(request.query ?? {}),
      ...(request.body === undefined ? {} : { body: request.body }),
    };
    const facts: JsonObject = {};
    for (const [fact, pointer] of Object.entries(operation.definition.facts)) {
      const value = ApiProfile.read(
        root,
        ApiProfile.pointerSegments(pointer, operation.definition.id),
      );
      if (value !== undefined) facts[fact] = value;
    }
    const subjectPointer = operation.definition.subject?.request;
    return {
      profile: this.definition.id,
      operation: operation.definition.id,
      action: operation.definition.action,
      facts,
      policyProjection: operation.definition.policy_projection,
      ...(subjectPointer === undefined
        ? {}
        : {
            subject: ApiProfile.subjectOf(
              ApiProfile.walk(
                root,
                ApiProfile.pointerSegments(subjectPointer, operation.definition.id),
              ),
            ),
          }),
    };
  }

  private select(
    method: string,
    path: string,
    query: NonNullable<ApiRequest["query"]>,
  ): { operation: CompiledOperation; parameters: JsonObject } | null {
    const upper = method.toUpperCase();
    if (!path.startsWith("/") || /[?#]/.test(path)) return null;
    for (const operation of this.compiled) {
      if (operation.definition.method !== upper) continue;
      if (!ApiProfile.queryMatches(operation.definition.query ?? {}, query)) continue;
      for (let index = 0; index < operation.matchers.length; index += 1) {
        const found = operation.matchers[index]!.exec(path);
        if (found === null) continue;
        const parameters: JsonObject = {};
        let decodable = true;
        operation.placeholders[index]!.forEach((placeholder, position) => {
          const decoded = ApiProfile.decode(found[position + 1] ?? "");
          if (decoded === null) decodable = false;
          else parameters[placeholder] = decoded;
        });
        if (decodable) return { operation, parameters };
      }
    }
    return null;
  }

  /** A template as an anchored expression: placeholders take one segment's text, never a `/`. */
  private static compile(
    template: string,
    operation: string,
  ): { pattern: RegExp; names: string[] } {
    const names: string[] = [];
    let source = "";
    let last = 0;
    for (const found of template.matchAll(PLACEHOLDER)) {
      const placeholder = found[1]!;
      if (names.includes(placeholder))
        throw new ApiProfileError(
          "API_PROFILE_INVALID",
          `operation ${operation} repeats the placeholder ${placeholder}`,
        );
      names.push(placeholder);
      source += ApiProfile.escape(template.slice(last, found.index)) + "([^/()]+)";
      last = (found.index ?? 0) + found[0].length;
    }
    source += ApiProfile.escape(template.slice(last));
    if (/[{}]/.test(template.replace(PLACEHOLDER, "")))
      throw new ApiProfileError(
        "API_PROFILE_INVALID",
        `operation ${operation} has a malformed placeholder`,
      );
    return { pattern: new RegExp(`^${source}$`), names };
  }

  private static escape(text: string): string {
    return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  /** A placeholder's value: percent-decoded, OData quotes removed; null when it does not decode. */
  private static decode(raw: string): string | null {
    let value: string;
    try {
      value = decodeURIComponent(raw);
    } catch {
      return null;
    }
    if (value.length >= 2 && value.startsWith("'") && value.endsWith("'"))
      value = value.slice(1, -1);
    if (value === "" || value === "." || value === ".." || value.includes("/")) return null;
    return value;
  }

  private static queryMatches(
    expected: Record<string, string>,
    query: NonNullable<ApiRequest["query"]>,
  ): boolean {
    return Object.entries(expected).every(([key, value]) => {
      const actual = query[key];
      return typeof actual === "string" ? actual === value : false;
    });
  }

  private static queryRoot(query: NonNullable<ApiRequest["query"]>): JsonObject {
    const root: JsonObject = {};
    for (const [key, value] of Object.entries(query)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
      root[key] = typeof value === "string" ? value : [...value];
    }
    return root;
  }

  /**
   * What a definition must also be about subjects: a read names where its
   * subject sits and states no fact or policy path, since it is never
   * decided; only a read names a response subject; a request subject is one
   * value, so its pointer has no `*`.
   */
  private static subjectRules(operation: ApiOperationDefinition): void {
    const subject = operation.subject;
    const refuse = (detail: string): never => {
      throw new ApiProfileError("API_PROFILE_INVALID", `operation ${operation.id} ${detail}`);
    };
    if (subject !== undefined && subject.request === undefined && subject.response === undefined)
      refuse("names an empty subject");
    if (ApiProfile.isRead(operation)) {
      if (subject === undefined) refuse("is a read that names no subject");
      if (Object.keys(operation.facts).length > 0 || operation.policy_projection !== null)
        refuse("is a read: it states no fact and no policy projection");
    } else if (subject?.response !== undefined) {
      refuse("is a write: only a read names a response subject");
    }
    if (subject?.request !== undefined) {
      if (ApiProfile.pointerSegments(subject.request, operation.id).includes("*"))
        refuse("names a request subject through *");
    }
    if (subject?.response !== undefined) ApiProfile.pointerSegments(subject.response, operation.id);
  }

  /** A subject as stated: a string or a finite number, as a string, within the bound; else null. */
  private static subjectOf(value: JsonValue | undefined): string | null {
    const text =
      typeof value === "string"
        ? value
        : typeof value === "number" && Number.isFinite(value)
          ? String(value)
          : null;
    return text === null || text.length === 0 || text.length > MAX_SUBJECT_LENGTH ? null : text;
  }

  /** Each element's value through a `*`; null when there is no list where the `*` stands. */
  private static walkList(
    root: JsonValue,
    before: readonly string[],
    after: readonly string[],
  ): (JsonValue | undefined)[] | null {
    const list = ApiProfile.walk(root, before);
    if (!Array.isArray(list)) return null;
    return list.map((element) => ApiProfile.walk(element, after));
  }

  /** RFC 6901 reference tokens, unescaped; one `*` token at most. */
  private static pointerSegments(pointer: string, operation: string): readonly string[] {
    const tokens = pointer
      .slice(1)
      .split("/")
      .map((token) => token.replaceAll("~1", "/").replaceAll("~0", "~"));
    if (tokens.filter((token) => token === "*").length > 1 || /~[^01]|~$/.test(pointer))
      throw new ApiProfileError(
        "API_PROFILE_INVALID",
        `operation ${operation} has an invalid fact pointer ${pointer}`,
      );
    return tokens;
  }

  /**
   * The value at a pointer, when it is statable: a string (at most 1000
   * characters), a finite number or a boolean; or, through one `*`, an array
   * of up to 100 of them, every element statable. Anything else is absent.
   */
  private static read(root: JsonValue, tokens: readonly string[]): JsonValue | undefined {
    const wildcard = tokens.indexOf("*");
    if (wildcard === -1) return ApiProfile.statable(ApiProfile.walk(root, tokens));
    const list = ApiProfile.walk(root, tokens.slice(0, wildcard));
    if (!Array.isArray(list) || list.length === 0 || list.length > MAX_FACT_ELEMENTS)
      return undefined;
    const values: JsonPrimitive[] = [];
    for (const element of list) {
      const value = ApiProfile.statable(ApiProfile.walk(element, tokens.slice(wildcard + 1)));
      if (value === undefined) return undefined;
      values.push(value);
    }
    return values;
  }

  private static walk(
    value: JsonValue | undefined,
    tokens: readonly string[],
  ): JsonValue | undefined {
    let current = value;
    for (const token of tokens) {
      if (Array.isArray(current)) {
        if (!/^(?:0|[1-9]\d{0,5})$/.test(token)) return undefined;
        current = current[Number(token)];
      } else if (current !== null && typeof current === "object") {
        current = Object.hasOwn(current, token) ? current[token] : undefined;
      } else {
        return undefined;
      }
      if (current === undefined) return undefined;
    }
    return current;
  }

  private static statable(value: JsonValue | undefined): JsonPrimitive | undefined {
    if (typeof value === "string") return value.length <= MAX_FACT_STRING ? value : undefined;
    if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
    if (typeof value === "boolean") return value;
    return undefined;
  }
}

/** The published JSON Schema of a profile definition, generated from the validator above. */
export function apiProfileJsonSchema(): Record<string, unknown> {
  const generated = z.toJSONSchema(ApiProfileDefinitionSchema, {
    target: "draft-2020-12",
    io: "input",
  });
  const schema: Record<string, unknown> = { ...generated };
  delete schema["$schema"];
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: API_PROFILE_SCHEMA_ID,
    title: API_PROFILE_CONTRACT,
    ...schema,
  };
}
