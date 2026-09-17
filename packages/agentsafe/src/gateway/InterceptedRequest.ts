import { createHash } from "node:crypto";
import type { AgentProposal, JsonObject, JsonValue } from "@decionis/agent-safe-pipeline";
import type { ConsequentialMethod } from "./GatewayConfig.js";

/** One request as the listener hands it over: read in full, bounded, and not yet interpreted. */
export interface InterceptedRequest {
  readonly method: string;
  /** The path alone; the query is carried separately. */
  readonly path: string;
  readonly search: string;
  /** Header names in lower case, values joined the way Node joins them. */
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Buffer;
  readonly remoteAddress: string | null;
  readonly encrypted: boolean;
}

/** The HTTP action's parameters: exactly what the authority evaluates and the handler forwards. */
export interface HttpActionParameters extends JsonObject {
  method: ConsequentialMethod;
  path: string;
  query: { [key: string]: string | string[] };
  body?: JsonValue;
}

/** What the intent's context carries about the body: its digest, size and kind, never its bytes. */
export interface HttpActionContext extends JsonObject {
  readonly body_sha256: string;
  readonly body_bytes: number;
  readonly content_type: string | null;
  readonly body_embedded: boolean;
}

export interface NormalizedAction {
  readonly proposal: AgentProposal;
  readonly context: HttpActionContext & JsonObject;
  readonly idempotencyKey: string | null;
  readonly correlationId: string | null;
  readonly principal: string | null;
}

const MAX_TARGET_LENGTH = 500;
const MAX_IDEMPOTENCY_KEY_LENGTH = 180;
const MAX_CORRELATION_LENGTH = 200;
/** A header the client may use to name itself; bounded like an identifier. */
const MAX_PRINCIPAL_LENGTH = 200;
const JSON_TYPES = /^application\/(?:[\w.+-]+\+)?json(?:\s*;.*)?$/i;

/** SHA-256 over the bytes, in the contract's `sha256:` form. */
export function bodyDigest(body: Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
}

/** Query pairs as an object: one value, or a list where a key repeats; keys sorted for stable hashing. */
function queryObject(search: string): { [key: string]: string | string[] } {
  const pairs = new URLSearchParams(search);
  const keys = [...new Set(pairs.keys())].sort();
  const query: { [key: string]: string | string[] } = {};
  for (const key of keys) {
    const values = pairs.getAll(key);
    query[key] = values.length === 1 ? (values[0] ?? "") : values;
  }
  return query;
}

/** A bounded header value, or null when absent, empty or over the bound. */
function header(
  headers: Readonly<Record<string, string>>,
  name: string,
  maxLength: number,
): string | null {
  const value = headers[name]?.trim();
  if (value === undefined || value === "" || value.length > maxLength) return null;
  return value;
}

/**
 * Turns an intercepted request into the agent's part of an intent. The
 * proposal is method, path, query and, when the body is JSON within the
 * embedding limit, the body itself, so policy can see the fields it decides
 * on. The context binds the raw bytes by digest whether or not they were
 * embedded, which is what the forwarding handler checks before dispatch.
 * Request headers are not part of the intent: a credential to the upstream
 * is the client's business with the upstream and never reaches the authority.
 */
export function normalizeRequest(
  request: InterceptedRequest,
  action: string,
  options: { readonly maxEmbeddedBodyBytes: number; readonly principalHeader: string | null },
): NormalizedAction {
  const method = request.method.toUpperCase() as ConsequentialMethod;
  const target = `${method} ${request.path}`;
  if (target.length > MAX_TARGET_LENGTH) throw new Error("TARGET_TOO_LONG");
  const contentType = header(request.headers, "content-type", 200);
  const embeddable =
    request.body.length > 0 &&
    request.body.length <= options.maxEmbeddedBodyBytes &&
    contentType !== null &&
    JSON_TYPES.test(contentType);
  let body: JsonValue | undefined;
  if (embeddable) {
    try {
      body = JSON.parse(request.body.toString("utf8")) as JsonValue;
    } catch {
      body = undefined;
    }
  }
  const parameters: HttpActionParameters = {
    method,
    path: request.path,
    query: queryObject(request.search),
    ...(body === undefined ? {} : { body }),
  };
  return {
    proposal: { action, target, parameters },
    context: {
      body_sha256: bodyDigest(request.body),
      body_bytes: request.body.length,
      content_type: contentType,
      body_embedded: body !== undefined,
    },
    idempotencyKey: header(request.headers, "idempotency-key", MAX_IDEMPOTENCY_KEY_LENGTH),
    correlationId:
      header(request.headers, "x-correlation-id", MAX_CORRELATION_LENGTH) ??
      header(request.headers, "x-request-id", MAX_CORRELATION_LENGTH),
    principal:
      options.principalHeader === null
        ? null
        : header(request.headers, options.principalHeader, MAX_PRINCIPAL_LENGTH),
  };
}
