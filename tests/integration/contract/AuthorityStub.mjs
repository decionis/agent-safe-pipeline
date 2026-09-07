/**
 * Loopback stand-in for the Decionis execution-authority routes that
 * `@decionis/agent-safe-pipeline` consumes: enforce-and-bind, claim-token (and
 * its consume-token alias), and finalize-token.
 *
 * It validates every request against the published OpenAPI contract with its
 * own canonicalizer, so a hash it recomputes is independent evidence that the
 * package binds intents the way Decionis does. Grants, claims, and commit
 * outcomes are synthetic in-memory state. Nothing here is a real policy,
 * tenant, or credential.
 */
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { z } from "zod";

export const STUB_API_KEY = "test-key";
export const AUTONOMOUS_LIMIT_MINOR = 10_000;
export const HUMAN_LIMIT_MINOR = 100_000;

const LOOPBACK_ORIGIN = "http://127.0.0.1";
const MAX_REQUEST_BYTES = 256 * 1024;
const MAX_RECORDED_BODY_CHARS = 4_096;
const SOCKET_TIMEOUT_MS = 10_000;
const GRANT_TTL_MS = 60_000;
const CLAIM_LEASE_MS = 30_000;

const boundedId = z.string().trim().min(1).max(200);
const sha256Digest = z.string().regex(/^sha256:[0-9a-f]{64}$/);

/** `ExecutionIntentBinding` from the Decionis OpenAPI contract; extra properties are rejected. */
const IntentBindingSchema = z.strictObject({
  protocol_version: z.literal("agent-safe.intent/1"),
  tenant_id: z.uuid(),
  intent_id: z.uuid(),
  captured_at: z.iso.datetime(),
  expires_at: z.iso.datetime(),
  actor: z.strictObject({
    id: boundedId,
    type: boundedId,
    runtime: boundedId.optional(),
    trust_level: z.string().trim().min(1).max(80).optional(),
  }),
  action: z.strictObject({
    type: z
      .string()
      .min(1)
      .max(120)
      .regex(/^[a-z][a-z0-9._:-]*$/),
    resource: z.string().min(1).max(500),
    parameters: z.record(z.string(), z.unknown()),
  }),
  context: z.record(z.string(), z.unknown()),
  downstream_target: z.strictObject({
    system: boundedId,
    environment: boundedId.optional(),
    operation: boundedId,
    endpoint: z.string().min(1).max(500).optional(),
  }),
});

const EvidenceSchema = z.strictObject({
  humanApproval: z
    .strictObject({
      provider: z.literal("presence"),
      requestId: boundedId,
      receiptDossierId: boundedId,
    })
    .optional(),
});

/** `ExecutionAuthorityRequest`: the binding plus hash, mode, and optional evidence. */
const AuthorityRequestSchema = z.strictObject({
  ...IntentBindingSchema.shape,
  intent_hash: sha256Digest,
  mode: z.enum(["SHADOW", "ENFORCEMENT"]),
  evidence: EvidenceSchema.optional(),
});

/** `ExecutionTokenRequest`. */
const TokenRequestSchema = z.strictObject({
  execution_token: z.string().min(1).max(20_000),
  intent_hash: sha256Digest,
  intent: z.record(z.string(), z.unknown()),
  evidence: EvidenceSchema.optional(),
  consumed_by: boundedId.optional(),
  commit_correlation_id: boundedId.optional(),
});

/** `ExecutionFinalizeRequest`. */
const FinalizeRequestSchema = z.strictObject({
  execution_token: z.string().min(1).max(20_000),
  claim_token: z.string().regex(/^[\w-]{43,128}$/),
  outcome: z.enum(["COMMITTED", "FAILED", "INDETERMINATE"]),
  commit_correlation_id: boundedId,
  downstream_evidence: z.record(z.string(), z.unknown()).optional(),
});

const BINDING_KEYS = Object.keys(IntentBindingSchema.shape);

/**
 * Independent canonicalization: keys sorted by UTF-16 code unit, values encoded
 * with JSON.stringify semantics. This deliberately does not import the
 * package's hasher so the two implementations check each other.
 */
export function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  const entries = Object.keys(value)
    .sort()
    .filter((key) => value[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`);
  return `{${entries.join(",")}}`;
}

export function hashBinding(binding) {
  return `sha256:${createHash("sha256").update(stableStringify(binding), "utf8").digest("hex")}`;
}

function bindingOf(request) {
  const binding = {};
  for (const key of BINDING_KEYS) binding[key] = request[key];
  return binding;
}

function truncate(text) {
  return text.length > MAX_RECORDED_BODY_CHARS
    ? `${text.slice(0, MAX_RECORDED_BODY_CHARS)}…[truncated ${text.length - MAX_RECORDED_BODY_CHARS} chars]`
    : text;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class AuthorityStub {
  /** Every request seen, oldest first, with bounded bodies and the response given. */
  requests = [];
  /** Issued grants keyed by execution token. */
  grants = new Map();
  #decisions = 0;
  #server = null;
  #port = 0;
  #overrides = { enforce: [], claim: [], finalize: [] };
  #verifyReceipt;

  /**
   * @param {{ verifyReceipt?: (approval: { requestId: string, receiptDossierId: string }, intentHash: string) => boolean }} options
   */
  constructor(options = {}) {
    this.#verifyReceipt = options.verifyReceipt ?? (() => false);
  }

  get baseUrl() {
    return `${LOOPBACK_ORIGIN}:${this.#port}`;
  }

  async start() {
    this.#server = createServer((req, res) => {
      void this.#handle(req, res);
    });
    this.#server.setTimeout(SOCKET_TIMEOUT_MS);
    await new Promise((resolve) => this.#server.listen(0, "127.0.0.1", resolve));
    this.#port = this.#server.address().port;
  }

  async stop() {
    if (this.#server === null) return;
    this.#server.closeAllConnections();
    await new Promise((resolve) => this.#server.close(() => resolve()));
    this.#server = null;
  }

  /**
   * Alters the next response on one route only. `transform` receives the
   * computed body; `body` replaces it (an object or a raw string); `status`,
   * `delayMs`, `truncateTo`, and `destroy` shape the transport behavior.
   *
   * @param {"enforce" | "claim" | "finalize"} route
   */
  scriptOnce(route, override) {
    this.#overrides[route].push(override);
  }

  async #handle(req, res) {
    const url = new URL(req.url ?? "/", this.baseUrl);
    const record = {
      method: req.method,
      path: url.pathname,
      headers: {
        authorization: req.headers.authorization ?? null,
        "content-type": req.headers["content-type"] ?? null,
        "idempotency-key": req.headers["idempotency-key"] ?? null,
      },
      body: null,
      recomputedHash: null,
      response: null,
      at: new Date().toISOString(),
    };
    this.requests.push(record);

    const raw = await this.#readBody(req);
    if (raw === null) {
      return this.#send(res, record, 413, { error: "REQUEST_TOO_LARGE" });
    }
    try {
      record.body = raw.length === 0 ? null : JSON.parse(raw);
    } catch {
      record.body = truncate(raw);
      return this.#send(res, record, 400, { error: "REQUEST_MALFORMED" });
    }
    if (req.method !== "POST") return this.#send(res, record, 405, { error: "METHOD_NOT_ALLOWED" });
    if (req.headers.authorization !== `Bearer ${STUB_API_KEY}`) {
      return this.#send(res, record, 401, { error: "UNAUTHORIZED" });
    }
    if (req.headers["content-type"] !== "application/json") {
      return this.#send(res, record, 415, { error: "UNSUPPORTED_MEDIA_TYPE" });
    }

    switch (url.pathname) {
      case "/v1/authority/enforce-and-bind":
        return this.#respond(res, record, "enforce", this.#enforceAndBind(record));
      case "/v1/execution/claim-token":
      case "/v1/execution/consume-token":
        return this.#respond(res, record, "claim", this.#claim(record));
      case "/v1/execution/finalize-token":
        return this.#respond(res, record, "finalize", this.#finalize(record));
      default:
        return this.#send(res, record, 404, { error: "NOT_FOUND" });
    }
  }

  #enforceAndBind(record) {
    const parsed = AuthorityRequestSchema.safeParse(record.body);
    if (!parsed.success) return { status: 400, body: { error: "REQUEST_INVALID" } };
    const request = parsed.data;
    if (record.headers["idempotency-key"] !== request.intent_id) {
      return { status: 400, body: { error: "IDEMPOTENCY_KEY_MISMATCH" } };
    }
    const bindingError = this.#assertBinding(request, record);
    if (bindingError !== null) return { status: 400, body: { error: bindingError } };

    this.#decisions += 1;
    const sequence = this.#decisions;
    const decisionId = `synthetic-decision-${sequence}`;
    const dossierId = `synthetic-dossier-${sequence}`;
    const amount = Number(request.action.parameters.amountMinor ?? 0);
    let status = "ALLOW";
    let reasonCode = "POLICY_AUTONOMOUS_LIMIT";
    let approval = null;
    if (amount > HUMAN_LIMIT_MINOR) {
      status = "BLOCK";
      reasonCode = "POLICY_HARD_LIMIT_EXCEEDED";
    } else if (amount > AUTONOMOUS_LIMIT_MINOR) {
      const humanApproval = request.evidence?.humanApproval;
      if (humanApproval === undefined) {
        status = "ESCALATE";
        reasonCode = "HUMAN_APPROVAL_REQUIRED";
      } else if (!this.#verifyReceipt(humanApproval, request.intent_hash)) {
        // Decionis verifies the receipt with Presence and refuses the request.
        return { status: 409, body: { error: "PRESENCE_RECEIPT_INVALID" } };
      } else {
        reasonCode = "PRESENCE_RECEIPT_VERIFIED";
        approval = humanApproval;
      }
    }

    const decision = {
      decision_id: decisionId,
      chain_id: "synthetic-chain-1",
      status,
      should_execute: false,
      reason_codes: [reasonCode],
      action_hash: request.intent_hash,
      policy_version: "synthetic-policy-v1",
      mode: request.mode,
      execution_token: null,
      execution_token_expires_at: null,
      dossier_id: dossierId,
      dossier_sha256: `sha256:${createHash("sha256").update(dossierId).digest("hex")}`,
      dossier_url: `/v1/protocol/dossiers/${dossierId}`,
      approval_request_id: status === "ESCALATE" ? `synthetic-approval-${sequence}` : null,
      ledger_entry_id: `synthetic-ledger-${sequence}`,
    };
    if (status !== "ALLOW" || request.mode !== "ENFORCEMENT") {
      return { status: 200, body: decision };
    }

    const issuedAt = Math.floor(Date.now() / 1_000);
    const expiresAt = Math.min(
      Math.floor((Date.now() + GRANT_TTL_MS) / 1_000),
      Math.floor(Date.parse(request.expires_at) / 1_000),
    );
    const jti = `synthetic-jti-${randomUUID()}`;
    const token = `synthetic-grant.${jti}`;
    this.grants.set(token, {
      jti,
      tenantId: request.tenant_id,
      actorId: request.actor.id,
      action: request.action.type,
      audience: `${request.downstream_target.system}:${request.downstream_target.operation}`,
      decisionId,
      dossierId,
      intentHash: request.intent_hash,
      issuedAt,
      expiresAt,
      nonce: randomBytes(32).toString("base64url"),
      bindingDigest: `sha256:${createHash("sha256").update(request.intent_hash).digest("hex")}`,
      receiptDossierId: approval?.receiptDossierId ?? null,
      claimed: false,
      claimToken: null,
      correlationId: null,
      consumedBy: null,
      finalized: null,
    });
    return {
      status: 200,
      body: {
        ...decision,
        should_execute: true,
        execution_token: token,
        execution_token_expires_at: new Date(expiresAt * 1_000).toISOString(),
      },
    };
  }

  #claim(record) {
    const parsed = TokenRequestSchema.safeParse(record.body);
    if (!parsed.success) return { status: 400, body: { error: "REQUEST_INVALID" } };
    const intent = IntentBindingSchema.safeParse(parsed.data.intent);
    if (!intent.success) return { status: 400, body: { error: "REQUEST_INVALID" } };
    const rejected = (reasonCode, status = 409) => ({
      status,
      body: { valid: false, reason_codes: [reasonCode], claims: null },
    });
    const bindingError = this.#assertBinding(
      { ...intent.data, intent_hash: parsed.data.intent_hash },
      record,
    );
    if (bindingError !== null) return rejected(bindingError);

    const grant = this.grants.get(parsed.data.execution_token);
    if (grant === undefined) return rejected("GRANT_INVALID");
    if (grant.expiresAt * 1_000 <= Date.now()) return rejected("GRANT_EXPIRED");
    if (grant.intentHash !== parsed.data.intent_hash) return rejected("GRANT_BINDING_MISMATCH");
    if (
      grant.receiptDossierId !== null &&
      parsed.data.evidence?.humanApproval?.receiptDossierId !== grant.receiptDossierId
    ) {
      return rejected("PRESENCE_APPROVAL_STALE");
    }
    if (grant.claimed) return rejected("NONCE_REPLAY_DETECTED");

    grant.claimed = true;
    grant.claimToken = randomBytes(32).toString("base64url");
    grant.correlationId = parsed.data.commit_correlation_id ?? intent.data.intent_id;
    grant.consumedBy = parsed.data.consumed_by ?? null;
    const leaseExpiresAt = new Date(Date.now() + CLAIM_LEASE_MS).toISOString();
    return {
      status: 200,
      body: {
        valid: true,
        should_execute: true,
        would_block: false,
        verdict: "ALLOW",
        reason_codes: [],
        claims: {
          iss: "synthetic-authority",
          sub: grant.actorId,
          aud: grant.audience,
          org_id: grant.tenantId,
          dossier_id: grant.dossierId,
          decision_id: grant.decisionId,
          chain_id: "synthetic-chain-1",
          action: grant.action,
          decision: "allow",
          scope: "execute",
          binding: {
            intent_hash: grant.intentHash,
            execution_binding_digest: grant.bindingDigest,
            execution_nonce: grant.nonce,
            execution_correlation_id: grant.correlationId,
          },
          jti: grant.jti,
          iat: grant.issuedAt,
          nbf: grant.issuedAt,
          exp: grant.expiresAt,
        },
        claim_token: grant.claimToken,
        claim_lease_expires_at: leaseExpiresAt,
        evidence: { nonce_claim_state: "CLAIMED", commit_correlation_id: grant.correlationId },
      },
    };
  }

  #finalize(record) {
    const parsed = FinalizeRequestSchema.safeParse(record.body);
    if (!parsed.success) return { status: 400, body: { error: "REQUEST_INVALID" } };
    const rejected = (reasonCode) => ({
      status: 409,
      body: { finalized: false, reason_codes: [reasonCode] },
    });
    const grant = this.grants.get(parsed.data.execution_token);
    if (grant === undefined) return rejected("GRANT_INVALID");
    if (!grant.claimed || grant.claimToken !== parsed.data.claim_token) {
      return rejected("NONCE_REPLAY_DETECTED");
    }
    if (grant.correlationId !== parsed.data.commit_correlation_id) {
      return rejected("EXECUTION_CORRELATION_MISMATCH");
    }
    if (grant.finalized !== null) return rejected("NONCE_REPLAY_DETECTED");
    grant.finalized = parsed.data.outcome;
    return {
      status: 200,
      body: {
        finalized: true,
        outcome: parsed.data.outcome,
        evidence_recorded: true,
        effect_status: "NOT_OBSERVED",
        reason_codes: [],
      },
    };
  }

  /** Recomputes the hash independently and applies the contract's time rules. */
  #assertBinding(request, record) {
    const recomputed = hashBinding(bindingOf(request));
    record.recomputedHash = recomputed;
    if (recomputed !== request.intent_hash) return "INTENT_HASH_MISMATCH";
    const capturedAt = Date.parse(request.captured_at);
    const expiresAt = Date.parse(request.expires_at);
    const now = Date.now();
    if (capturedAt > now + 5_000) return "INTENT_CAPTURED_IN_FUTURE";
    if (expiresAt <= now) return "INTENT_EXPIRED";
    if (expiresAt <= capturedAt) return "INTENT_TIME_ORDER_INVALID";
    if (expiresAt - capturedAt > 300_000) return "INTENT_LIFETIME_TOO_LONG";
    return null;
  }

  async #respond(res, record, route, computed) {
    const override = this.#overrides[route].shift();
    if (override === undefined) return this.#send(res, record, computed.status, computed.body);
    if (override.delayMs !== undefined) await sleep(override.delayMs);
    if (override.destroy === true) {
      record.response = { status: null, body: "[connection destroyed]" };
      res.socket?.destroy();
      return;
    }
    const status = override.status ?? computed.status;
    const body =
      override.body !== undefined
        ? override.body
        : override.transform !== undefined
          ? override.transform(computed.body)
          : computed.body;
    if (override.truncateTo !== undefined) {
      const raw = typeof body === "string" ? body : JSON.stringify(body);
      record.response = { status, body: `[truncated to ${override.truncateTo} bytes]` };
      res.writeHead(status, {
        "content-type": "application/json",
        "content-length": String(Buffer.byteLength(raw, "utf8")),
      });
      res.write(raw.slice(0, override.truncateTo));
      res.socket?.destroy();
      return;
    }
    return this.#send(res, record, status, body);
  }

  #send(res, record, status, body) {
    const raw = typeof body === "string" ? body : JSON.stringify(body);
    record.response = { status, body: typeof body === "string" ? truncate(body) : body };
    res.writeHead(status, { "content-type": "application/json" });
    res.end(raw);
  }

  async #readBody(req) {
    const chunks = [];
    let total = 0;
    for await (const chunk of req) {
      total += chunk.length;
      if (total > MAX_REQUEST_BYTES) return null;
      chunks.push(chunk);
    }
    return Buffer.concat(chunks).toString("utf8");
  }
}
