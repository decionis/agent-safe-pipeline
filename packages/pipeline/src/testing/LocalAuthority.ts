/**
 * Loopback stand-in for the Decionis execution-authority routes that
 * `@decionis/agent-safe-pipeline` consumes: enforce-and-bind (including
 * shadow mode and managed escalation), escalation status and cancellation,
 * claim-token with its consume-token alias, and finalize-token.
 *
 * It validates every request against the published OpenAPI contract with its
 * own canonicalizer, so a hash it recomputes is independent evidence that the
 * package binds intents the way Decionis does. Direct Presence evidence is
 * verified against a `LocalPresence`, and a managed escalation is orchestrated
 * through that same `LocalPresence` the way Decionis orchestrates Presence:
 * create a request bound to the exact intent hash, wait for the ceremony,
 * verify the receipt, re-evaluate policy, then expose a normal grant.
 *
 * Grants, claims, escalations, and commit outcomes are synthetic in-memory
 * state. Nothing here is a real policy, tenant, or credential.
 */
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { z } from "zod";
import { readBody, type LocalPresence } from "./LocalPresence.js";

export const LOCAL_AUTHORITY_API_KEY = "test-key";
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
const roleId = z.string().regex(/^[A-Z][A-Z0-9_]{1,63}$/);

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

const ManagedEscalationRequestSchema = z.strictObject({
  mode: z.literal("MANAGED"),
  approver: z
    .strictObject({
      principal_id: boundedId.optional(),
      role_id: roleId.optional(),
    })
    .optional(),
  verification_requirements: z
    .strictObject({
      methods: z
        .array(z.enum(["WEBAUTHN", "ACTIVE_LIVENESS"]))
        .min(1)
        .max(3),
      level: z.enum(["STANDARD", "HIGH_CONFIDENCE"]).optional(),
    })
    .optional(),
});

/** `ExecutionAuthorityRequest`: the binding plus hash, mode, evidence, and managed constraints. */
const AuthorityRequestSchema = z.strictObject({
  ...IntentBindingSchema.shape,
  intent_hash: sha256Digest,
  mode: z.enum(["SHADOW", "ENFORCEMENT"]),
  evidence: EvidenceSchema.optional(),
  escalation: ManagedEscalationRequestSchema.optional(),
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

export type LocalAuthorityRequest = z.infer<typeof AuthorityRequestSchema>;
type IntentBinding = z.infer<typeof IntentBindingSchema>;
type Verdict = "ALLOW" | "ESCALATE" | "BLOCK";
type ManagedStatus =
  | "PENDING_PRESENCE"
  | "PRESENCE_REQUESTED"
  | "AWAITING_APPROVER"
  | "PRESENCE_VERIFIED"
  | "REAUTHORIZING"
  | "GRANT_READY"
  | "EXPIRED"
  | "REJECTED"
  | "BLOCKED"
  | "CANCELLED"
  | "FAILED";
type LifecycleEntry = ManagedStatus | { status: ManagedStatus; reasonCodes?: string[] };
type Decision = Record<string, unknown>;

interface Computed {
  readonly status: number;
  readonly body: unknown;
}

/** Verdict for an intent evaluated without evidence; evidence handling stays generic. */
export type LocalAuthorityPolicy = (request: LocalAuthorityRequest) => Verdict;

export interface LocalRouteOverride {
  readonly status?: number;
  readonly body?: unknown;
  readonly transform?: (body: unknown) => unknown;
  readonly delayMs?: number;
  readonly truncateTo?: number;
  readonly destroy?: boolean;
}

export type LocalAuthorityRoute = "enforce" | "status" | "claim" | "finalize";

export interface LocalAuthorityRequestRecord {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string | null>>;
  body: unknown;
  recomputedHash: string | null;
  response: { readonly status: number | null; readonly body: unknown } | null;
  readonly at: string;
}

export interface LocalGrantRecord {
  readonly jti: string;
  readonly tenantId: string;
  readonly actorId: string;
  readonly action: string;
  readonly audience: string;
  readonly decisionId: string;
  readonly dossierId: string;
  readonly intentHash: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly nonce: string;
  readonly bindingDigest: string;
  /** Present for direct grants issued on client-supplied evidence; null for managed grants. */
  readonly receiptDossierId: string | null;
  claimed: boolean;
  claimToken: string | null;
  correlationId: string | null;
  consumedBy: string | null;
  finalized: "COMMITTED" | "FAILED" | "INDETERMINATE" | null;
}

export interface LocalManagedEscalationRecord {
  readonly escalationId: string;
  readonly request: LocalAuthorityRequest;
  /** The `LocalPresence` request this escalation is orchestrated through, if any. */
  readonly presenceRequestId: string | null;
  /** Scripted statuses take precedence over orchestration; used to test client state handling. */
  lifecycle: LifecycleEntry[] | null;
  lookup: number;
  status: ManagedStatus;
  reasonCodes: string[];
  finalDecision: Decision | null;
  readonly initialDecision: Decision;
}

export interface LocalAuthorityOptions {
  readonly apiKey?: string;
  /** Verifies direct evidence and hosts managed escalations. */
  readonly presence?: LocalPresence;
  /** Legacy hook used when no `presence` is configured. */
  readonly verifyReceipt?: (
    approval: { readonly requestId: string; readonly receiptDossierId: string },
    intentHash: string,
  ) => boolean;
  readonly policy?: LocalAuthorityPolicy;
  /** Subject routed to for a managed escalation without an approver principal. */
  readonly managedApproverId?: string;
  readonly clock?: () => number;
}

/**
 * Independent canonicalization: keys sorted by UTF-16 code unit, values encoded
 * with JSON.stringify semantics. This deliberately does not import the
 * package's hasher so the two implementations check each other.
 */
export function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  const record = value as Record<string, unknown>;
  const entries = Object.keys(record)
    .sort()
    .filter((key) => record[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`);
  return `{${entries.join(",")}}`;
}

export function hashBinding(binding: unknown): string {
  return `sha256:${createHash("sha256").update(stableStringify(binding), "utf8").digest("hex")}`;
}

function bindingOf(request: Record<string, unknown>): Record<string, unknown> {
  const binding: Record<string, unknown> = {};
  for (const key of BINDING_KEYS) binding[key] = request[key];
  return binding;
}

function truncate(text: string): string {
  return text.length > MAX_RECORDED_BODY_CHARS
    ? `${text.slice(0, MAX_RECORDED_BODY_CHARS)}…[truncated ${text.length - MAX_RECORDED_BODY_CHARS} chars]`
    : text;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function defaultPolicy(request: LocalAuthorityRequest): Verdict {
  const amount = Number(request.action.parameters.amountMinor ?? 0);
  if (amount > HUMAN_LIMIT_MINOR) return "BLOCK";
  if (amount > AUTONOMOUS_LIMIT_MINOR) return "ESCALATE";
  return "ALLOW";
}

export class LocalAuthority {
  /** Every request seen, oldest first, with bounded bodies and the response given. */
  public readonly requests: LocalAuthorityRequestRecord[] = [];
  /** Issued grants keyed by execution token. */
  public readonly grants = new Map<string, LocalGrantRecord>();
  /** Managed escalations keyed by their opaque identifier. */
  public readonly escalations = new Map<string, LocalManagedEscalationRecord>();
  private readonly apiKey: string;
  private readonly presence: LocalPresence | undefined;
  private readonly legacyVerifyReceipt: LocalAuthorityOptions["verifyReceipt"];
  private readonly policy: LocalAuthorityPolicy;
  private readonly managedApproverId: string;
  private readonly clock: () => number;
  private readonly overrides: Record<LocalAuthorityRoute, LocalRouteOverride[]> = {
    enforce: [],
    status: [],
    claim: [],
    finalize: [],
  };
  private readonly managedByIntent = new Map<string, LocalManagedEscalationRecord>();
  private nextManagedLifecycle: LifecycleEntry[] | null = null;
  private decisions = 0;
  private server: Server | null = null;
  private port = 0;

  public constructor(options: LocalAuthorityOptions = {}) {
    if (process.env.NODE_ENV === "production") throw new Error("LOCAL_DOUBLE_FORBIDDEN");
    this.apiKey = options.apiKey ?? LOCAL_AUTHORITY_API_KEY;
    this.presence = options.presence;
    this.legacyVerifyReceipt = options.verifyReceipt;
    this.policy = options.policy ?? defaultPolicy;
    this.managedApproverId = options.managedApproverId ?? "synthetic-managed-approver";
    this.clock = options.clock ?? Date.now;
  }

  public get baseUrl(): string {
    return `${LOOPBACK_ORIGIN}:${this.port}`;
  }

  public async start(): Promise<void> {
    const server = createServer((req, res) => {
      void this.handle(req, res);
    });
    server.setTimeout(SOCKET_TIMEOUT_MS);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const address = server.address();
    this.port = typeof address === "object" && address !== null ? address.port : 0;
    this.server = server;
  }

  public async stop(): Promise<void> {
    const server = this.server;
    if (server === null) return;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    this.server = null;
  }

  /**
   * Alters the next response on one route only. `transform` receives the
   * computed body; `body` replaces it (an object or a raw string); `status`,
   * `delayMs`, `truncateTo`, and `destroy` shape the transport behavior.
   */
  public scriptOnce(route: LocalAuthorityRoute, override: LocalRouteOverride): void {
    this.overrides[route].push(override);
  }

  /** Statuses returned, in order, for the next managed escalation instead of orchestration. */
  public scriptNextManagedLifecycle(statuses: readonly LifecycleEntry[]): void {
    this.nextManagedLifecycle = [...statuses];
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", this.baseUrl);
    const record: LocalAuthorityRequestRecord = {
      method: req.method ?? "GET",
      path: url.pathname,
      headers: {
        authorization: headerString(req.headers.authorization),
        "content-type": headerString(req.headers["content-type"]),
        "idempotency-key": headerString(req.headers["idempotency-key"]),
      },
      body: null,
      recomputedHash: null,
      response: null,
      at: new Date(this.clock()).toISOString(),
    };
    this.requests.push(record);

    const raw = await readBody(req, MAX_REQUEST_BYTES);
    if (raw === null) return this.send(res, record, 413, { error: "REQUEST_TOO_LARGE" });
    try {
      record.body = raw.length === 0 ? null : JSON.parse(raw);
    } catch {
      record.body = truncate(raw);
      return this.send(res, record, 400, { error: "REQUEST_MALFORMED" });
    }
    if (req.headers.authorization !== `Bearer ${this.apiKey}`) {
      return this.send(res, record, 401, { error: "UNAUTHORIZED" });
    }
    const escalationLookup = url.pathname.match(/^\/v1\/authority\/escalations\/([^/]+)$/);
    if (req.method === "GET" && escalationLookup !== null) {
      return this.respond(
        res,
        record,
        "status",
        this.managedStatus(decodeURIComponent(escalationLookup[1] ?? "")),
      );
    }
    if (req.method === "DELETE" && escalationLookup !== null) {
      return this.cancelManaged(res, record, decodeURIComponent(escalationLookup[1] ?? ""));
    }
    if (req.method !== "POST") return this.send(res, record, 405, { error: "METHOD_NOT_ALLOWED" });
    if (req.headers["content-type"] !== "application/json") {
      return this.send(res, record, 415, { error: "UNSUPPORTED_MEDIA_TYPE" });
    }

    switch (url.pathname) {
      case "/v1/authority/enforce-and-bind":
        return this.respond(res, record, "enforce", this.enforceAndBind(record));
      case "/v1/execution/claim-token":
      case "/v1/execution/consume-token":
        return this.respond(res, record, "claim", this.claim(record));
      case "/v1/execution/finalize-token":
        return this.respond(res, record, "finalize", this.finalize(record));
      default:
        return this.send(res, record, 404, { error: "NOT_FOUND" });
    }
  }

  private enforceAndBind(record: LocalAuthorityRequestRecord): Computed {
    const parsed = AuthorityRequestSchema.safeParse(record.body);
    if (!parsed.success) return { status: 400, body: { error: "REQUEST_INVALID" } };
    const request = parsed.data;
    if (record.headers["idempotency-key"] !== request.intent_id) {
      return { status: 400, body: { error: "IDEMPOTENCY_KEY_MISMATCH" } };
    }
    const bindingError = this.assertBinding(request, record);
    if (bindingError !== null) return { status: 400, body: { error: bindingError } };

    const evaluation = this.evaluate(request);
    if (evaluation.error !== undefined) return { status: 409, body: { error: evaluation.error } };

    this.decisions += 1;
    const decision = this.baseDecision(request, evaluation.status, [evaluation.reasonCode]);
    if (evaluation.status === "ESCALATE" && request.escalation?.mode === "MANAGED") {
      return { status: 200, body: this.openManaged(request, decision) };
    }
    if (evaluation.status !== "ALLOW" || request.mode !== "ENFORCEMENT") {
      return { status: 200, body: decision };
    }
    return { status: 200, body: this.grantDecision(request, decision, evaluation.approval) };
  }

  /** Policy plus evidence handling: a valid receipt turns an escalation into an allow. */
  private evaluate(request: LocalAuthorityRequest): {
    readonly status: Verdict;
    readonly reasonCode: string;
    readonly approval: { readonly requestId: string; readonly receiptDossierId: string } | null;
    readonly error?: string;
  } {
    const verdict = this.policy(request);
    if (verdict === "BLOCK") {
      return { status: "BLOCK", reasonCode: "POLICY_HARD_LIMIT_EXCEEDED", approval: null };
    }
    if (verdict === "ALLOW") {
      return { status: "ALLOW", reasonCode: "POLICY_AUTONOMOUS_LIMIT", approval: null };
    }
    const humanApproval = request.evidence?.humanApproval;
    if (humanApproval === undefined) {
      return { status: "ESCALATE", reasonCode: "HUMAN_APPROVAL_REQUIRED", approval: null };
    }
    if (!this.verifyEvidence(humanApproval, request)) {
      // Decionis verifies the receipt with Presence and refuses the request.
      return {
        status: "BLOCK",
        reasonCode: "PRESENCE_RECEIPT_INVALID",
        approval: null,
        error: "PRESENCE_RECEIPT_INVALID",
      };
    }
    return { status: "ALLOW", reasonCode: "PRESENCE_RECEIPT_VERIFIED", approval: humanApproval };
  }

  private verifyEvidence(
    approval: { readonly requestId: string; readonly receiptDossierId: string },
    request: LocalAuthorityRequest,
    requiredRole?: string,
  ): boolean {
    if (this.presence !== undefined) {
      return this.presence.verifyReceiptDetailed(approval, {
        intentHash: request.intent_hash,
        actionType: request.action.type,
        resource: request.action.resource,
        ...(requiredRole === undefined ? {} : { requiredRole }),
      }).ok;
    }
    return this.legacyVerifyReceipt?.(approval, request.intent_hash) ?? false;
  }

  private baseDecision(
    request: LocalAuthorityRequest,
    status: Verdict,
    reasonCodes: readonly string[],
  ): Decision {
    const sequence = this.decisions;
    const dossierId = `synthetic-dossier-${sequence}`;
    return {
      decision_id: `synthetic-decision-${sequence}`,
      chain_id: "synthetic-chain-1",
      status,
      should_execute: false,
      reason_codes: [...reasonCodes],
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
      authority_classification: request.mode === "ENFORCEMENT" ? "AUTHORITATIVE" : "OBSERVATIONAL",
      execution_eligible: false,
      execution_binding_digest: null,
      execution_token_jti: null,
      execution_token_key_id: null,
    };
  }

  private grantDecision(
    request: LocalAuthorityRequest,
    decision: Decision,
    approval: { readonly requestId: string; readonly receiptDossierId: string } | null,
  ): Decision {
    const issuedAt = Math.floor(this.clock() / 1_000);
    const expiresAt = Math.min(
      Math.floor((this.clock() + GRANT_TTL_MS) / 1_000),
      Math.floor(Date.parse(request.expires_at) / 1_000),
    );
    const jti = `synthetic-jti-${randomUUID()}`;
    const token = `synthetic-grant.${jti}`;
    const bindingDigest = `sha256:${createHash("sha256").update(request.intent_hash).digest("hex")}`;
    this.grants.set(token, {
      jti,
      tenantId: request.tenant_id,
      actorId: request.actor.id,
      action: request.action.type,
      audience: `${request.downstream_target.system}:${request.downstream_target.operation}`,
      decisionId: String(decision.decision_id),
      dossierId: String(decision.dossier_id),
      intentHash: request.intent_hash,
      issuedAt,
      expiresAt,
      nonce: randomBytes(32).toString("base64url"),
      bindingDigest,
      receiptDossierId: approval?.receiptDossierId ?? null,
      claimed: false,
      claimToken: null,
      correlationId: null,
      consumedBy: null,
      finalized: null,
    });
    return {
      ...decision,
      should_execute: true,
      execution_token: token,
      execution_token_expires_at: new Date(expiresAt * 1_000).toISOString(),
      execution_eligible: true,
      execution_binding_digest: bindingDigest,
      execution_token_jti: jti,
      execution_token_key_id: "synthetic-key-1",
    };
  }

  /** Opens a managed escalation: scripted, orchestrated through LocalPresence, or default-scripted. */
  private openManaged(request: LocalAuthorityRequest, decision: Decision): Decision {
    const existing = this.managedByIntent.get(request.intent_id);
    if (existing !== undefined) return existing.initialDecision;
    const escalationId = `synthetic-escalation-${randomUUID()}`;
    const initialDecision: Decision = {
      ...decision,
      managed_escalation: {
        outcome: "ESCALATE_PENDING",
        escalation_id: escalationId,
        intent_id: request.intent_id,
        status: "PENDING_PRESENCE",
        expires_at: request.expires_at,
        reason_codes: ["PRESENCE_PENDING"],
      },
    };
    let lifecycle: LifecycleEntry[] | null = this.nextManagedLifecycle;
    this.nextManagedLifecycle = null;
    let presenceRequestId: string | null = null;
    let status: ManagedStatus = "PENDING_PRESENCE";
    let reasonCodes = ["PRESENCE_PENDING"];
    if (lifecycle === null && this.presence !== undefined) {
      const created = this.requestPresence(request, escalationId);
      if (created === null) {
        status = "FAILED";
        reasonCodes = ["PRESENCE_REQUEST_FAILED"];
      } else {
        presenceRequestId = created;
        status = "AWAITING_APPROVER";
      }
    } else if (lifecycle === null) {
      lifecycle = ["AWAITING_APPROVER", "GRANT_READY"];
    }
    const managed: LocalManagedEscalationRecord = {
      escalationId,
      request,
      presenceRequestId,
      lifecycle,
      lookup: 0,
      status,
      reasonCodes,
      finalDecision: null,
      initialDecision,
    };
    this.escalations.set(escalationId, managed);
    this.managedByIntent.set(request.intent_id, managed);
    return initialDecision;
  }

  /** Creates the Presence request the way Decionis does: bound structurally to the intent hash. */
  private requestPresence(request: LocalAuthorityRequest, escalationId: string): string | null {
    if (this.presence === undefined) return null;
    const requirements = request.escalation?.verification_requirements;
    const amountMinor = request.action.parameters.amountMinor;
    const currency = request.action.parameters.currency;
    const remainingSeconds = Math.floor((Date.parse(request.expires_at) - this.clock()) / 1_000);
    const created = this.presence.createRequest(
      {
        action_context: {
          intent: request.action.type,
          surface: "decionis_managed",
          actor_id: request.escalation?.approver?.principal_id ?? this.managedApproverId,
          target_resource_id: request.action.resource,
          intent_hash: request.intent_hash,
          ...(typeof amountMinor === "number" && typeof currency === "string"
            ? { amount: amountMinor / 100, currency: currency.toUpperCase() }
            : {}),
        },
        originator: {
          organization_name: "Local Decionis",
          actor_id: request.actor.id,
          display_name: request.actor.id,
          role: "AI execution authority requester",
        },
        presentation: {
          locale: "en",
          title: `Approve ${request.action.type}`,
          description: `${request.action.resource} is held until human authority is verified.`,
          display_fields: [
            { key: "action", label: "Action", value: request.action.type },
            { key: "target", label: "Target", value: request.action.resource },
            { key: "intent_hash", label: "Intent hash", value: request.intent_hash },
          ],
        },
        verification_requirements: {
          level: requirements?.level ?? "STANDARD",
          methods: requirements?.methods ?? ["WEBAUTHN"],
          hardware_pki_required: false,
          disallow_virtual_cameras: true,
        },
        ttl_seconds: Math.min(Math.max(remainingSeconds, 30), 600),
      },
      `managed-${createHash("sha256").update(escalationId).digest("hex").slice(0, 40)}`,
    );
    if (created.status !== 200) return null;
    const body = created.body as { request_id?: unknown };
    return typeof body.request_id === "string" ? body.request_id : null;
  }

  private managedStatus(escalationId: string): Computed {
    const managed = this.escalations.get(escalationId);
    if (managed === undefined) return { status: 404, body: { error: "NOT_FOUND" } };
    const state = managed.lifecycle === null ? this.advance(managed) : this.scripted(managed);
    let outcome = "ESCALATE_PENDING";
    let decision: Decision | null = null;
    if (state.status === "GRANT_READY") {
      outcome = "ALLOW";
      if (managed.finalDecision === null) {
        this.decisions += 1;
        managed.finalDecision = this.grantDecision(
          managed.request,
          this.baseDecision(
            { ...managed.request, mode: "ENFORCEMENT" },
            "ALLOW",
            state.reasonCodes,
          ),
          null,
        );
      }
      decision = managed.finalDecision;
    } else if (
      state.status === "EXPIRED" ||
      state.status === "REJECTED" ||
      state.status === "BLOCKED" ||
      state.status === "CANCELLED"
    ) {
      outcome = "BLOCK";
    } else if (state.status === "FAILED") {
      outcome = "ERROR";
    }
    return {
      status: 200,
      body: {
        escalation_id: managed.escalationId,
        intent_id: managed.request.intent_id,
        action_hash: managed.request.intent_hash,
        status: state.status,
        outcome,
        expires_at: managed.request.expires_at,
        reason_codes: state.reasonCodes,
        decision,
      },
    };
  }

  private scripted(managed: LocalManagedEscalationRecord): {
    readonly status: ManagedStatus;
    readonly reasonCodes: string[];
  } {
    const lifecycle = managed.lifecycle ?? [];
    const index = Math.min(managed.lookup, lifecycle.length - 1);
    const entry: LifecycleEntry = lifecycle[index] ?? "FAILED";
    managed.lookup += 1;
    const status = typeof entry === "string" ? entry : entry.status;
    const scriptedReasonCodes = typeof entry === "string" ? null : (entry.reasonCodes ?? null);
    const reasonCodes =
      scriptedReasonCodes ??
      (status === "GRANT_READY"
        ? ["PRESENCE_RECEIPT_VERIFIED"]
        : status === "EXPIRED"
          ? ["INTENT_EXPIRED", "RECAPTURE_REQUIRED"]
          : status === "REJECTED"
            ? ["PRESENCE_REJECTED"]
            : status === "CANCELLED"
              ? ["CANCELLED"]
              : status === "BLOCKED"
                ? ["REAUTHORIZATION_BLOCKED"]
                : status === "FAILED"
                  ? ["PRESENCE_VERIFICATION_FAILED"]
                  : ["PRESENCE_PENDING"]);
    managed.status = status;
    managed.reasonCodes = reasonCodes;
    return { status, reasonCodes };
  }

  /** Orchestrated state machine, mirroring Decionis's transitions against Presence. */
  private advance(managed: LocalManagedEscalationRecord): {
    readonly status: ManagedStatus;
    readonly reasonCodes: string[];
  } {
    const done = (status: ManagedStatus, reasonCodes: string[]) => {
      managed.status = status;
      managed.reasonCodes = reasonCodes;
      return { status, reasonCodes };
    };
    if (LocalAuthority.isTerminal(managed.status)) {
      return { status: managed.status, reasonCodes: managed.reasonCodes };
    }
    if (Date.parse(managed.request.expires_at) <= this.clock()) {
      return done("EXPIRED", ["INTENT_EXPIRED", "RECAPTURE_REQUIRED"]);
    }
    if (this.presence === undefined || managed.presenceRequestId === null) {
      return done("FAILED", ["PRESENCE_REQUEST_FAILED"]);
    }
    const view = this.presence.poll(managed.presenceRequestId);
    if (view === null) return done("FAILED", ["PRESENCE_REQUEST_FAILED"]);
    switch (view.status) {
      case "PENDING":
      case "DELIVERED":
        return done("AWAITING_APPROVER", ["PRESENCE_PENDING"]);
      case "BLOCKED":
        return done("REJECTED", ["PRESENCE_REJECTED"]);
      case "EXPIRED":
        return done("EXPIRED", ["PRESENCE_EXPIRED", "RECAPTURE_REQUIRED"]);
      case "CANCELLED":
        return done("CANCELLED", ["MANAGED_ESCALATION_CANCELLED"]);
      case "ALLOWED":
        break;
    }
    if (view.receiptDossierId === null) return done("FAILED", ["PRESENCE_VERIFICATION_FAILED"]);
    const verification = this.presence.verifyReceiptDetailed(
      { requestId: view.requestId, receiptDossierId: view.receiptDossierId },
      {
        intentHash: managed.request.intent_hash,
        actionType: managed.request.action.type,
        resource: managed.request.action.resource,
        ...(managed.request.escalation?.approver?.role_id === undefined
          ? {}
          : { requiredRole: managed.request.escalation.approver.role_id }),
      },
    );
    if (!verification.ok)
      return done("FAILED", ["PRESENCE_VERIFICATION_FAILED", verification.reasonCode]);
    // PRESENCE_VERIFIED and REAUTHORIZING are passed through within one lookup, as Decionis does.
    const reevaluated = this.policy(managed.request);
    if (reevaluated === "BLOCK") return done("BLOCKED", ["REAUTHORIZATION_BLOCKED"]);
    return done("GRANT_READY", ["PRESENCE_RECEIPT_VERIFIED"]);
  }

  private cancelManaged(
    res: ServerResponse,
    record: LocalAuthorityRequestRecord,
    escalationId: string,
  ): void {
    const managed = this.escalations.get(escalationId);
    if (managed === undefined) return this.send(res, record, 404, { error: "NOT_FOUND" });
    if (managed.lifecycle !== null) {
      managed.lifecycle = ["CANCELLED"];
      managed.lookup = 0;
    } else if (!LocalAuthority.isTerminal(managed.status)) {
      if (managed.presenceRequestId !== null) this.presence?.cancel(managed.presenceRequestId);
      managed.status = "CANCELLED";
      managed.reasonCodes = ["MANAGED_ESCALATION_CANCELLED"];
    }
    const result = this.managedStatus(escalationId);
    return this.send(res, record, result.status, result.body);
  }

  private claim(record: LocalAuthorityRequestRecord): Computed {
    const parsed = TokenRequestSchema.safeParse(record.body);
    if (!parsed.success) return { status: 400, body: { error: "REQUEST_INVALID" } };
    const intent = IntentBindingSchema.safeParse(parsed.data.intent);
    if (!intent.success) return { status: 400, body: { error: "REQUEST_INVALID" } };
    const rejected = (reasonCode: string, status = 409): Computed => ({
      status,
      body: { valid: false, reason_codes: [reasonCode], claims: null },
    });
    const bindingError = this.assertBinding(
      { ...intent.data, intent_hash: parsed.data.intent_hash },
      record,
    );
    if (bindingError !== null) return rejected(bindingError);

    const grant = this.grants.get(parsed.data.execution_token);
    if (grant === undefined) return rejected("GRANT_INVALID");
    if (grant.expiresAt * 1_000 <= this.clock()) return rejected("GRANT_EXPIRED");
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
        claim_lease_expires_at: new Date(this.clock() + CLAIM_LEASE_MS).toISOString(),
        evidence: { nonce_claim_state: "CLAIMED", commit_correlation_id: grant.correlationId },
      },
    };
  }

  private finalize(record: LocalAuthorityRequestRecord): Computed {
    const parsed = FinalizeRequestSchema.safeParse(record.body);
    if (!parsed.success) return { status: 400, body: { error: "REQUEST_INVALID" } };
    const rejected = (reasonCode: string): Computed => ({
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
  private assertBinding(
    request: IntentBinding & { readonly intent_hash: string },
    record: LocalAuthorityRequestRecord,
  ): string | null {
    const recomputed = hashBinding(bindingOf(request as unknown as Record<string, unknown>));
    record.recomputedHash = recomputed;
    if (recomputed !== request.intent_hash) return "INTENT_HASH_MISMATCH";
    const capturedAt = Date.parse(request.captured_at);
    const expiresAt = Date.parse(request.expires_at);
    const now = this.clock();
    if (capturedAt > now + 5_000) return "INTENT_CAPTURED_IN_FUTURE";
    if (expiresAt <= now) return "INTENT_EXPIRED";
    if (expiresAt <= capturedAt) return "INTENT_TIME_ORDER_INVALID";
    if (expiresAt - capturedAt > 300_000) return "INTENT_LIFETIME_TOO_LONG";
    return null;
  }

  private async respond(
    res: ServerResponse,
    record: LocalAuthorityRequestRecord,
    route: LocalAuthorityRoute,
    computed: Computed,
  ): Promise<void> {
    const override = this.overrides[route].shift();
    if (override === undefined) return this.send(res, record, computed.status, computed.body);
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
    return this.send(res, record, status, body);
  }

  private send(
    res: ServerResponse,
    record: LocalAuthorityRequestRecord,
    status: number,
    body: unknown,
  ): void {
    const raw = typeof body === "string" ? body : JSON.stringify(body);
    record.response = { status, body: typeof body === "string" ? truncate(body) : body };
    res.writeHead(status, { "content-type": "application/json" });
    res.end(raw);
  }

  private static isTerminal(status: ManagedStatus): boolean {
    return (
      status === "GRANT_READY" ||
      status === "EXPIRED" ||
      status === "REJECTED" ||
      status === "BLOCKED" ||
      status === "CANCELLED" ||
      status === "FAILED"
    );
  }
}

function headerString(value: string | string[] | undefined): string | null {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value[0] ?? null;
  return null;
}
