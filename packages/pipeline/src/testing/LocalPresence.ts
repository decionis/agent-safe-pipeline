/**
 * Loopback stand-in for the Presence verification-request surface that the
 * `@decionis/presence-node` human-approval gate uses, with the semantics an
 * execution authority relies on: a request is bound to the exact intent hash
 * (structurally through `action_context.intent_hash`, with the mandatory
 * `Intent hash` display field as the fallback), a receipt exists only after a
 * ceremony, the projection carries who approved in which role and with which
 * authenticator, and receipt verification checks everything Decionis checks.
 *
 * It is a local double for developers and tests. It does not run a FIDO2
 * ceremony, sign receipts, or reproduce the Presence Authority envelope
 * protocol; the ceremony is completed by `approve`, `deny`, or the local
 * control route. Every identity it mints is synthetic.
 */
import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { z } from "zod";

export const LOCAL_PRESENCE_API_KEY = "test-key";

const LOOPBACK_ORIGIN = "http://127.0.0.1";
const MAX_REQUEST_BYTES = 64 * 1024;
const SOCKET_TIMEOUT_MS = 10_000;
const IDEMPOTENCY_KEY_PATTERN = /^[\w.:-]{8,128}$/;
const INTENT_HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;

const boundedString = z.string().min(1).max(500);

/** `CreateVerificationRequest` as the Presence contract accepts it, including the structural binding. */
const CreateVerificationRequestSchema = z.object({
  action_context: z
    .object({
      intent: boundedString,
      surface: boundedString,
      actor_id: boundedString,
      target_resource_id: boundedString,
      intent_hash: z.string().regex(INTENT_HASH_PATTERN).optional(),
      amount: z.number().nonnegative().optional(),
      currency: z.string().length(3).optional(),
    })
    .passthrough(),
  originator: z
    .object({
      organization_name: boundedString,
      actor_id: boundedString.optional(),
      display_name: boundedString.optional(),
      role: boundedString.optional(),
    })
    .passthrough(),
  presentation: z.object({
    locale: z.string().min(1).max(35),
    title: boundedString,
    description: z.string().min(1).max(2_000),
    display_fields: z
      .array(z.object({ key: boundedString, label: boundedString, value: boundedString }).strict())
      .max(50),
  }),
  verification_requirements: z
    .object({
      level: z.enum(["STANDARD", "HIGH_CONFIDENCE"]),
      methods: z
        .array(z.enum(["WEBAUTHN", "MOBILE_DEVICE", "ACTIVE_LIVENESS"]))
        .min(1)
        .max(3),
      hardware_pki_required: z.boolean(),
      disallow_virtual_cameras: z.boolean(),
      mobile_device_policy: z.enum(["WEB_OR_JIT_DEVICE", "MANAGED_DEVICE_REQUIRED"]).optional(),
    })
    .passthrough(),
  ttl_seconds: z.number().int().min(30).max(600).default(120),
});

export type LocalVerificationStatus =
  "PENDING" | "DELIVERED" | "ALLOWED" | "BLOCKED" | "EXPIRED" | "CANCELLED";
export type LocalCeremonyResponse = "APPROVE" | "DENY";

export interface LocalAuthenticator {
  readonly method: "WEBAUTHN" | "MOBILE_DEVICE" | "ACTIVE_LIVENESS";
  readonly aaguid?: string;
  readonly device_platform?: string;
  readonly user_verified: boolean;
  readonly attestation_reference?: string;
}

export interface LocalPresenceOptions {
  readonly apiKey?: string;
  /** Outcome lookups that stay pending before automatic completion. Default 1. */
  readonly pendingLookups?: number;
  /**
   * `APPROVE` (default) completes the ceremony automatically after the pending
   * lookups; `DENY` denies it; `MANUAL` waits for `approve`, `deny`, or the
   * `/local/verification-requests/:id/complete` control route.
   */
  readonly autoComplete?: LocalCeremonyResponse | "MANUAL";
  /** Role returned for an approving identity; `roles` overrides per identity. */
  readonly defaultRole?: string;
  readonly roles?: Readonly<Record<string, string>>;
  /** Authenticator evidence sealed into every approval. */
  readonly authenticator?: LocalAuthenticator;
  readonly clock?: () => number;
}

export interface LocalVerificationRecord {
  readonly requestId: string;
  readonly sessionId: string;
  readonly intentDigest: string;
  readonly idempotencyKey: string;
  readonly subjectActorId: string;
  readonly subjectRole: string;
  readonly action: { readonly intent: string; readonly target: string };
  /** Structural binding when supplied, otherwise the `intent_hash` display field, otherwise null. */
  readonly intentHash: string | null;
  readonly bindingSource: "structural" | "display_field" | "none";
  readonly actionContext: Readonly<Record<string, unknown>>;
  readonly presentation: z.infer<typeof CreateVerificationRequestSchema>["presentation"];
  readonly requirements: Readonly<Record<string, unknown>>;
  readonly createdAt: string;
  readonly expiresAt: string;
  status: LocalVerificationStatus;
  result: "ALLOW" | "BLOCK" | null;
  receiptDossierId: string | null;
  approvedAt: string | null;
  lookups: number;
  scheduledResponse: LocalCeremonyResponse | "MANUAL";
}

export interface LocalReceipt {
  readonly requestId: string;
  readonly intentHash: string | null;
  readonly result: "ALLOW" | "BLOCK";
  readonly approverIdentity: string;
  readonly approverRole: string;
  readonly sealedAt: string;
}

/** What the authority needs to verify a receipt against an execution intent. */
export interface LocalReceiptBinding {
  readonly intentHash: string;
  readonly actionType?: string;
  readonly resource?: string;
  readonly requiredRole?: string;
}

export type LocalReceiptVerification =
  | {
      readonly ok: true;
      readonly approverIdentity: string;
      readonly approverRole: string;
      readonly authenticator: LocalAuthenticator;
    }
  | { readonly ok: false; readonly reasonCode: string };

export interface LocalPresenceRequestRecord {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string | null>>;
  body: unknown;
  response: { readonly status: number; readonly body: unknown } | null;
  readonly at: string;
}

interface ComputedResponse {
  readonly status: number;
  readonly body: unknown;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((item) => canonical(item)).join(",")}]`;
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  const record = value as Record<string, unknown>;
  const entries = Object.keys(record)
    .sort()
    .filter((key) => record[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`);
  return `{${entries.join(",")}}`;
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export class LocalPresence {
  /** Every request seen, oldest first. */
  public readonly requests: LocalPresenceRequestRecord[] = [];
  /** Receipts sealed, keyed by receipt dossier id. */
  public readonly receipts = new Map<string, LocalReceipt>();
  private readonly verifications = new Map<string, LocalVerificationRecord>();
  private readonly byIdempotencyKey = new Map<string, string>();
  private readonly apiKey: string;
  private readonly pendingLookups: number;
  private readonly autoComplete: LocalCeremonyResponse | "MANUAL";
  private readonly defaultRole: string;
  private readonly roles: Readonly<Record<string, string>>;
  private readonly authenticator: LocalAuthenticator;
  private readonly clock: () => number;
  private nextStatus: LocalCeremonyResponse | "MANUAL" | null = null;
  private sequence = 0;
  private server: Server | null = null;
  private port = 0;

  public constructor(options: LocalPresenceOptions = {}) {
    if (process.env.NODE_ENV === "production") throw new Error("LOCAL_DOUBLE_FORBIDDEN");
    this.apiKey = options.apiKey ?? LOCAL_PRESENCE_API_KEY;
    this.pendingLookups = options.pendingLookups ?? 1;
    this.autoComplete = options.autoComplete ?? "APPROVE";
    this.defaultRole = options.defaultRole ?? "APPROVER";
    this.roles = options.roles ?? {};
    this.authenticator = options.authenticator ?? { method: "WEBAUTHN", user_verified: true };
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
   * Terminal status of the next request created: `"ALLOWED"` approves,
   * `"BLOCKED"` denies, `"MANUAL"` waits for an explicit completion.
   */
  public scriptNextStatus(status: "ALLOWED" | "BLOCKED" | "MANUAL"): void {
    this.nextStatus = status === "ALLOWED" ? "APPROVE" : status === "BLOCKED" ? "DENY" : "MANUAL";
  }

  /** The current state of one verification request without counting a lookup, or null. */
  public verification(requestId: string): Readonly<LocalVerificationRecord> | null {
    const record = this.verifications.get(requestId);
    return record === undefined ? null : this.expireIfDue(record);
  }

  /**
   * One outcome lookup, as the authority or the SDK performs it: counts toward
   * the pending lookups, applies automatic completion and expiry, and returns
   * the current state.
   */
  public poll(requestId: string): Readonly<LocalVerificationRecord> | null {
    const record = this.verifications.get(requestId);
    if (record === undefined) return null;
    this.expireIfDue(record);
    if (record.status === "PENDING" || record.status === "DELIVERED") {
      record.lookups += 1;
      if (record.scheduledResponse !== "MANUAL" && record.lookups > this.pendingLookups) {
        this.complete(requestId, record.scheduledResponse);
      }
    }
    return record;
  }

  /** Completes the ceremony as an approval by the bound subject. */
  public approve(requestId: string): LocalReceipt | null {
    return this.complete(requestId, "APPROVE");
  }

  /** Completes the ceremony as a denial by the bound subject. */
  public deny(requestId: string): LocalReceipt | null {
    return this.complete(requestId, "DENY");
  }

  public cancel(requestId: string): boolean {
    const record = this.verifications.get(requestId);
    if (record === undefined || this.isTerminal(record)) return false;
    record.status = "CANCELLED";
    record.result = "BLOCK";
    return true;
  }

  /** Forces expiry regardless of the clock. */
  public expire(requestId: string): boolean {
    const record = this.verifications.get(requestId);
    if (record === undefined || this.isTerminal(record)) return false;
    record.status = "EXPIRED";
    record.result = "BLOCK";
    return true;
  }

  /** Compatibility check used by the contract harness: receipt, request, and hash agree. */
  public verifyReceipt(
    approval: { readonly requestId: string; readonly receiptDossierId: string },
    binding: string | LocalReceiptBinding,
  ): boolean {
    return this.verifyReceiptDetailed(approval, binding).ok;
  }

  /**
   * Mirrors the authority-side checks: terminal ALLOWED with result ALLOW, the
   * receipt the request produced, action type and target, the intent hash
   * (structural when present, otherwise the display field), an approver with
   * a role, an optional required role, and the request's own expiry.
   */
  public verifyReceiptDetailed(
    approval: { readonly requestId: string; readonly receiptDossierId: string },
    binding: string | LocalReceiptBinding,
  ): LocalReceiptVerification {
    const expected = typeof binding === "string" ? { intentHash: binding } : binding;
    const record = this.verifications.get(approval.requestId);
    if (record === undefined) return { ok: false, reasonCode: "PRESENCE_REQUEST_UNKNOWN" };
    this.expireIfDue(record);
    const receipt = this.receipts.get(approval.receiptDossierId);
    if (
      receipt === undefined ||
      receipt.requestId !== approval.requestId ||
      record.receiptDossierId !== approval.receiptDossierId
    ) {
      return { ok: false, reasonCode: "PRESENCE_DOSSIER_INVALID" };
    }
    if (record.status !== "ALLOWED" || record.result !== "ALLOW" || receipt.result !== "ALLOW") {
      return { ok: false, reasonCode: "PRESENCE_OUTCOME_NOT_ALLOW" };
    }
    if (
      (expected.actionType !== undefined && record.action.intent !== expected.actionType) ||
      (expected.resource !== undefined && record.action.target !== expected.resource)
    ) {
      return { ok: false, reasonCode: "PRESENCE_ACTION_MISMATCH" };
    }
    if (record.intentHash !== expected.intentHash) {
      return { ok: false, reasonCode: "PRESENCE_INTENT_HASH_MISMATCH" };
    }
    if (expected.requiredRole !== undefined && receipt.approverRole !== expected.requiredRole) {
      return { ok: false, reasonCode: "PRESENCE_APPROVER_ROLE_MISMATCH" };
    }
    if (Date.parse(record.expiresAt) <= this.clock()) {
      return { ok: false, reasonCode: "PRESENCE_APPROVAL_EXPIRED" };
    }
    return {
      ok: true,
      approverIdentity: receipt.approverIdentity,
      approverRole: receipt.approverRole,
      authenticator: this.authenticator,
    };
  }

  /** Creates a request without HTTP; the same path the route uses. */
  public createRequest(
    body: unknown,
    idempotencyKey: string,
  ): { readonly status: number; readonly body: unknown } {
    return this.createVerificationRequest(body, idempotencyKey);
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", this.baseUrl);
    const record: LocalPresenceRequestRecord = {
      method: req.method ?? "GET",
      path: url.pathname,
      headers: {
        authorization: headerString(req.headers.authorization),
        "idempotency-key": headerString(req.headers["idempotency-key"]),
      },
      body: null,
      response: null,
      at: new Date(this.clock()).toISOString(),
    };
    this.requests.push(record);

    const raw = await readBody(req, MAX_REQUEST_BYTES);
    if (raw === null) return this.send(res, record, 413, { reason: "REQUEST_TOO_LARGE" });
    try {
      record.body = raw.length === 0 ? null : JSON.parse(raw);
    } catch {
      return this.send(res, record, 400, { reason: "REQUEST_MALFORMED" });
    }
    if (req.headers.authorization !== `Bearer ${this.apiKey}`) {
      return this.send(res, record, 401, { reason: "UNAUTHORIZED" });
    }

    const requestMatch = url.pathname.match(/^\/v1\/verification-requests\/([^/]+)$/);
    const completeMatch = url.pathname.match(/^\/local\/verification-requests\/([^/]+)\/complete$/);
    const dossierMatch = url.pathname.match(/^\/v1\/dossiers\/([^/]+)\/verify$/);
    let computed: ComputedResponse;
    if (req.method === "POST" && url.pathname === "/v1/verification-requests") {
      computed = this.createVerificationRequest(
        record.body,
        record.headers["idempotency-key"] ?? "",
      );
    } else if (req.method === "GET" && requestMatch !== null) {
      computed = this.projection(decodeURIComponent(requestMatch[1] ?? ""));
    } else if (req.method === "DELETE" && requestMatch !== null) {
      const cancelled = this.cancel(decodeURIComponent(requestMatch[1] ?? ""));
      computed = cancelled
        ? this.projection(decodeURIComponent(requestMatch[1] ?? ""))
        : { status: 409, body: { reason: "request_not_cancellable" } };
    } else if (req.method === "POST" && completeMatch !== null) {
      const response = (record.body as { response?: unknown } | null)?.response;
      if (response !== "APPROVE" && response !== "DENY") {
        computed = { status: 400, body: { reason: "REQUEST_INVALID" } };
      } else {
        const receipt = this.complete(decodeURIComponent(completeMatch[1] ?? ""), response);
        computed =
          receipt === null
            ? { status: 409, body: { reason: "request_not_completable" } }
            : this.projection(decodeURIComponent(completeMatch[1] ?? ""));
      }
    } else if (req.method === "GET" && dossierMatch !== null) {
      const dossierId = decodeURIComponent(dossierMatch[1] ?? "");
      const receipt = this.receipts.get(dossierId);
      computed = {
        status: receipt === undefined ? 404 : 200,
        body: {
          dossier_id: dossierId,
          valid: receipt !== undefined,
          signature_valid: receipt !== undefined,
          chain_valid: receipt !== undefined,
        },
      };
    } else {
      computed = { status: 404, body: { reason: "NOT_FOUND" } };
    }
    return this.send(res, record, computed.status, computed.body);
  }

  private createVerificationRequest(body: unknown, idempotencyKey: string): ComputedResponse {
    if (!IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey)) {
      return { status: 400, body: { reason: "invalid_idempotency_key" } };
    }
    const parsed = CreateVerificationRequestSchema.safeParse(body);
    if (!parsed.success) return { status: 400, body: { reason: "REQUEST_INVALID" } };
    const input = parsed.data;
    const existingId = this.byIdempotencyKey.get(idempotencyKey);
    if (existingId !== undefined) return this.created(existingId);

    const displayed =
      input.presentation.display_fields.find((field) => field.key === "intent_hash")?.value ?? null;
    const structural = input.action_context.intent_hash ?? null;
    if (structural !== null && displayed !== null && structural !== displayed) {
      // A structural binding that disagrees with what the person would see is
      // an integration defect, never something to seal.
      return { status: 400, body: { reason: "intent_binding_mismatch" } };
    }
    this.sequence += 1;
    const requestId = `synthetic-presence-request-${this.sequence}`;
    const now = this.clock();
    const subjectActorId = input.action_context.actor_id;
    const record: LocalVerificationRecord = {
      requestId,
      sessionId: `synthetic-presence-session-${this.sequence}`,
      intentDigest: sha256Hex(canonical(input.action_context)),
      idempotencyKey,
      subjectActorId,
      subjectRole: this.roles[subjectActorId] ?? this.defaultRole,
      action: {
        intent: input.action_context.intent,
        target: input.action_context.target_resource_id,
      },
      intentHash: structural ?? displayed,
      bindingSource:
        structural !== null ? "structural" : displayed !== null ? "display_field" : "none",
      actionContext: input.action_context,
      presentation: input.presentation,
      requirements: input.verification_requirements,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + input.ttl_seconds * 1_000).toISOString(),
      status: "PENDING",
      result: null,
      receiptDossierId: null,
      approvedAt: null,
      lookups: 0,
      scheduledResponse: this.nextStatus ?? this.autoComplete,
    };
    this.nextStatus = null;
    this.verifications.set(requestId, record);
    this.byIdempotencyKey.set(idempotencyKey, requestId);
    return this.created(requestId);
  }

  private created(requestId: string): ComputedResponse {
    const record = this.verifications.get(requestId);
    if (record === undefined) return { status: 404, body: { reason: "request_not_found" } };
    return {
      status: 200,
      body: {
        request_id: requestId,
        invitation_token: `presence_it_synthetic_${this.sequence}`,
        invitation_url: `https://presence.example.invalid/verify#invitation_token=presence_it_synthetic_${this.sequence}`,
        invitation_expires_at: record.expiresAt,
        channel: "handoff",
      },
    };
  }

  private projection(requestId: string): ComputedResponse {
    const record = this.poll(requestId);
    if (record === null) return { status: 404, body: { reason: "request_not_found" } };
    const receipt =
      record.receiptDossierId === null ? undefined : this.receipts.get(record.receiptDossierId);
    return {
      status: 200,
      body: {
        request_id: record.requestId,
        session_id: record.sessionId,
        intent_digest: record.intentDigest,
        status: record.status,
        ...(record.result === null ? {} : { result: record.result }),
        ...(record.receiptDossierId === null
          ? {}
          : { receipt_dossier_id: record.receiptDossierId }),
        ...(record.approvedAt === null ? {} : { approved_at: record.approvedAt }),
        expires_at: record.expiresAt,
        envelope: {
          envelope_version: "presence.intent/1",
          action_context: record.actionContext,
          subject_actor_id: record.subjectActorId,
          presentation: record.presentation,
          verification_requirements: record.requirements,
          expires_at: record.expiresAt,
        },
        ...(receipt === undefined
          ? {}
          : {
              approver: { id: receipt.approverIdentity, role: receipt.approverRole },
              approver_identity: receipt.approverIdentity,
              approver_role: receipt.approverRole,
              authenticator: this.authenticator,
            }),
      },
    };
  }

  private complete(requestId: string, response: LocalCeremonyResponse): LocalReceipt | null {
    const record = this.verifications.get(requestId);
    if (record === undefined) return null;
    this.expireIfDue(record);
    if (this.isTerminal(record)) return null;
    const receiptDossierId = `synthetic-presence-receipt-${requestId.split("-").at(-1) ?? "0"}`;
    const sealedAt = new Date(this.clock()).toISOString();
    const receipt: LocalReceipt = {
      requestId,
      intentHash: record.intentHash,
      result: response === "APPROVE" ? "ALLOW" : "BLOCK",
      approverIdentity: record.subjectActorId,
      approverRole: record.subjectRole,
      sealedAt,
    };
    this.receipts.set(receiptDossierId, receipt);
    record.receiptDossierId = receiptDossierId;
    record.result = receipt.result;
    record.status = response === "APPROVE" ? "ALLOWED" : "BLOCKED";
    record.approvedAt = response === "APPROVE" ? sealedAt : null;
    return receipt;
  }

  private expireIfDue(record: LocalVerificationRecord): LocalVerificationRecord {
    if (!this.isTerminal(record) && Date.parse(record.expiresAt) <= this.clock()) {
      record.status = "EXPIRED";
      record.result = "BLOCK";
    }
    return record;
  }

  private isTerminal(record: LocalVerificationRecord): boolean {
    return record.status !== "PENDING" && record.status !== "DELIVERED";
  }

  private send(
    res: ServerResponse,
    record: LocalPresenceRequestRecord,
    status: number,
    body: unknown,
  ): void {
    record.response = { status, body };
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  }
}

function headerString(value: string | string[] | undefined): string | null {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value[0] ?? null;
  return null;
}

export async function readBody(req: IncomingMessage, maxBytes: number): Promise<string | null> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer);
    total += buffer.length;
    if (total > maxBytes) return null;
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}
