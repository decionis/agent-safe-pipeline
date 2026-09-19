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
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
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
/** The issuer the fixture's grants and attestations name; a provider double checks it. */
export const LOCAL_AUTHORITY_ISSUER = "synthetic-authority";
/** Where the fixture publishes its attestation key, at the path Decionis documents. */
export const LOCAL_AUTHORITY_JWKS_PATH = "/.well-known/decionis-execution-grant-jwks.json";
export const CLAIM_ATTESTATION_TYPE = "decionis-claim-attestation+jwt";
/** The protected header `typ` of a verifying provider's effect receipt (VP-3). */
export const EFFECT_RECEIPT_TYPE = "decionis-effect-receipt+jwt";
const COMPACT_JWS = /^[\w-]+\.[\w-]+\.[\w-]+$/;
/** The profile the fixture digests parameters under; the only one the pipeline reproduces. */
const JCS_PROFILE = "RFC8785/JCS";

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
  expected_effect_digest: sha256Digest.optional(),
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

/** `boundedIdentifier` from the Decionis `EffectEvidence` contract, verbatim. */
const boundedEffectIdentifier = z.string().trim().min(1).max(500);

/**
 * Protocol 1.1 `EffectEvidence`, mirrored from the Decionis shared contract
 * including its `CONFIRMED` refinements: a confirmed observation may not rest
 * on a bare downstream acknowledgement, must name an observer with a version,
 * must have observed exactly the expected effect at a stated time, and must
 * carry a digest or a reference for the observation itself.
 */
const EffectEvidenceSchema = z
  .strictObject({
    version: z.literal("1.0"),
    status: z.enum(["CONFIRMED", "UNCONFIRMED"]),
    observation_method: z.enum([
      "DOWNSTREAM_ACK",
      "READ_AFTER_WRITE",
      "EVENT_CONFIRMATION",
      "STATE_RECONCILIATION",
      "SIGNED_RECEIPT",
      "EXTERNAL_ATTESTATION",
      "HUMAN_VALIDATION",
    ]),
    observer: z
      .strictObject({
        id: boundedEffectIdentifier,
        version: boundedEffectIdentifier.nullable(),
      })
      .nullable(),
    expected_effect_digest: sha256Digest,
    observed_effect_digest: sha256Digest.nullable(),
    observed_at: z.iso.datetime().nullable(),
    evidence_digest: sha256Digest.nullable(),
    evidence_reference: boundedEffectIdentifier.nullable(),
    execution_correlation_id: boundedEffectIdentifier,
  })
  .superRefine((evidence, context) => {
    if (evidence.status !== "CONFIRMED") return;
    const fail = (message: string): void => {
      context.addIssue({ code: "custom", message });
    };
    if (evidence.observation_method === "DOWNSTREAM_ACK") fail("EFFECT_METHOD_INSUFFICIENT");
    if (evidence.observer === null || evidence.observer.version === null) {
      fail("EFFECT_OBSERVER_REQUIRED");
    }
    if (evidence.observed_effect_digest !== evidence.expected_effect_digest) {
      fail("EFFECT_OBSERVED_DIGEST_MISMATCH");
    }
    if (evidence.observed_at === null) fail("EFFECT_OBSERVED_AT_REQUIRED");
    if (evidence.evidence_digest === null && evidence.evidence_reference === null) {
      fail("EFFECT_EVIDENCE_ARTIFACT_REQUIRED");
    }
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
  // Deliberately unvalidated here: the hosted route answers malformed effect
  // evidence with a 409 and a reason code, not with a 400 request rejection,
  // so the shape is checked where that answer is produced.
  effect_evidence: z.unknown().optional(),
  // The provider's receipt: only its shape is a request error. What it says
  // is verified and recorded, never a reason to refuse the finalization.
  effect_receipt: z.string().min(1).max(20_000).regex(COMPACT_JWS).optional(),
});

/** `ExecutionProviderKeyRegistrationRequest`: the public half of an Ed25519 key. */
const ProviderKeyRegistrationSchema = z.strictObject({
  org_id: z.uuid().optional(),
  kid: boundedId,
  issuer: z.string().trim().min(1).max(500),
  algorithm: z.literal("EdDSA"),
  public_jwk: z.strictObject({
    kty: z.literal("OKP"),
    crv: z.literal("Ed25519"),
    x: z.string().regex(/^[\w-]{43}$/),
    kid: z.string().optional(),
    alg: z.literal("EdDSA").optional(),
    use: z.literal("sig").optional(),
  }),
  label: z.string().max(200).optional(),
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
  /** The digest the authority bound over the canonical action parameters. */
  readonly payloadDigest: string;
  /** The expected-effect digest committed at enforce-and-bind; null when none was bound. */
  readonly expectedEffectDigest: string | null;
  /** Present for direct grants issued on client-supplied evidence; null for managed grants. */
  readonly receiptDossierId: string | null;
  claimed: boolean;
  claimToken: string | null;
  correlationId: string | null;
  consumedBy: string | null;
  finalized: "COMMITTED" | "FAILED" | "INDETERMINATE" | null;
  /** The provider's effect receipt as this authority read it at finalization, when one came. */
  receipt: LocalEffectReceiptRecord | null;
}

/** The verdict codes the hosted authority records for a receipt, and this double with it. */
export type LocalEffectReceiptCode =
  | "EFFECT_RECEIPT_VERIFIED"
  | "EFFECT_RECEIPT_MALFORMED"
  | "EFFECT_RECEIPT_KEY_UNKNOWN"
  | "EFFECT_RECEIPT_SIGNATURE_INVALID"
  | "EFFECT_RECEIPT_BINDING_MISMATCH";

export interface LocalEffectReceiptRecord {
  readonly token: string;
  readonly verified: boolean;
  readonly verification_code: LocalEffectReceiptCode;
  readonly provider_key_id: string | null;
  readonly issuer: string | null;
  readonly effect_status: "EFFECTED" | "REFUSED" | "INDETERMINATE" | null;
  readonly effect_digest: string | null;
  readonly effect_reference: string | null;
  readonly effected_at: string | null;
}

function effectStatus(value: unknown): LocalEffectReceiptRecord["effect_status"] {
  return value === "EFFECTED" || value === "REFUSED" || value === "INDETERMINATE" ? value : null;
}

/** A verifying provider's registered receipt key: the public half, its `kid`, the `iss` it signs as. */
export interface LocalProviderKey {
  readonly kid: string;
  readonly issuer: string;
  readonly publicKey: KeyObject;
  readonly label: string | null;
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
  /**
   * API-key identities this deployment accepts as effect observers, mirroring
   * `DECIONIS_TRUSTED_EFFECT_OBSERVER_API_KEY_IDS`. Empty by default, exactly as
   * the hosted authority is by default, so `CONFIRMED` evidence is refused
   * unless a test opts in. As in the hosted route, the allowlist is intersected
   * with the caller's own authenticated identity — this double's `apiKey` — so
   * naming any other id confirms nothing.
   */
  readonly trustedEffectObserverIds?: readonly string[];
  readonly clock?: () => number;
  /**
   * Attach a verification envelope to every decision, as the hosted
   * `evaluate-decision` does and `enforce-and-bind` may: a page URL under
   * this double's own origin, so a test can see the link travel end to end.
   */
  readonly verificationLinks?: boolean;
}

/** The organization a provisioned synthetic workspace belongs to. */
export const LOCAL_AUTHORITY_PROVISIONAL_ORG_ID = "00000000-0000-4000-8000-000000000008";

/** What one claim attestation says, as the fixture signs it and a provider double reads it. */
export interface LocalClaimAttestationClaims {
  readonly iss: string;
  readonly sub: string;
  readonly org_id: string;
  readonly dossier_id: string;
  readonly decision_id: string;
  readonly binding: {
    readonly intent_hash: string;
    readonly execution_payload_digest: string;
    readonly execution_payload_canonicalization_profile: string;
    readonly expected_effect_digest?: string;
    readonly execution_nonce: string;
    readonly execution_correlation_id: string;
  };
  readonly claim_token_digest: string;
  readonly claim_validated_at: string;
  readonly jti: string;
  readonly iat: number;
  readonly nbf: number;
  readonly exp: number;
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
  /** The verifying providers' receipt keys, by `kid`, as `/v1/execution/provider-keys` registers them. */
  public readonly providerKeys = new Map<string, LocalProviderKey>();
  private readonly apiKey: string;
  private readonly presence: LocalPresence | undefined;
  private readonly legacyVerifyReceipt: LocalAuthorityOptions["verifyReceipt"];
  private readonly policy: LocalAuthorityPolicy;
  private readonly managedApproverId: string;
  private readonly trustedEffectObserverIds: readonly string[];
  private readonly clock: () => number;
  private readonly attestationKey: {
    readonly privateKey: KeyObject;
    readonly publicJwk: JsonWebKey;
  };
  /** The `kid` the fixture's attestations name; a provider double looks it up in the JWKS. */
  public readonly attestationKeyId = "synthetic-exec-grant-1";
  /**
   * A drill knob: when set, the next claim binds a digest over parameters
   * other than the ones captured, which is what a tampered or mismatched
   * authority looks like from the executor's side, and what BEAP-L3-BND-01
   * says the executor must refuse.
   */
  public misbindNextPayloadDigest = false;
  private readonly overrides: Record<LocalAuthorityRoute, LocalRouteOverride[]> = {
    enforce: [],
    status: [],
    claim: [],
    finalize: [],
  };
  private readonly managedByIntent = new Map<string, LocalManagedEscalationRecord>();
  private nextManagedLifecycle: LifecycleEntry[] | null = null;
  private decisions = 0;
  /** Every decision minted, by dossier id, for `GET /v1/protocol/dossiers/{id}`. */
  private readonly dossiers = new Map<
    string,
    { readonly request: LocalAuthorityRequest; readonly decision: Decision }
  >();
  private readonly verificationLinks: boolean;
  private server: Server | null = null;
  private port = 0;

  public constructor(options: LocalAuthorityOptions = {}) {
    if (process.env.NODE_ENV === "production") throw new Error("LOCAL_DOUBLE_FORBIDDEN");
    this.apiKey = options.apiKey ?? LOCAL_AUTHORITY_API_KEY;
    this.verificationLinks = options.verificationLinks === true;
    this.presence = options.presence;
    this.legacyVerifyReceipt = options.verifyReceipt;
    this.policy = options.policy ?? defaultPolicy;
    this.managedApproverId = options.managedApproverId ?? "synthetic-managed-approver";
    this.trustedEffectObserverIds = options.trustedEffectObserverIds ?? [];
    this.clock = options.clock ?? Date.now;
    const keys = generateKeyPairSync("ed25519");
    this.attestationKey = {
      privateKey: keys.privateKey,
      publicJwk: keys.publicKey.export({ format: "jwk" }),
    };
  }

  /** The fixture's JWKS, as `GET /.well-known/decionis-execution-grant-jwks.json` serves it. */
  public get jwks(): { readonly keys: readonly Record<string, unknown>[] } {
    return {
      keys: [
        { ...this.attestationKey.publicJwk, kid: this.attestationKeyId, alg: "EdDSA", use: "sig" },
      ],
    };
  }

  /**
   * A compact JWS over the claim, signed the way Decionis signs one: EdDSA,
   * the grant key, the attestation type in the protected header. Built with
   * `node:crypto` alone so the fixture stays an independent implementation.
   */
  private attest(
    grant: LocalGrantRecord,
    claimValidatedAt: string,
    leaseExpiresAt: string,
  ): string {
    const encode = (value: unknown): string =>
      Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
    const now = Math.floor(this.clock() / 1_000);
    const claims: LocalClaimAttestationClaims = {
      iss: LOCAL_AUTHORITY_ISSUER,
      sub: grant.jti,
      org_id: grant.tenantId,
      dossier_id: grant.dossierId,
      decision_id: grant.decisionId,
      binding: {
        intent_hash: grant.intentHash,
        execution_payload_digest: grant.payloadDigest,
        execution_payload_canonicalization_profile: JCS_PROFILE,
        ...(grant.expectedEffectDigest === null
          ? {}
          : { expected_effect_digest: grant.expectedEffectDigest }),
        execution_nonce: grant.nonce,
        execution_correlation_id: grant.correlationId ?? "",
      },
      claim_token_digest: `sha256:${createHash("sha256")
        .update(grant.claimToken ?? "", "utf8")
        .digest("hex")}`,
      claim_validated_at: claimValidatedAt,
      jti: randomUUID(),
      iat: now,
      nbf: now,
      exp: Math.floor(Date.parse(leaseExpiresAt) / 1_000),
    };
    const header = encode({
      alg: "EdDSA",
      kid: this.attestationKeyId,
      typ: CLAIM_ATTESTATION_TYPE,
    });
    const payload = encode(claims);
    const signature = sign(
      null,
      Buffer.from(`${header}.${payload}`, "ascii"),
      this.attestationKey.privateKey,
    );
    return `${header}.${payload}.${signature.toString("base64url")}`;
  }

  /**
   * Registers the public half of a provider's receipt key, as the hosted
   * `POST /v1/execution/provider-keys` does; a test or a demo provider calls
   * it directly rather than over HTTP.
   */
  public registerProviderKey(input: {
    readonly kid: string;
    readonly issuer: string;
    readonly publicJwk: JsonWebKey;
    readonly label?: string;
  }): void {
    this.providerKeys.set(input.kid, {
      kid: input.kid,
      issuer: input.issuer,
      publicKey: createPublicKey({ key: input.publicJwk, format: "jwk" }),
      label: input.label ?? null,
    });
  }

  /**
   * Reads a receipt the way the hosted authority does: the protected header
   * names an Ed25519 key the organisation registered; the signature verifies
   * under it; the issuer is the one registered with the key and the audience
   * is this authority; and the claims describe this grant and this claim,
   * through `sub`, the decision and dossier ids and the digest of the claim
   * token being finalized. Anything else is recorded with its code, and the
   * finalization proceeds regardless.
   */
  private readEffectReceipt(
    token: string,
    grant: LocalGrantRecord,
    claimToken: string,
  ): LocalEffectReceiptRecord {
    const record = (
      code: LocalEffectReceiptCode,
      partial: Partial<LocalEffectReceiptRecord> = {},
    ): LocalEffectReceiptRecord => ({
      token,
      verified: code === "EFFECT_RECEIPT_VERIFIED",
      verification_code: code,
      provider_key_id: null,
      issuer: null,
      effect_status: null,
      effect_digest: null,
      effect_reference: null,
      effected_at: null,
      ...partial,
    });
    const [encodedHeader = "", encodedPayload = "", encodedSignature = ""] = token.split(".");
    let header: Record<string, unknown>;
    let payload: Record<string, unknown>;
    try {
      header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8"));
      payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));
    } catch {
      return record("EFFECT_RECEIPT_MALFORMED");
    }
    if (
      header.alg !== "EdDSA" ||
      header.typ !== EFFECT_RECEIPT_TYPE ||
      typeof header.kid !== "string" ||
      header.kid.length === 0
    ) {
      return record("EFFECT_RECEIPT_MALFORMED");
    }
    const key = this.providerKeys.get(header.kid);
    if (key === undefined) {
      return record("EFFECT_RECEIPT_KEY_UNKNOWN", { provider_key_id: header.kid });
    }
    const known = { provider_key_id: key.kid, issuer: key.issuer };
    const signed = Buffer.from(`${encodedHeader}.${encodedPayload}`, "ascii");
    if (
      !verify(null, signed, key.publicKey, Buffer.from(encodedSignature, "base64url")) ||
      payload.iss !== key.issuer ||
      payload.aud !== LOCAL_AUTHORITY_ISSUER
    ) {
      return record("EFFECT_RECEIPT_SIGNATURE_INVALID", known);
    }
    const effect =
      typeof payload.effect === "object" && payload.effect !== null
        ? (payload.effect as Record<string, unknown>)
        : null;
    const status = effectStatus(effect?.status);
    const digest = effect?.digest;
    const effectedAt = effect?.effected_at;
    if (
      typeof payload.sub !== "string" ||
      typeof payload.decision_id !== "string" ||
      typeof payload.dossier_id !== "string" ||
      typeof payload.claim_token_digest !== "string" ||
      typeof payload.jti !== "string" ||
      typeof payload.iat !== "number" ||
      status === null ||
      (digest !== undefined && !sha256Digest.safeParse(digest).success) ||
      typeof effectedAt !== "string" ||
      Number.isNaN(Date.parse(effectedAt))
    ) {
      return record("EFFECT_RECEIPT_MALFORMED", known);
    }
    const described = {
      ...known,
      effect_status: status,
      effect_digest: typeof digest === "string" ? digest : null,
      effect_reference: typeof effect?.reference === "string" ? effect.reference : null,
      effected_at: new Date(effectedAt).toISOString(),
    };
    const claimTokenDigest = `sha256:${createHash("sha256").update(claimToken, "utf8").digest("hex")}`;
    if (
      payload.sub !== grant.jti ||
      payload.decision_id !== grant.decisionId ||
      payload.dossier_id !== grant.dossierId ||
      payload.claim_token_digest !== claimTokenDigest ||
      (typeof payload.intent_hash === "string" && payload.intent_hash !== grant.intentHash)
    ) {
      return record("EFFECT_RECEIPT_BINDING_MISMATCH", described);
    }
    return record("EFFECT_RECEIPT_VERIFIED", described);
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
        // What the client says about itself, so a test can see the version
        // and the surface a call carried; the double never acts on it.
        "user-agent": headerString(req.headers["user-agent"]),
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
    // The verification keys are public, as Decionis's are: a provider double
    // fetches them with no credential to the authority at all.
    if (req.method === "GET" && url.pathname === LOCAL_AUTHORITY_JWKS_PATH) {
      return this.send(res, record, 200, this.jwks);
    }
    // The public lane: a workspace minted with no account, as the hosted
    // authority mints one, with this double's own key as the raw key.
    if (req.method === "POST" && url.pathname === "/v1/public/agents/provision") {
      return this.send(res, record, 201, {
        org_id: LOCAL_AUTHORITY_PROVISIONAL_ORG_ID,
        raw_key: this.apiKey,
        provisional: true,
        limits: {
          requests_per_minute: 10,
          workspaces_per_network_per_day: 5,
          governed_decisions_per_month: 50,
        },
        claim: { note: "synthetic workspace on loopback; there is nothing to claim" },
        next: {},
      });
    }
    if (req.headers.authorization !== `Bearer ${this.apiKey}`) {
      return this.send(res, record, 401, { error: "UNAUTHORIZED" });
    }
    const dossierLookup = url.pathname.match(/^\/v1\/protocol\/dossiers\/([^/]+)$/);
    if (req.method === "GET" && dossierLookup !== null) {
      const minted = this.dossiers.get(decodeURIComponent(dossierLookup[1] ?? ""));
      if (minted === undefined || url.searchParams.get("org_id") !== minted.request.tenant_id) {
        return this.send(res, record, 404, { error: "DOSSIER_NOT_FOUND" });
      }
      return this.send(res, record, 200, this.dossierRecord(minted.request, minted.decision));
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
      case "/v1/execution/provider-keys":
        return this.send(res, record, ...this.registerProviderKeyRoute(record));
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

  /** `POST /v1/execution/provider-keys`: the public half only, or a 400 naming why. */
  private registerProviderKeyRoute(record: LocalAuthorityRequestRecord): [number, unknown] {
    const parsed = ProviderKeyRegistrationSchema.safeParse(record.body);
    if (!parsed.success) return [400, { error: "INVALID_BODY" }];
    const body = parsed.data;
    this.registerProviderKey({
      kid: body.kid,
      issuer: body.issuer,
      publicJwk: { kty: body.public_jwk.kty, crv: body.public_jwk.crv, x: body.public_jwk.x },
      ...(body.label === undefined ? {} : { label: body.label }),
    });
    return [
      201,
      {
        service: "decionis",
        kid: body.kid,
        issuer: body.issuer,
        algorithm: "EdDSA",
        label: body.label ?? null,
        created_at: new Date(this.clock()).toISOString(),
        revoked_at: null,
      },
    ];
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
      return { status: 200, body: this.remember(request, this.openManaged(request, decision)) };
    }
    if (evaluation.status !== "ALLOW" || request.mode !== "ENFORCEMENT") {
      return { status: 200, body: this.remember(request, decision) };
    }
    return {
      status: 200,
      body: this.remember(request, this.grantDecision(request, decision, evaluation.approval)),
    };
  }

  /** Keeps a minted decision for its dossier route, with the envelope when links are on. */
  private remember(request: LocalAuthorityRequest, decision: Decision): Decision {
    const dossierId = decision["dossier_id"];
    if (typeof dossierId !== "string") return decision;
    const linked = this.verificationLinks
      ? {
          ...decision,
          verification: {
            verification_page_url: `${this.baseUrl}/verify/${dossierId}?sig=synthetic`,
            verification_url: `${this.baseUrl}/v1/public/decision-dossiers/${dossierId}/verify?sig=synthetic`,
            link_expires_at: new Date(this.clock() + 24 * 60 * 60 * 1_000).toISOString(),
            signature_scheme: "synthetic",
          },
        }
      : decision;
    this.dossiers.set(dossierId, { request, decision: linked });
    return linked;
  }

  /**
   * The persisted record, shaped as `GET /v1/protocol/dossiers/{id}` returns
   * it: a payload with the routing decision, the inputs and a proof bundle
   * naming this double's key. The artifacts are not signed; the record says
   * so in its issuer tier, and nothing here claims otherwise.
   */
  private dossierRecord(
    request: LocalAuthorityRequest,
    decision: Decision,
  ): Record<string, unknown> {
    const generatedAt = new Date(this.clock()).toISOString();
    return {
      service: "synthetic-authority",
      protocol_version: "synthetic",
      dossier: {
        dossier_payload: {
          schema_version: "decionis.decision_dossier/2.0",
          dossier_id: decision["dossier_id"],
          generated_at: generatedAt,
          routing_decision: {
            decision_id: decision["decision_id"],
            outcome: decision["status"],
            authority: decision["authority_classification"],
            policy_version: decision["policy_version"],
            reason_codes: decision["reason_codes"],
          },
          inputs_snapshot: {
            tenant_id: request.tenant_id,
            actor_id: request.actor.id,
            action: request.action.type,
            target: request.action.resource,
          },
          portable_artifact: { issuer_context: { tier: "synthetic_loopback" } },
          integrity: {
            proof_bundle: {
              bundle_type: "decionis.decision_dossier.proof_bundle",
              version: "2.0",
              issued_at: generatedAt,
              algorithm: "Ed25519",
              key_id: this.attestationKeyId,
              artifacts: [],
            },
          },
        },
      },
    };
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
      payloadDigest: hashBinding(request.action.parameters),
      expectedEffectDigest: request.expected_effect_digest ?? null,
      receiptDossierId: approval?.receiptDossierId ?? null,
      claimed: false,
      claimToken: null,
      receipt: null,
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
    // Unreachable while the commitment stays inside the intent hash — a
    // divergence is already an `INTENT_HASH_MISMATCH` from the independent
    // re-hash above. Kept because the hosted route checks the committed value
    // itself, and a double that only checked the hash would stop proving that.
    if ((intent.data.expected_effect_digest ?? null) !== grant.expectedEffectDigest) {
      return rejected("GRANT_BINDING_MISMATCH");
    }
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
    const claimValidatedAt = new Date(this.clock()).toISOString();
    const leaseExpiresAt = new Date(this.clock() + CLAIM_LEASE_MS).toISOString();
    // The drill knob: an authority that bound a digest over other parameters.
    // It is consumed by one claim, so the executor's refusal is the one
    // observation and the next proposal sees an honest authority again.
    const payloadDigest = this.misbindNextPayloadDigest
      ? hashBinding({ ...(intent.data.action.parameters as object), synthetic_tamper: true })
      : grant.payloadDigest;
    this.misbindNextPayloadDigest = false;
    return {
      status: 200,
      body: {
        valid: true,
        should_execute: true,
        would_block: false,
        verdict: "ALLOW",
        reason_codes: [],
        claims: {
          iss: LOCAL_AUTHORITY_ISSUER,
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
            execution_payload_digest: payloadDigest,
            execution_payload_canonicalization_profile: JCS_PROFILE,
            execution_nonce: grant.nonce,
            execution_correlation_id: grant.correlationId,
            ...(grant.expectedEffectDigest === null
              ? {}
              : { expected_effect_digest: grant.expectedEffectDigest }),
          },
          jti: grant.jti,
          iat: grant.issuedAt,
          nbf: grant.issuedAt,
          exp: grant.expiresAt,
        },
        claim_token: grant.claimToken,
        claim_validated_at: claimValidatedAt,
        claim_lease_expires_at: leaseExpiresAt,
        claim_attestation: this.attest(
          { ...grant, payloadDigest },
          claimValidatedAt,
          leaseExpiresAt,
        ),
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
    // The receipt is read first and recorded whatever it says; when the grant
    // named the effect it expected and the executor supplied no observation of
    // its own, a verified receipt with a digest stands in as SIGNED_RECEIPT
    // evidence by the provider's key, exactly as the hosted route reads it.
    const receipt =
      parsed.data.effect_receipt === undefined
        ? null
        : this.readEffectReceipt(parsed.data.effect_receipt, grant, parsed.data.claim_token);
    let supplied = parsed.data.effect_evidence;
    if (
      supplied === undefined &&
      receipt?.verified === true &&
      grant.expectedEffectDigest !== null &&
      receipt.effect_digest !== null
    ) {
      supplied = {
        version: "1.0",
        status:
          receipt.effect_status === "EFFECTED" &&
          receipt.effect_digest === grant.expectedEffectDigest &&
          parsed.data.outcome === "COMMITTED"
            ? "CONFIRMED"
            : "UNCONFIRMED",
        observation_method: "SIGNED_RECEIPT",
        observer: { id: receipt.provider_key_id, version: EFFECT_RECEIPT_TYPE },
        expected_effect_digest: grant.expectedEffectDigest,
        observed_effect_digest: receipt.effect_digest,
        observed_at: receipt.effected_at,
        evidence_digest: `sha256:${createHash("sha256").update(receipt.token, "utf8").digest("hex")}`,
        evidence_reference: receipt.effect_reference,
        execution_correlation_id: parsed.data.commit_correlation_id,
      };
    }
    // The hosted authority refuses the whole finalization for evidence it
    // cannot bind, in exactly this order, before the commit transition.
    let evidence: z.infer<typeof EffectEvidenceSchema> | undefined;
    if (supplied !== undefined) {
      const parsedEvidence = EffectEvidenceSchema.safeParse(supplied);
      if (!parsedEvidence.success) return rejected(malformedEffectEvidenceReason(supplied));
      evidence = parsedEvidence.data;
      if (evidence.execution_correlation_id !== parsed.data.commit_correlation_id) {
        return rejected("EXECUTION_CORRELATION_MISMATCH");
      }
      if (grant.expectedEffectDigest === null) {
        return rejected("EFFECT_EXPECTED_BINDING_UNAVAILABLE");
      }
      if (evidence.expected_effect_digest !== grant.expectedEffectDigest) {
        return rejected("EFFECT_EXPECTED_DIGEST_MISMATCH");
      }
      if (evidence.status === "CONFIRMED" && parsed.data.outcome !== "COMMITTED") {
        return rejected("EFFECT_EVIDENCE_OUTCOME_MISMATCH");
      }
      if (evidence.status === "CONFIRMED") {
        // A verified receipt's key is an observer for this finalization only.
        const trusted = [
          ...this.effectObserverIds(),
          ...(receipt?.verified === true && receipt.provider_key_id !== null
            ? [receipt.provider_key_id]
            : []),
        ];
        if (trusted.length === 0) {
          return rejected("EFFECT_OBSERVER_PROVENANCE_UNAVAILABLE");
        }
        if (evidence.observer === null || !trusted.includes(evidence.observer.id)) {
          return rejected("EFFECT_OBSERVER_PROVENANCE_MISMATCH");
        }
      }
    }
    grant.finalized = parsed.data.outcome;
    grant.receipt = receipt;
    // Byte-for-byte the hosted success body: the commit's own decision-chain
    // evidence is queued, not yet recorded, so a successful finalization still
    // carries `COMMIT_EVIDENCE_PENDING`.
    return {
      status: 200,
      body: {
        finalized: true,
        outcome: parsed.data.outcome,
        evidence_durably_queued: true,
        decision_chain_evidence_recorded: false,
        evidence_recorded: false,
        effect_evidence_recorded: evidence !== undefined,
        effect_confirmation: evidence?.status === "CONFIRMED" ? "CONFIRMED" : "UNCONFIRMED",
        ...(receipt === null
          ? {}
          : {
              effect_receipt: {
                verified: receipt.verified,
                verification_code: receipt.verification_code,
                provider_key_id: receipt.provider_key_id,
                recorded: true,
              },
            }),
        reason_codes: ["COMMIT_EVIDENCE_PENDING"],
      },
    };
  }

  /**
   * The hosted route never trusts the allowlist alone: it returns at most the
   * caller's own authenticated API-key identity, so a confirmed observation
   * must name the identity that presented the credential. This double has one
   * credential, so that credential is its identity.
   */
  private effectObserverIds(): readonly string[] {
    return this.trustedEffectObserverIds.includes(this.apiKey) ? [this.apiKey] : [];
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

/**
 * The hosted route maps an unparseable observation to a 409 reason code rather
 * than a request rejection, and singles out a `CONFIRMED` observation whose
 * observer version is missing, because that is a provenance failure rather than
 * a malformed body.
 */
function malformedEffectEvidenceReason(supplied: unknown): string {
  const candidate = asRecord(supplied);
  const observer = asRecord(candidate.observer);
  if (
    candidate.version === "1.0" &&
    candidate.status === "CONFIRMED" &&
    (typeof observer.version !== "string" || observer.version.trim().length === 0)
  ) {
    return "EFFECT_OBSERVER_PROVENANCE_UNAVAILABLE";
  }
  return "EFFECT_EVIDENCE_INVALID";
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

function headerString(value: string | string[] | undefined): string | null {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value[0] ?? null;
  return null;
}
