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
 * A claim re-derives authority from current state before it consumes
 * anything, as the hosted revalidator does: a policy released since the grant
 * fails `POLICY_VERSION_STALE`, a material signal published since the grant
 * fails `SIGNAL_VERSION_STALE`, and a concurrency scope another open claim
 * holds fails `AUTHORIZATION_SCOPE_BUSY` (or `CURRENT_STATE_UNRESOLVED` while
 * that claim's outcome is unknown). None of them burns the grant.
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
import { LocalAssumptionBreaches } from "./LocalAssumptionBreaches.js";
import {
  verifySignedSignals,
  type SignedSignalFacts,
  type SignedSignalKey,
  type SignedSignalRefusalCode,
} from "./SignedSignals.js";

export const LOCAL_AUTHORITY_API_KEY = "test-key";
export const AUTONOMOUS_LIMIT_MINOR = 10_000;
export const HUMAN_LIMIT_MINOR = 100_000;

const LOOPBACK_ORIGIN = "http://127.0.0.1";
const MAX_REQUEST_BYTES = 256 * 1024;
const MAX_RECORDED_BODY_CHARS = 4_096;
const SOCKET_TIMEOUT_MS = 10_000;
const GRANT_TTL_MS = 60_000;
const CLAIM_LEASE_MS = 30_000;

/**
 * `ExecutionTargetPrecondition`, the contract's, written here again rather
 * than imported, so the fixture checks the package's precondition with an
 * independent reading: what a runtime states in `context.agent_safe` about
 * the target's state before asking.
 */
const TargetPreconditionContract = z
  .object({
    version: z.string().regex(/^[\x21-\x7e]{1,256}$/),
    state: z
      .string()
      .min(1)
      .max(200)
      .regex(/^\P{Cc}+$/u)
      .optional(),
    source: z
      .string()
      .min(1)
      .max(200)
      .regex(/^[a-z0-9][\w.:/#-]*$/i),
    read_at: z.string().datetime(),
  })
  .strict();

/**
 * The precondition an intent's context states: the parsed contract, null when
 * it states none, or `undefined` when it states one the contract refuses.
 */
function preconditionIn(
  context: Record<string, unknown>,
): z.infer<typeof TargetPreconditionContract> | null | undefined {
  const namespace = context["agent_safe"];
  if (namespace === null || typeof namespace !== "object" || Array.isArray(namespace)) return null;
  const raw = (namespace as Record<string, unknown>)["precondition"];
  if (raw === undefined) return null;
  const parsed = TargetPreconditionContract.safeParse(raw);
  return parsed.success ? parsed.data : undefined;
}
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
  policy_projection: z
    .strictObject({
      decision_type: z.string().trim().min(1).max(120),
      transaction_type: z.string().trim().min(1).max(120).nullable(),
      workflow_key: z.string().trim().min(1).max(120).nullable(),
      channel: z.string().trim().min(1).max(120).nullable(),
    })
    .optional(),
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

/**
 * `enforce-and-bind` evidence: a Presence receipt reference, or a presence
 * provider's signed attestation (`AttestedHumanApprovalEvidence`). The claim
 * route keeps the Presence shape only, as the contract does.
 */
const AuthorityEvidenceSchema = z.strictObject({
  humanApproval: z
    .discriminatedUnion("provider", [
      z.strictObject({
        provider: z.literal("presence"),
        requestId: boundedId,
        receiptDossierId: boundedId,
      }),
      z.strictObject({
        provider: z.literal("attestation"),
        attestation: z.string().max(20_000).regex(COMPACT_JWS),
      }),
    ])
    .optional(),
  /** A producer's signed standing signals (`SignedSignalEvidence`), at most eight. */
  signals: z
    .array(z.strictObject({ token: z.string().max(20_000).regex(COMPACT_JWS) }))
    .min(1)
    .max(8)
    .optional(),
});

/** `ExecutionAuthorityRequest`: the binding plus hash, mode, evidence, and managed constraints. */
const AuthorityRequestSchema = z.strictObject({
  ...IntentBindingSchema.shape,
  intent_hash: sha256Digest,
  mode: z.enum(["SHADOW", "ENFORCEMENT"]),
  evidence: AuthorityEvidenceSchema.optional(),
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

const ReconcileRequestSchema = z.strictObject({
  execution_token: z.string().min(1).max(20_000),
  claim_token: z.string().regex(/^[\w-]{43,128}$/),
  commit_correlation_id: boundedId,
  outcome: z.enum(["COMMITTED", "FAILED"]),
  reconciliation_note: z.string().min(1).max(2_000).optional(),
  downstream_evidence: z.record(z.string(), z.unknown()).optional(),
  effect_evidence: z.unknown().optional(),
});

/** What a registered key may sign, as the hosted `ExecutionProviderKeyPurpose` names it. */
export const PROVIDER_KEY_PURPOSES = [
  "effect_receipt",
  "presence_attestation",
  "usage_report",
  "signed_signal",
] as const;
export type LocalProviderKeyPurpose = (typeof PROVIDER_KEY_PURPOSES)[number];

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
  purpose: z.enum(PROVIDER_KEY_PURPOSES).optional(),
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

/**
 * What a policy hook sees: the request; the facts of every signed signal it
 * carried, verified, under `signed_signals` by name, as the hosted authority
 * writes them under `agent_safe.signed_signals`; and the current value of
 * every published material signal the request names, under
 * `material_signals` by id, as the hosted policy reads them.
 */
export type LocalAuthorityPolicyInput = LocalAuthorityRequest & {
  readonly signed_signals?: Readonly<Record<string, SignedSignalFacts>>;
  readonly material_signals?: Readonly<Record<string, unknown>>;
};
export type LocalAuthorityPolicy = (request: LocalAuthorityPolicyInput) => Verdict;

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
  /** The target's version the intent's precondition stated; null when it stated none. */
  readonly expectedStateVersion: string | null;
  /** Present for direct grants issued on client-supplied evidence; null for managed grants. */
  readonly receiptDossierId: string | null;
  /** The policy release the grant was decided under. */
  readonly policyVersion: string;
  /** The material signals the decision rested on, at the versions it read them. */
  readonly materialSignals: readonly LocalMaterialSignal[];
  /** The concurrency scopes a claim of this grant holds until its outcome is known. */
  readonly scopes: readonly string[];
  claimed: boolean;
  claimToken: string | null;
  correlationId: string | null;
  consumedBy: string | null;
  finalized: "COMMITTED" | "FAILED" | "INDETERMINATE" | null;
  /** The provider's effect receipt as this authority read it at finalization, when one came. */
  receipt: LocalEffectReceiptRecord | null;
}

/**
 * A material signal as the authority last ingested it, in the shape of the
 * hosted `MaterialSignalReference`. Every ingestion is a new version here.
 */
export interface LocalMaterialSignal {
  readonly signal_id: string;
  readonly version: string;
  readonly observed_at: string;
  readonly value_digest: string;
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

/**
 * One draw on a held allowance, as the approving hosted rule names it in
 * `then.allowance` and the binding signs it in `allowance_draws`. `amount` is
 * null when the rule reads it from parameters that give no whole number.
 */
export interface LocalAllowanceDraw {
  readonly allowance_key: string;
  readonly amount: number | null;
}

/** What an allowance holds now, as hosted `GET /v1/authority/allowances/{key}` reports it. */
export interface LocalAllowanceUsage {
  readonly reserved: number;
  readonly held: number;
  readonly consumed: number;
  readonly available: number;
}

/** A verifying provider's registered receipt key: the public half, its `kid`, the `iss` it signs as. */
export interface LocalProviderKey {
  readonly kid: string;
  readonly issuer: string;
  readonly publicKey: KeyObject;
  readonly label: string | null;
  readonly purpose: LocalProviderKeyPurpose;
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
  /**
   * Stands in for the authority's verification of a presence attestation
   * (signature under the provider's registered key, audience, expiry, intent
   * binding). Absent, every attestation is refused as the hosted route
   * refuses one it cannot verify, with `PRESENCE_ATTESTATION_SIGNATURE_INVALID`.
   */
  readonly verifyAttestation?: (
    attestation: string,
    binding: { readonly intentId: string; readonly intentHash: string; readonly tenantId: string },
  ) => boolean;
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
  /**
   * The material signals a request's decision rests on, by id, as a hosted
   * policy names them. Their current values reach the policy hook under
   * `material_signals`; the versions are bound into the grant, and a claim
   * made after any of them was published again fails `SIGNAL_VERSION_STALE`.
   * Each one is also a concurrency scope, as the hosted claim store derives
   * them. Hosted, a grant that binds none holds its execution target as its
   * scope; here it holds no scope at all.
   */
  readonly materialSignals?: (request: LocalAuthorityRequest) => readonly string[];
  /**
   * Further API keys, each bound to the one organisation it was issued for,
   * as every hosted key is. A request a bound key authenticates must name
   * that organisation, or enforce-and-bind answers 403
   * `AUTHORITY_TENANT_MISMATCH` and a claim 403 `TENANT_MISMATCH`, so a grant
   * cannot be carried into another organisation. `apiKey` stays unbound.
   */
  readonly tenantKeys?: Readonly<Record<string, string>>;
  /**
   * Mint each execution token in the hosted shape, a compact JWT whose `jti`
   * is the grant's UUID (unsigned here), so a client addresses the grant's
   * own resources, `/v1/authority/grants/{grantId}/…`, as it does in
   * production: the reconciliations resource has no legacy alias and is
   * reachable no other way. Off by default, which keeps the opaque tokens
   * and the legacy verb routes earlier tests were written against.
   */
  readonly addressableGrants?: boolean;
  readonly clock?: () => number;
  /**
   * Attach a verification envelope to every decision, as the hosted
   * `evaluate-decision` does and `enforce-and-bind` may: a page URL under
   * this double's own origin, so a test can see the link travel end to end.
   */
  readonly verificationLinks?: boolean;
  /**
   * Where every ESCALATE goes, as the hosted authority reads it from the
   * policy and attaches it to the decision as `escalation_requirement`: the
   * selector (kind and role) and who proves the person. A test names a
   * third-party provider here to see a hold routed to a cardholder's tap.
   */
  readonly escalationRouting?: {
    readonly selector?: { readonly kind: "ROLE" | "PRINCIPAL"; readonly role_id?: string } | null;
    readonly verification: {
      readonly provider: string;
      readonly methods: readonly string[];
      readonly level: "STANDARD" | "HIGH_CONFIDENCE";
    };
  };
  /**
   * The held allowances an approval draws on, as the approving hosted rule
   * names them in `then.allowance`. An ALLOW is granted only once every draw
   * fits what its allowance has left; otherwise the decision is `BLOCK` with
   * `ALLOWANCE_EXHAUSTED`, `ALLOWANCE_UNDEFINED` (no `setAllowance` for the
   * key) or `ALLOWANCE_AMOUNT_INVALID`, and no grant is issued. A draw counts
   * from the grant to the outcome: an unclaimed grant holds it until it
   * expires, a commit keeps it, a failure releases it, and an INDETERMINATE
   * holds it until reconciled. A counter, never a concurrency scope. Here an
   * allowance has no window and serves every tenant alike.
   */
  readonly allowanceDraws?: (request: LocalAuthorityRequest) => readonly LocalAllowanceDraw[];
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
    /** The target's version the grant was decided against, when the intent stated one. */
    readonly expected_state_version?: string;
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
  private readonly verifyAttestation: LocalAuthorityOptions["verifyAttestation"];
  private policy: LocalAuthorityPolicy;
  /** How many policy releases are active or behind; the first is `synthetic-policy-v1`. */
  private policyReleases = 1;
  /** Every material signal ingested, by id: the reference and the value it carries. */
  private readonly signals = new Map<
    string,
    { readonly reference: LocalMaterialSignal; readonly value: unknown }
  >();
  private readonly materialSignalsOf: (request: LocalAuthorityRequest) => readonly string[];
  private readonly tenantKeys: Readonly<Record<string, string>>;
  private readonly addressableGrants: boolean;
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
  /**
   * The hosted assumption breaches: a finalization whose receipt or
   * observation contradicts its grant holds the grant's scope, and
   * `assumptionBreaches.clear(citations)` is the governed release or
   * recovery review that cites it.
   */
  public readonly assumptionBreaches = new LocalAssumptionBreaches();
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
  private readonly escalationRouting: LocalAuthorityOptions["escalationRouting"];
  private server: Server | null = null;
  private port = 0;
  private readonly allowanceDrawsOf: (
    request: LocalAuthorityRequest,
  ) => readonly LocalAllowanceDraw[];
  /** Each allowance's limit, by key, as the policy writer last set it. */
  private readonly allowanceLimits = new Map<string, number>();
  /** What each issued grant drew, by jti. */
  private readonly grantDraws = new Map<string, readonly LocalAllowanceDraw[]>();

  public constructor(options: LocalAuthorityOptions = {}) {
    if (process.env.NODE_ENV === "production") throw new Error("LOCAL_DOUBLE_FORBIDDEN");
    this.apiKey = options.apiKey ?? LOCAL_AUTHORITY_API_KEY;
    this.verificationLinks = options.verificationLinks === true;
    this.escalationRouting = options.escalationRouting;
    this.presence = options.presence;
    this.legacyVerifyReceipt = options.verifyReceipt;
    this.verifyAttestation = options.verifyAttestation;
    this.policy = options.policy ?? defaultPolicy;
    this.materialSignalsOf = options.materialSignals ?? (() => []);
    this.tenantKeys = options.tenantKeys ?? {};
    this.addressableGrants = options.addressableGrants === true;
    this.managedApproverId = options.managedApproverId ?? "synthetic-managed-approver";
    this.trustedEffectObserverIds = options.trustedEffectObserverIds ?? [];
    this.clock = options.clock ?? Date.now;
    const keys = generateKeyPairSync("ed25519");
    this.attestationKey = {
      privateKey: keys.privateKey,
      publicJwk: keys.publicKey.export({ format: "jwk" }),
    };
    this.allowanceDrawsOf = options.allowanceDraws ?? (() => []);
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
        ...(grant.expectedStateVersion === null
          ? {}
          : { expected_state_version: grant.expectedStateVersion }),
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
    /** What the key may sign; a receipt key by default, as the hosted route defaults. */
    readonly purpose?: LocalProviderKeyPurpose;
  }): void {
    this.providerKeys.set(input.kid, {
      kid: input.kid,
      issuer: input.issuer,
      publicKey: createPublicKey({ key: input.publicJwk, format: "jwk" }),
      label: input.label ?? null,
      purpose: input.purpose ?? "effect_receipt",
    });
  }

  /** The policy release decisions are made under now, as `policy_version` names it. */
  public get policyVersion(): string {
    return `synthetic-policy-v${this.policyReleases}`;
  }

  /**
   * Activates the next policy release, with a new policy hook or the same
   * one: the governance authority's own act, which no API key can perform
   * here or hosted. Every grant decided under an earlier release then fails
   * at claim with `POLICY_VERSION_STALE`, and a new decision is made under
   * this one. Returns the release now active.
   */
  public releasePolicy(policy?: LocalAuthorityPolicy): string {
    if (policy !== undefined) this.policy = policy;
    this.policyReleases += 1;
    return this.policyVersion;
  }

  /**
   * Ingests a material signal's current value, as the hosted
   * `POST /v1/protocol/signals/envelopes` does for a system of record. Each
   * call is a new version, so a grant that read an earlier one fails at
   * claim with `SIGNAL_VERSION_STALE`.
   */
  public publishSignal(signalId: string, value: unknown): LocalMaterialSignal {
    const reference: LocalMaterialSignal = {
      signal_id: signalId,
      version: String(Number(this.signals.get(signalId)?.reference.version ?? 0) + 1),
      observed_at: new Date(this.clock()).toISOString(),
      value_digest: hashBinding(value),
    };
    this.signals.set(signalId, { reference, value });
    return reference;
  }

  /** The published material signals a request names, in id order. */
  private materialSignalsFor(request: LocalAuthorityRequest): {
    readonly references: readonly LocalMaterialSignal[];
    readonly values: Readonly<Record<string, unknown>>;
  } {
    const ids = [...new Set(this.materialSignalsOf(request))].sort();
    const published = ids.flatMap((id) => {
      const signal = this.signals.get(id);
      return signal === undefined ? [] : [signal];
    });
    return {
      references: published.map((signal) => signal.reference),
      values: Object.fromEntries(
        published.map((signal) => [signal.reference.signal_id, signal.value]),
      ),
    };
  }

  /** The key a signed signal's `kid` names, when it was registered to sign signals. */
  private signedSignalKey(kid: string): SignedSignalKey | null {
    const key = this.providerKeys.get(kid);
    return key !== undefined && key.purpose === "signed_signal"
      ? { kid: key.kid, issuer: key.issuer, publicKey: key.publicKey }
      : null;
  }

  /**
   * The signed signals a request carries, verified as the hosted authority
   * verifies them, as facts by name for the policy hook; a refusal names its
   * code, and the route answers it with a 409 like a refused attestation.
   */
  private signedSignalsOf(
    request: LocalAuthorityRequest,
  ):
    | { readonly facts: Readonly<Record<string, SignedSignalFacts>> | undefined }
    | { readonly refused: SignedSignalRefusalCode } {
    const signals = request.evidence?.signals;
    if (signals === undefined) return { facts: undefined };
    const verification = verifySignedSignals(
      signals.map((signal) => signal.token),
      {
        orgId: request.tenant_id,
        findKey: (kid) => this.signedSignalKey(kid),
        intent: {
          action: request.action.type,
          actorId: request.actor.id,
          resource: request.action.resource,
          parameters: request.action.parameters as Readonly<Record<string, unknown>>,
        },
        nowMs: this.clock(),
      },
    );
    return verification.ok ? { facts: verification.facts } : { refused: verification.code };
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

  /**
   * Defines an allowance, or changes its limit: the policy writer's act
   * (hosted, `PUT /v1/authority/allowances/{key}` with `policy:write`), which
   * no decision key can perform here or hosted. Raising it is a top-up.
   */
  public setAllowance(key: string, limit: number): void {
    if (!Number.isSafeInteger(limit) || limit < 0) throw new Error("ALLOWANCE_LIMIT_INVALID");
    this.allowanceLimits.set(key, limit);
  }

  /** What an allowance holds now; null for a key no allowance is defined under. */
  public allowanceUsage(key: string): LocalAllowanceUsage | null {
    const limit = this.allowanceLimits.get(key);
    if (limit === undefined) return null;
    let reserved = 0;
    let held = 0;
    let consumed = 0;
    for (const grant of this.grants.values()) {
      for (const draw of this.grantDraws.get(grant.jti) ?? []) {
        if (draw.allowance_key !== key || draw.amount === null) continue;
        if (!grant.claimed) {
          if (grant.expiresAt * 1_000 > this.clock()) reserved += draw.amount;
        } else if (grant.finalized === "COMMITTED") {
          consumed += draw.amount;
        } else if (grant.finalized !== "FAILED") {
          held += draw.amount;
        }
      }
    }
    return { reserved, held, consumed, available: Math.max(0, limit - reserved - held - consumed) };
  }

  /**
   * An ALLOW's grant, once its draws are reserved, as hosted reserves them
   * with the grant; or the same decision as `BLOCK` with the refusal code and
   * no grant. Never ESCALATE: no approval creates capacity.
   */
  private grantWithinAllowances(
    request: LocalAuthorityRequest,
    decision: Decision,
    approval: { readonly requestId: string; readonly receiptDossierId: string } | null,
  ): Decision {
    const draws = this.allowanceDrawsOf(request);
    const refused =
      draws.find((draw) => draw.amount === null) !== undefined
        ? "ALLOWANCE_AMOUNT_INVALID"
        : draws.some((draw) => this.allowanceUsage(draw.allowance_key) === null)
          ? "ALLOWANCE_UNDEFINED"
          : draws.some((draw) => draw.amount! > this.allowanceUsage(draw.allowance_key)!.available)
            ? "ALLOWANCE_EXHAUSTED"
            : null;
    if (refused !== null) {
      const reasons = Array.isArray(decision.reason_codes) ? decision.reason_codes : [];
      return { ...decision, status: "BLOCK", reason_codes: [...reasons, refused] };
    }
    const granted = this.grantDecision(request, decision, approval);
    if (draws.length > 0) this.grantDraws.set(String(granted.execution_token_jti), draws);
    return granted;
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
    // The policy lifecycle takes an account session, never an API key, as the
    // hosted contract says: no key, an agent's or an executor's or this
    // double's own, can propose, accept or release a policy. This double
    // holds no account sessions at all; `releasePolicy` is the only way in.
    if (url.pathname === "/v1/policies" || url.pathname.startsWith("/v1/policies/")) {
      return this.send(res, record, 401, { error: "ACCOUNT_SESSION_REQUIRED" });
    }
    if (req.headers.authorization !== `Bearer ${this.apiKey}` && this.tenantOf(record) === null) {
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

    // The grant's REST resources, as the hosted authority serves them: the
    // path names the grant by its id, which must be the presented token's.
    const grantResource = url.pathname.match(
      /^\/v1\/authority\/grants\/([^/]+)\/(claims|receipts|reconciliations)$/,
    );
    if (grantResource !== null) {
      const mismatch = this.grantIdMismatch(record, decodeURIComponent(grantResource[1] ?? ""));
      if (mismatch !== null) return this.send(res, record, 409, mismatch);
      if (grantResource[2] === "claims") {
        return this.respond(res, record, "claim", this.claim(record));
      }
      if (grantResource[2] === "receipts") {
        return this.respond(res, record, "finalize", this.finalize(record));
      }
      return this.send(res, record, ...this.reconcile(record));
    }

    switch (url.pathname) {
      case "/v1/execution/provider-keys":
        return this.send(res, record, ...this.registerProviderKeyRoute(record));
      case "/v1/authority/grants":
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

  /** The organisation a request's key is bound to, or null for the unbound `apiKey` or no key. */
  private tenantOf(record: LocalAuthorityRequestRecord): string | null {
    const presented = record.headers.authorization?.match(/^Bearer (.+)$/)?.[1];
    return presented !== undefined && Object.hasOwn(this.tenantKeys, presented)
      ? (this.tenantKeys[presented] ?? null)
      : null;
  }

  /** A grant resource addressed by an id that is not the presented token's grant: refused, as hosted. */
  private grantIdMismatch(
    record: LocalAuthorityRequestRecord,
    grantId: string,
  ): { readonly valid: false; readonly reason_codes: readonly string[] } | null {
    const token = (record.body as { readonly execution_token?: unknown } | null)?.execution_token;
    const grant = typeof token === "string" ? this.grants.get(token) : undefined;
    if (grant === undefined || grant.jti === grantId) return null;
    return { valid: false, reason_codes: ["GRANT_ID_MISMATCH"] };
  }

  /**
   * `POST /v1/authority/grants/{grantId}/reconciliations`: how an attempt
   * finalized `INDETERMINATE` resolved, from the executor that claimed it.
   * Recorded once; the grant is never reopened.
   */
  private reconcile(record: LocalAuthorityRequestRecord): [number, unknown] {
    const parsed = ReconcileRequestSchema.safeParse(record.body);
    if (!parsed.success) return [400, { error: "REQUEST_INVALID" }];
    const refused = (reasonCode: string): [number, unknown] => [
      409,
      { reconciled: false, reason_codes: [reasonCode] },
    ];
    const grant = this.grants.get(parsed.data.execution_token);
    if (grant === undefined) return refused("GRANT_INVALID");
    if (!grant.claimed || grant.claimToken !== parsed.data.claim_token) {
      return refused("NONCE_REPLAY_DETECTED");
    }
    if (grant.correlationId !== parsed.data.commit_correlation_id) {
      return refused("EXECUTION_CORRELATION_MISMATCH");
    }
    if (grant.finalized !== "INDETERMINATE") return refused("EXECUTION_NOT_INDETERMINATE");
    grant.finalized = parsed.data.outcome;
    return [
      200,
      {
        reconciled: true,
        resolution: parsed.data.outcome === "COMMITTED" ? "FINALIZED" : "FAILED",
        reason_codes: [],
      },
    ];
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
      ...(body.purpose === undefined ? {} : { purpose: body.purpose }),
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
    const tenant = this.tenantOf(record);
    if (tenant !== null && tenant !== request.tenant_id) {
      return { status: 403, body: { error: "AUTHORITY_TENANT_MISMATCH" } };
    }
    if (record.headers["idempotency-key"] !== request.intent_id) {
      return { status: 400, body: { error: "IDEMPOTENCY_KEY_MISMATCH" } };
    }
    const bindingError = this.assertBinding(request, record);
    if (bindingError !== null) return { status: 400, body: { error: bindingError } };

    const evaluation = this.heldByBreach(request, this.evaluate(request));
    if (evaluation.error !== undefined) return { status: 409, body: { error: evaluation.error } };

    this.decisions += 1;
    const decision = this.baseDecision(request, evaluation.status, [evaluation.reasonCode]);
    if (evaluation.status === "ESCALATE" && request.escalation?.mode === "MANAGED") {
      return { status: 200, body: this.remember(request, this.openManaged(request, decision)) };
    }
    if (evaluation.status !== "ALLOW" || request.mode !== "ENFORCEMENT") {
      return { status: 200, body: this.remember(request, decision) };
    }
    const granted = this.grantWithinAllowances(request, decision, evaluation.approval);
    // Only a grant has a scope to hold: a refusal for want of an allowance has no token.
    const token = granted.execution_token;
    if (typeof token === "string") {
      this.assumptionBreaches.granted(
        token,
        LocalAssumptionBreaches.scopeOf(request),
        evaluation.reasonCode === "POLICY_AUTONOMOUS_LIMIT",
      );
    }
    return { status: 200, body: this.remember(request, granted) };
  }

  /**
   * The starter policy's assumption-breach rule: an ALLOW the policy gave on
   * its own becomes ESCALATE while a breach holds the scope. A person's
   * approval is that person's decision, and stands.
   */
  private heldByBreach(
    request: LocalAuthorityRequest,
    evaluation: ReturnType<LocalAuthority["evaluate"]>,
  ): ReturnType<LocalAuthority["evaluate"]> {
    if (evaluation.reasonCode !== "POLICY_AUTONOMOUS_LIMIT") return evaluation;
    if (this.assumptionBreaches.openIn(LocalAssumptionBreaches.scopeOf(request)).length === 0) {
      return evaluation;
    }
    return { status: "ESCALATE", reasonCode: "ASSUMPTION_BREACH_OPEN", approval: null };
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
    const signed = this.signedSignalsOf(request);
    if ("refused" in signed) {
      return { status: "BLOCK", reasonCode: signed.refused, approval: null, error: signed.refused };
    }
    const verdict = this.policy(this.policyInput(request, signed.facts));
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
    if (humanApproval.provider === "attestation") {
      const verified =
        this.verifyAttestation?.(humanApproval.attestation, {
          intentId: request.intent_id,
          intentHash: request.intent_hash,
          tenantId: request.tenant_id,
        }) ?? false;
      return verified
        ? { status: "ALLOW", reasonCode: "PRESENCE_ATTESTATION_VERIFIED", approval: null }
        : {
            status: "BLOCK",
            reasonCode: "PRESENCE_ATTESTATION_SIGNATURE_INVALID",
            approval: null,
            error: "PRESENCE_ATTESTATION_SIGNATURE_INVALID",
          };
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

  /** The request as the policy hook reads it, with the signals that reach it. */
  private policyInput(
    request: LocalAuthorityRequest,
    signedFacts: Readonly<Record<string, SignedSignalFacts>> | undefined,
  ): LocalAuthorityPolicyInput {
    const material = this.materialSignalsFor(request).values;
    return {
      ...request,
      ...(signedFacts === undefined ? {} : { signed_signals: signedFacts }),
      ...(Object.keys(material).length === 0 ? {} : { material_signals: material }),
    };
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
      policy_version: this.policyVersion,
      mode: request.mode,
      execution_token: null,
      execution_token_expires_at: null,
      dossier_id: dossierId,
      dossier_sha256: `sha256:${createHash("sha256").update(dossierId).digest("hex")}`,
      dossier_url: `/v1/protocol/dossiers/${dossierId}`,
      approval_request_id: status === "ESCALATE" ? `synthetic-approval-${sequence}` : null,
      ...(status === "ESCALATE" && this.escalationRouting !== undefined
        ? {
            escalation_requirement: {
              requirement_id: null,
              expires_at: request.expires_at,
              selector: this.escalationRouting.selector ?? null,
              verification: {
                provider: this.escalationRouting.verification.provider,
                methods: [...this.escalationRouting.verification.methods],
                level: this.escalationRouting.verification.level,
              },
            },
          }
        : {}),
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
    const jti = this.addressableGrants ? randomUUID() : `synthetic-jti-${randomUUID()}`;
    const encode = (value: unknown): string =>
      Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
    const token = this.addressableGrants
      ? `${encode({ alg: "none", typ: "synthetic-grant" })}.${encode({ jti, org_id: request.tenant_id })}.unsigned`
      : `synthetic-grant.${jti}`;
    const bindingDigest = `sha256:${createHash("sha256").update(request.intent_hash).digest("hex")}`;
    const materialSignals = this.materialSignalsFor(request).references;
    // The hosted claim store's conflict domains, one per material signal the
    // grant binds. Hosted, a grant that binds none holds its execution target
    // instead; this double does not, so that flows written before it modelled
    // scopes, such as two open card claims on one card, keep their behaviour.
    const scopes = materialSignals.map((signal) => `signal:${signal.signal_id}`);
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
      expectedStateVersion: preconditionIn(request.context)?.version ?? null,
      receiptDossierId: approval?.receiptDossierId ?? null,
      policyVersion: this.policyVersion,
      materialSignals,
      scopes,
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
        managed.finalDecision = this.grantWithinAllowances(
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
    // A reauthorization whose allowance cannot be reserved ends BLOCKED, as hosted.
    const refused = decision?.status === "BLOCK" ? decision : null;
    return {
      status: 200,
      body: {
        escalation_id: managed.escalationId,
        intent_id: managed.request.intent_id,
        action_hash: managed.request.intent_hash,
        status: refused === null ? state.status : "BLOCKED",
        outcome: refused === null ? outcome : "BLOCK",
        expires_at: managed.request.expires_at,
        reason_codes:
          refused === null
            ? state.reasonCodes
            : [...(refused.reason_codes as string[]), "REAUTHORIZATION_BLOCKED"],
        decision: refused === null ? decision : null,
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
    const signed = this.signedSignalsOf(managed.request);
    const reevaluated = this.policy(
      this.policyInput(managed.request, "refused" in signed ? undefined : signed.facts),
    );
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
    const tenant = this.tenantOf(record);
    if (tenant !== null && tenant !== intent.data.tenant_id)
      return rejected("TENANT_MISMATCH", 403);
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
    // Authority is re-derived from current state before anything is claimed,
    // in the hosted order, so a stale grant never burns its nonce: the policy
    // release first, then every material signal the decision read.
    if (grant.policyVersion !== this.policyVersion) return rejected("POLICY_VERSION_STALE");
    if (
      grant.materialSignals.some(
        (bound) => this.signals.get(bound.signal_id)?.reference.version !== bound.version,
      )
    ) {
      return rejected("SIGNAL_VERSION_STALE");
    }
    // A breach opened since the grant was issued: the policy re-run no longer
    // approves it, after the release and the signals, as the hosted claim orders it.
    if (this.assumptionBreaches.holdsClaim(parsed.data.execution_token)) {
      return rejected("POLICY_STATE_CHANGED");
    }
    if (grant.claimed) return rejected("NONCE_REPLAY_DETECTED");
    // A scope is held from the claim until the outcome is known: a commit or
    // a failure releases it, an INDETERMINATE keeps it until reconciled.
    const holders = [...this.grants.values()].filter(
      (other) =>
        other.claimed &&
        other.tenantId === grant.tenantId &&
        (other.finalized === null || other.finalized === "INDETERMINATE") &&
        other.scopes.some((scope) => grant.scopes.includes(scope)),
    );
    if (holders.some((other) => other.finalized === "INDETERMINATE")) {
      return rejected("CURRENT_STATE_UNRESOLVED");
    }
    if (holders.length > 0) return rejected("AUTHORIZATION_SCOPE_BUSY");

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
            ...(grant.expectedStateVersion === null
              ? {}
              : { expected_state_version: grant.expectedStateVersion }),
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
    const assumptionBreach = this.assumptionBreaches.finalized({
      token: parsed.data.execution_token,
      grantJti: grant.jti,
      dossierId: grant.dossierId,
      outcome: parsed.data.outcome,
      expectedEffectDigest: grant.expectedEffectDigest,
      observedEffectDigest: evidence?.observed_effect_digest ?? null,
      evidenceDigest: evidence?.evidence_digest ?? null,
      receipt,
    });
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
        ...(assumptionBreach === null ? {} : { assumption_breach: assumptionBreach }),
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
    if (preconditionIn(request.context) === undefined) return "INTENT_PRECONDITION_INVALID";
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
