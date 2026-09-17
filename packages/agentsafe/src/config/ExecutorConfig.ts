import { z } from "zod";
import type { PresenceVerificationRequirements } from "@decionis/agent-safe-pipeline";
import { INSPECTED_ENVIRONMENT, type PostureConfig } from "../posture/PostureChecks.js";
import type { PrivateKeyJwtAlgorithm } from "../credential/PrivateKeyJwtCredential.js";
import type { SignedRequestAlgorithm } from "../credential/SignedRequestCredential.js";
import type { TlsMinVersion } from "../http/TlsListener.js";
import { RateLimiter, type LockoutRule, type RateLimitRule } from "../identity/RateLimiter.js";
import { HardLimits, type HardLimitSettings } from "../limits/HardLimits.js";
import type { PostureMode } from "../posture/HostPosture.js";
import { SecretError, type SecretName } from "../secrets/SecretStore.js";

export type ExecutorMode = "SHADOW" | "ENFORCEMENT";
export type EscalationMode = "NONE" | "DIRECT" | "MANAGED";
export type VerificationMethod = "WEBAUTHN" | "ACTIVE_LIVENESS";
export type VerificationLevel = "STANDARD" | "HIGH_CONFIDENCE";

/**
 * How this process proves itself to the downstream. A static header value
 * from the secret store; an OAuth 2.0 client-credentials token obtained with
 * a `private_key_jwt` assertion; or an RFC 9421 signature over each request.
 * The secret each kind needs is named by the kind, never by the caller.
 */
export type DownstreamCredentialConfig =
  | { readonly kind: "STATIC_HEADER"; readonly header: string }
  | {
      readonly kind: "PRIVATE_KEY_JWT";
      readonly tokenUrl: string;
      readonly clientId: string;
      readonly keyId: string | null;
      readonly algorithm: PrivateKeyJwtAlgorithm;
      readonly audience: string | null;
      readonly scope: string | null;
    }
  | {
      readonly kind: "SIGNED_REQUEST";
      readonly algorithm: SignedRequestAlgorithm;
      readonly keyId: string;
    };

export interface DownstreamConfig {
  readonly url: string;
  /** Read-only lookup for reconciliation; `{idempotency_key}` is substituted. */
  readonly lookupUrl: string | null;
  readonly system: string;
  readonly operation: string;
  readonly environment: string;
  readonly credential: DownstreamCredentialConfig;
  /** The header names whose values the redactor treats as credentials. */
  readonly redactedHeaders: readonly string[];
  readonly timeoutMs: number;
}

/** Who may call: the principals file, or the one legacy caller the configuration names. */
export interface IdentityConfig {
  readonly principalsFile: string | null;
  readonly allowLegacyCaller: boolean;
  /** The legacy caller's tenant and actor; null when a principals file names the callers. */
  readonly legacy: {
    readonly tenantId: string;
    readonly actor: { readonly id: string; readonly type: string; readonly runtime?: string };
  } | null;
  readonly jwt: {
    readonly audience: string;
    readonly jwksFile: string;
    readonly jwksUrl: string | null;
    readonly jwksCaFile: string | null;
    readonly refreshSeconds: number;
    readonly clockToleranceSeconds: number;
  } | null;
  readonly unauthenticated: RateLimitRule;
  readonly lockout: LockoutRule | null;
}

/**
 * How an `ESCALATE` is resolved. `NONE` returns the hold and stops. `DIRECT`
 * has this process open the Presence request and hold the Presence
 * credential; the receipt goes back to the authority for a fresh decision.
 * `MANAGED` asks the authority to orchestrate Presence and polls the
 * authority only; no Presence credential exists here.
 */
export type EscalationConfig =
  | { readonly mode: "NONE" }
  | {
      readonly mode: "DIRECT";
      readonly presence: {
        readonly baseUrl: string;
        readonly organization: string;
      };
      readonly approverId: string;
      readonly requirements: PresenceVerificationRequirements;
    }
  | {
      readonly mode: "MANAGED";
      readonly approverId: string;
      readonly approverRole: string | null;
      readonly requirements: {
        readonly methods: readonly VerificationMethod[];
        readonly level: VerificationLevel;
      };
    };

/** What the posture verifies, and how: declared by the deployment, never defaulted to lenient. */
export interface PostureSettings extends PostureConfig {
  readonly mode: PostureMode;
  readonly intervalSeconds: number;
}

/** How the listener presents itself: TLS with the given material, or plaintext outside production only. */
export interface ListenerConfig {
  readonly tls: {
    readonly certFile: string;
    /** When set, every connection is asked for a client certificate and non-public routes require one. */
    readonly clientCaFile: string | null;
    readonly minVersion: TlsMinVersion;
  } | null;
}

/** How a destination is trusted beyond the platform's own store: a CA bundle, SPKI pins, or neither. */
export interface TrustAnchor {
  readonly caFile: string | null;
  /** `sha256/<base64>` over the DER SubjectPublicKeyInfo; empty, or at least two. */
  readonly pins: readonly string[];
}

export interface EgressConfig {
  readonly maxResponseBytes: number;
  readonly trust: {
    readonly authority: TrustAnchor;
    readonly presence: TrustAnchor;
    readonly downstream: TrustAnchor;
  };
}

/** Where the chain heads and the attempt journal are kept, and how much is kept. */
export interface EvidenceConfig {
  readonly journalDir: string | null;
  readonly checkpointLines: number;
  /**
   * Whether an attempt must be journaled before it may execute. True by
   * default: an execution nobody could reconcile afterwards is worse than a
   * refusal. `SHADOW` never executes, so it never needs one.
   */
  readonly journalRequired: boolean;
  readonly journalRetainDays: number;
  /** Whether `/ready` waits while an attempt's outcome is still unknown. */
  readonly readyRequiresNoUnknownAttempts: boolean;
  /** Where an evidence bundle is written; exporting is refused when null. */
  readonly exportDir: string | null;
  /** How many lines of each stream this process keeps for an export. */
  readonly windowLines: number;
  /**
   * The image digest this deployment believes it is running, as the platform
   * reported it. Carried into a bundle and marked as not self-verified,
   * because a process cannot read the digest of its own image.
   */
  readonly imageDigest: string | null;
}

/** When the executor stops taking work, and what it takes to let it through again. */
export interface HaltConfig {
  readonly file: string | null;
  readonly authFailures: RateLimitRule | null;
  readonly egressRefusals: RateLimitRule | null;
}

/** The host's own ceilings, above whatever the authority decides; none when null. */
export type LimitsConfig = HardLimitSettings | null;

/**
 * The banking family's settings. `onEffectMismatch` is the institution's
 * exception policy in one word: an observation that does not match what was
 * authorised either stops the executor or is recorded and alerted on.
 */
export interface BankingConfig {
  readonly adapterId: string;
  readonly adapterVersion: string;
  readonly onEffectMismatch: "HALT" | "ALERT";
  /** Where a posted effect is read back by the provider's own reference. */
  readonly lookupByReferenceUrl: string | null;
}

/**
 * The executor's configuration: every setting, and the names of the secrets
 * it needs, but no secret value. Values live in a `SecretStore`, read through
 * a handle at the moment of use, so a rotation is followed and nothing here
 * can be printed by mistake.
 */
export interface ExecutorConfig {
  readonly mode: ExecutorMode;
  readonly production: boolean;
  readonly bindAddress: string;
  readonly port: number;
  readonly identity: IdentityConfig;
  /** How long a proposal stays valid; a ceremony has to finish inside it. */
  readonly intentTtlSeconds: number;
  readonly escalation: EscalationConfig;
  readonly authority: {
    readonly baseUrl: string;
    readonly allowInsecureLoopback: boolean;
  };
  readonly downstream: DownstreamConfig;
  readonly listener: ListenerConfig;
  readonly egress: EgressConfig;
  readonly evidence: EvidenceConfig;
  readonly halt: HaltConfig;
  readonly limits: LimitsConfig;
  readonly banking: BankingConfig;
  /** The most the authority's clock may differ from this host's before the executor halts. */
  readonly maxClockSkewMs: number;
  readonly posture: PostureSettings;
  readonly secrets: {
    /** The secrets this configuration needs; each is given as a file or, outside production, a variable. */
    readonly required: readonly SecretName[];
  };
}

const identifier = z.string().trim().min(1).max(200);
const headerName = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(/^[\w!#$%&'*+.^`|~-]+$/);
const booleanFlag = z.enum(["true", "false"]);
const absolutePath = z.string().trim().min(1).max(500).regex(/^\//);
const pinList = z
  .string()
  .trim()
  .regex(/^sha256\/[\w+/]{43}=(?:,sha256\/[\w+/]{43}=)*$/);
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const TLS_KEYS = [
  "EXECUTOR_TLS_CERT_FILE",
  "EXECUTOR_TLS_KEY",
  "EXECUTOR_TLS_KEY_FILE",
  "EXECUTOR_TLS_CLIENT_CA_FILE",
  "EXECUTOR_TLS_MIN_VERSION",
] as const;

const LEGACY_KEYS = [
  "EXECUTOR_TENANT_ID",
  "EXECUTOR_ACTOR_ID",
  "EXECUTOR_ACTOR_TYPE",
  "EXECUTOR_ACTOR_RUNTIME",
  "EXECUTOR_CALLER_TOKEN",
  "EXECUTOR_CALLER_TOKEN_FILE",
] as const;
const CREDENTIAL_KEYS = {
  STATIC_HEADER: [
    "DOWNSTREAM_CREDENTIAL",
    "DOWNSTREAM_CREDENTIAL_FILE",
    "DOWNSTREAM_CREDENTIAL_HEADER",
  ],
  PRIVATE_KEY_JWT: [
    "DOWNSTREAM_TOKEN_URL",
    "DOWNSTREAM_CLIENT_ID",
    "DOWNSTREAM_PRIVATE_KEY",
    "DOWNSTREAM_PRIVATE_KEY_FILE",
    "DOWNSTREAM_PRIVATE_KEY_ID",
    "DOWNSTREAM_PRIVATE_KEY_ALGORITHM",
    "DOWNSTREAM_TOKEN_AUDIENCE",
    "DOWNSTREAM_TOKEN_SCOPE",
  ],
  SIGNED_REQUEST: [
    "DOWNSTREAM_SIGNING_KEY",
    "DOWNSTREAM_SIGNING_KEY_FILE",
    "DOWNSTREAM_SIGNING_ALGORITHM",
    "DOWNSTREAM_SIGNING_KEY_ID",
  ],
} as const;

const EnvironmentSchema = z.object({
  EXECUTOR_MODE: z.enum(["SHADOW", "ENFORCEMENT"]),
  EXECUTOR_BIND_ADDRESS: z.string().trim().min(1).max(64),
  PORT: z.coerce.number().int().min(1).max(65_535),
  EXECUTOR_TENANT_ID: z.string().uuid().optional(),
  EXECUTOR_ACTOR_ID: identifier.optional(),
  EXECUTOR_ACTOR_TYPE: identifier.optional(),
  EXECUTOR_ACTOR_RUNTIME: identifier.optional(),
  EXECUTOR_PRINCIPALS_FILE: absolutePath.optional(),
  EXECUTOR_ALLOW_LEGACY_CALLER: booleanFlag.optional(),
  EXECUTOR_JWT_AUDIENCE: z.string().trim().min(1).max(200).optional(),
  EXECUTOR_JWKS_FILE: absolutePath.optional(),
  EXECUTOR_JWKS_URL: z.string().trim().min(1).max(500).optional(),
  EXECUTOR_JWKS_CA_FILE: absolutePath.optional(),
  EXECUTOR_JWKS_REFRESH_SECONDS: z.coerce.number().int().min(60).max(86_400).optional(),
  EXECUTOR_JWT_CLOCK_TOLERANCE_SECONDS: z.coerce.number().int().min(0).max(300).optional(),
  EXECUTOR_RATE_LIMIT_UNAUTHENTICATED: z.string().trim().min(1).max(20).optional(),
  EXECUTOR_AUTH_LOCKOUT: z.string().trim().min(1).max(30).optional(),
  EXECUTOR_INTENT_TTL_SECONDS: z.coerce.number().int().min(1).max(300),
  EXECUTOR_ESCALATION: z.enum(["NONE", "DIRECT", "MANAGED"]),
  EXECUTOR_POSTURE: z.enum(["ENFORCED", "DEVELOPMENT"]).optional(),
  EXECUTOR_POSTURE_INTERVAL_SECONDS: z.coerce.number().int().min(10).max(600).optional(),
  EXECUTOR_SECRETS_DIR: z.string().trim().min(1).max(500).optional(),
  EXECUTOR_TLS_CERT_FILE: absolutePath.optional(),
  EXECUTOR_TLS_CLIENT_CA_FILE: absolutePath.optional(),
  EXECUTOR_TLS_MIN_VERSION: z.enum(["1.2", "1.3"]).optional(),
  EXECUTOR_ALLOW_PLAINTEXT_LISTENER: booleanFlag.optional(),
  EXECUTOR_EGRESS_MAX_RESPONSE_BYTES: z.coerce
    .number()
    .int()
    .min(1024)
    .max(MAX_RESPONSE_BYTES)
    .optional(),
  EXECUTOR_JOURNAL_DIR: absolutePath.optional(),
  EXECUTOR_JOURNAL_REQUIRED: booleanFlag.optional(),
  EXECUTOR_JOURNAL_RETAIN_DAYS: z.coerce.number().int().min(1).max(365).optional(),
  EXECUTOR_READY_REQUIRES_NO_UNKNOWN_ATTEMPTS: booleanFlag.optional(),
  EXECUTOR_AUDIT_CHECKPOINT_LINES: z.coerce.number().int().min(1).max(10_000).optional(),
  EXECUTOR_EVIDENCE_DIR: absolutePath.optional(),
  EXECUTOR_EVIDENCE_WINDOW_LINES: z.coerce.number().int().min(100).max(200_000).optional(),
  // As the platform reports it, in the one form a registry uses.
  EXECUTOR_IMAGE_DIGEST: z
    .string()
    .trim()
    .regex(/^sha256:[0-9a-f]{64}$/)
    .optional(),
  EXECUTOR_HALT_FILE: absolutePath.optional(),
  EXECUTOR_HALT_ON_AUTH_FAILURES: z.string().trim().min(1).max(20).optional(),
  EXECUTOR_HALT_ON_EGRESS_REFUSALS: z.string().trim().min(1).max(20).optional(),
  EXECUTOR_HARD_LIMIT_SINGLE_MINOR: z.string().trim().min(5).max(500).optional(),
  EXECUTOR_HARD_LIMIT_WINDOW_COUNT: z.coerce.number().int().min(1).max(1_000_000).optional(),
  EXECUTOR_HARD_LIMIT_WINDOW_SECONDS: z.coerce.number().int().min(1).max(86_400).optional(),
  EXECUTOR_HARD_LIMIT_WINDOW_SUM_MINOR: z
    .string()
    .trim()
    .regex(/^\d{1,30}$/)
    .optional(),
  EXECUTOR_MAX_CLOCK_SKEW_MS: z.coerce.number().int().min(100).max(300_000).optional(),
  EXECUTOR_ON_EFFECT_MISMATCH: z.enum(["HALT", "ALERT"]).optional(),
  BANKING_ADAPTER_ID: identifier.optional(),
  BANKING_ADAPTER_VERSION: z.string().trim().min(1).max(100).optional(),
  DECIONIS_API_URL: z.string().trim().min(1).max(500),
  DECIONIS_ALLOW_INSECURE_LOOPBACK: booleanFlag.optional(),
  DECIONIS_CA_FILE: absolutePath.optional(),
  DECIONIS_SPKI_PINS: pinList.optional(),
  PRESENCE_API_URL: z.string().trim().min(1).max(500).optional(),
  PRESENCE_CA_FILE: absolutePath.optional(),
  PRESENCE_ORGANIZATION: z.string().trim().min(1).max(200).optional(),
  PRESENCE_APPROVER_ID: identifier.optional(),
  PRESENCE_APPROVER_ROLE: identifier.optional(),
  PRESENCE_VERIFICATION_LEVEL: z.enum(["STANDARD", "HIGH_CONFIDENCE"]).optional(),
  PRESENCE_VERIFICATION_METHODS: z
    .string()
    .trim()
    .regex(/^[A-Z_]+(?:,[A-Z_]+)*$/)
    .optional(),
  PRESENCE_HARDWARE_PKI_REQUIRED: booleanFlag.optional(),
  PRESENCE_DISALLOW_VIRTUAL_CAMERAS: booleanFlag.optional(),
  DOWNSTREAM_URL: z.string().trim().min(1).max(500),
  DOWNSTREAM_LOOKUP_URL: z.string().trim().min(1).max(500).optional(),
  DOWNSTREAM_LOOKUP_BY_REFERENCE_URL: z.string().trim().min(1).max(500).optional(),
  DOWNSTREAM_SYSTEM: identifier,
  DOWNSTREAM_OPERATION: identifier,
  DOWNSTREAM_ENVIRONMENT: identifier,
  DOWNSTREAM_CREDENTIAL_KIND: z
    .enum(["STATIC_HEADER", "PRIVATE_KEY_JWT", "SIGNED_REQUEST"])
    .optional(),
  DOWNSTREAM_CREDENTIAL_HEADER: headerName.optional(),
  DOWNSTREAM_TOKEN_URL: z.string().trim().min(1).max(500).optional(),
  DOWNSTREAM_CLIENT_ID: identifier.optional(),
  DOWNSTREAM_PRIVATE_KEY_ID: identifier.optional(),
  DOWNSTREAM_PRIVATE_KEY_ALGORITHM: z.enum(["ES256", "PS256"]).optional(),
  DOWNSTREAM_TOKEN_AUDIENCE: z.string().trim().min(1).max(500).optional(),
  DOWNSTREAM_TOKEN_SCOPE: z.string().trim().min(1).max(500).optional(),
  DOWNSTREAM_SIGNING_ALGORITHM: z.enum(["ed25519", "hmac-sha256"]).optional(),
  DOWNSTREAM_SIGNING_KEY_ID: identifier.optional(),
  DOWNSTREAM_CA_FILE: absolutePath.optional(),
  DOWNSTREAM_SPKI_PINS: pinList.optional(),
  DOWNSTREAM_TIMEOUT_MS: z.coerce.number().int().min(1).max(15_000),
});

type Environment = z.infer<typeof EnvironmentSchema>;
type EnvironmentMap = Readonly<Record<string, string | undefined>>;

const DIRECT_KEYS = [
  "PRESENCE_API_URL",
  "PRESENCE_ORGANIZATION",
  "PRESENCE_APPROVER_ID",
  "PRESENCE_VERIFICATION_LEVEL",
  "PRESENCE_VERIFICATION_METHODS",
  "PRESENCE_HARDWARE_PKI_REQUIRED",
  "PRESENCE_DISALLOW_VIRTUAL_CAMERAS",
] as const;

const MANAGED_KEYS = [
  "PRESENCE_APPROVER_ID",
  "PRESENCE_VERIFICATION_LEVEL",
  "PRESENCE_VERIFICATION_METHODS",
] as const;

/**
 * Reads the executor's configuration from an environment map. Every failure
 * is a refusal to start that names the variable, never its value. There is
 * no default for anything that identifies a tenant, a system, a person, or
 * a network path: a deployment states all of it. Secrets are located here
 * (which variable, which file) and read elsewhere.
 */
export class ExecutorConfigLoader {
  public static load(env: EnvironmentMap): ExecutorConfig {
    const production = env["NODE_ENV"] === "production";
    const present: Record<string, string> = {};
    for (const key of Object.keys(EnvironmentSchema.shape)) {
      const value = env[key];
      if (value !== undefined) present[key] = value;
    }
    const parsed = EnvironmentSchema.safeParse(present);
    if (!parsed.success) {
      const keys = [...new Set(parsed.error.issues.map((issue) => String(issue.path[0] ?? "")))];
      throw new Error(`CONFIG_INVALID: ${keys.sort().join(", ")}`);
    }
    const values = parsed.data;
    const allowInsecureLoopback = values.DECIONIS_ALLOW_INSECURE_LOOPBACK === "true";
    if (allowInsecureLoopback && production) {
      throw new Error("CONFIG_INVALID: DECIONIS_ALLOW_INSECURE_LOOPBACK (forbidden in production)");
    }
    const postureMode = values.EXECUTOR_POSTURE ?? "ENFORCED";
    if (postureMode === "DEVELOPMENT" && production) {
      throw new Error("CONFIG_INVALID: EXECUTOR_POSTURE (forbidden in production)");
    }
    const lookupUrl = values.DOWNSTREAM_LOOKUP_URL;
    if (lookupUrl !== undefined && !lookupUrl.includes("{idempotency_key}")) {
      throw new Error("CONFIG_INVALID: DOWNSTREAM_LOOKUP_URL (must contain {idempotency_key})");
    }
    const byReference = values.DOWNSTREAM_LOOKUP_BY_REFERENCE_URL;
    if (byReference !== undefined && !byReference.includes("{provider_reference}")) {
      throw new Error(
        "CONFIG_INVALID: DOWNSTREAM_LOOKUP_BY_REFERENCE_URL (must contain {provider_reference})",
      );
    }
    const escalation = ExecutorConfigLoader.escalation(values, allowInsecureLoopback);
    const listener = ExecutorConfigLoader.listener(values, env, production);
    const authorityUrl = ExecutorConfigLoader.serviceUrl(
      values.DECIONIS_API_URL,
      "DECIONIS_API_URL",
      allowInsecureLoopback,
    );
    const downstreamUrl = ExecutorConfigLoader.serviceUrl(
      values.DOWNSTREAM_URL,
      "DOWNSTREAM_URL",
      allowInsecureLoopback,
    );
    const downstreamLookupUrl =
      lookupUrl === undefined
        ? null
        : ExecutorConfigLoader.serviceUrl(
            lookupUrl,
            "DOWNSTREAM_LOOKUP_URL",
            allowInsecureLoopback,
          );
    const byReferenceUrl =
      byReference === undefined
        ? null
        : ExecutorConfigLoader.serviceUrl(
            byReference,
            "DOWNSTREAM_LOOKUP_BY_REFERENCE_URL",
            allowInsecureLoopback,
          );
    const identity = ExecutorConfigLoader.identity(values, env, production, allowInsecureLoopback);
    const credential = ExecutorConfigLoader.credential(values, env, allowInsecureLoopback);
    const egress = ExecutorConfigLoader.egress(
      values,
      escalation.mode,
      authorityUrl,
      downstreamUrl,
    );
    const required: SecretName[] = [];
    if (identity.legacy !== null) required.push("EXECUTOR_CALLER_TOKEN");
    required.push("DECIONIS_API_KEY");
    if (credential.kind === "STATIC_HEADER") required.push("DOWNSTREAM_CREDENTIAL");
    if (credential.kind === "PRIVATE_KEY_JWT") required.push("DOWNSTREAM_PRIVATE_KEY");
    if (credential.kind === "SIGNED_REQUEST") required.push("DOWNSTREAM_SIGNING_KEY");
    if (escalation.mode === "DIRECT") required.push("PRESENCE_API_KEY");
    if (listener.tls !== null) required.push("EXECUTOR_TLS_KEY");
    // A signing key for the bundle manifest is optional: without it a bundle
    // proves its own internal consistency and nothing about who made it, and
    // the verifier says which of the two it is holding.
    const evidenceSigning =
      env["EXECUTOR_EVIDENCE_SIGNING_KEY"] !== undefined ||
      env["EXECUTOR_EVIDENCE_SIGNING_KEY_FILE"] !== undefined;
    if (evidenceSigning) {
      if (values.EXECUTOR_EVIDENCE_DIR === undefined) {
        throw new Error("CONFIG_INVALID: EXECUTOR_EVIDENCE_DIR (required to sign a bundle)");
      }
      required.push("EXECUTOR_EVIDENCE_SIGNING_KEY");
    }
    if (
      escalation.mode !== "NONE" &&
      identity.legacy !== null &&
      escalation.approverId === identity.legacy.actor.id
    ) {
      throw new Error(
        "CONFIG_INVALID: PRESENCE_APPROVER_ID (separation of duties: also the actor)",
      );
    }
    const located = ExecutorConfigLoader.locateSecrets(env, required, production);
    const secretsDir = values.EXECUTOR_SECRETS_DIR ?? null;
    if (secretsDir !== null && !secretsDir.startsWith("/")) {
      throw new Error("CONFIG_INVALID: EXECUTOR_SECRETS_DIR (absolute path)");
    }
    if (production && secretsDir === null && Object.keys(located.files).length > 0) {
      throw new Error("CONFIG_INVALID: EXECUTOR_SECRETS_DIR (required in production)");
    }
    const journalRequired = values.EXECUTOR_JOURNAL_REQUIRED !== "false";
    if (
      values.EXECUTOR_MODE === "ENFORCEMENT" &&
      journalRequired &&
      values.EXECUTOR_JOURNAL_DIR === undefined
    ) {
      throw new Error(
        "CONFIG_INVALID: EXECUTOR_JOURNAL_DIR (required in enforcement unless EXECUTOR_JOURNAL_REQUIRED=false)",
      );
    }
    if (!journalRequired && production) {
      throw new Error("CONFIG_INVALID: EXECUTOR_JOURNAL_REQUIRED (forbidden in production)");
    }
    const environment: Record<string, string> = {};
    for (const key of INSPECTED_ENVIRONMENT) {
      const value = env[key];
      if (value !== undefined) environment[key] = value;
    }
    return {
      mode: values.EXECUTOR_MODE,
      production,
      bindAddress: values.EXECUTOR_BIND_ADDRESS,
      port: values.PORT,
      identity,
      intentTtlSeconds: values.EXECUTOR_INTENT_TTL_SECONDS,
      escalation,
      authority: { baseUrl: authorityUrl, allowInsecureLoopback },
      downstream: {
        url: downstreamUrl,
        lookupUrl: downstreamLookupUrl,
        system: values.DOWNSTREAM_SYSTEM,
        operation: values.DOWNSTREAM_OPERATION,
        environment: values.DOWNSTREAM_ENVIRONMENT,
        credential,
        redactedHeaders:
          credential.kind === "STATIC_HEADER"
            ? [credential.header]
            : credential.kind === "PRIVATE_KEY_JWT"
              ? ["authorization"]
              : ["signature"],
        timeoutMs: values.DOWNSTREAM_TIMEOUT_MS,
      },
      listener,
      egress,
      evidence: {
        journalDir: values.EXECUTOR_JOURNAL_DIR ?? null,
        checkpointLines: values.EXECUTOR_AUDIT_CHECKPOINT_LINES ?? 100,
        journalRequired: values.EXECUTOR_JOURNAL_REQUIRED !== "false",
        journalRetainDays: values.EXECUTOR_JOURNAL_RETAIN_DAYS ?? 7,
        readyRequiresNoUnknownAttempts:
          values.EXECUTOR_READY_REQUIRES_NO_UNKNOWN_ATTEMPTS === "true",
        exportDir: values.EXECUTOR_EVIDENCE_DIR ?? null,
        windowLines: values.EXECUTOR_EVIDENCE_WINDOW_LINES ?? 5_000,
        imageDigest: values.EXECUTOR_IMAGE_DIGEST ?? null,
      },
      halt: {
        file: values.EXECUTOR_HALT_FILE ?? null,
        authFailures: RateLimiter.parseRule(
          values.EXECUTOR_HALT_ON_AUTH_FAILURES ?? "50/60",
          "EXECUTOR_HALT_ON_AUTH_FAILURES",
        ),
        egressRefusals: RateLimiter.parseRule(
          values.EXECUTOR_HALT_ON_EGRESS_REFUSALS ?? "5/60",
          "EXECUTOR_HALT_ON_EGRESS_REFUSALS",
        ),
      },
      limits: ExecutorConfigLoader.limits(values),
      banking: {
        adapterId: values.BANKING_ADAPTER_ID ?? "AGENTSAFE_CORE_BANKING",
        adapterVersion: values.BANKING_ADAPTER_VERSION ?? "0.1.0",
        onEffectMismatch: values.EXECUTOR_ON_EFFECT_MISMATCH ?? "HALT",
        lookupByReferenceUrl: byReferenceUrl,
      },
      maxClockSkewMs: values.EXECUTOR_MAX_CLOCK_SKEW_MS ?? 2_000,
      posture: {
        mode: postureMode,
        intervalSeconds: values.EXECUTOR_POSTURE_INTERVAL_SECONDS ?? 60,
        production,
        environment,
        secretsInEnvironment: located.fromEnvironment,
        secretFiles: located.files,
        secretsDir,
        principalsFile: identity.principalsFile,
      },
      secrets: { required },
    };
  }

  /**
   * Who may call. A principals file names every caller and excludes the
   * legacy variables; without one, the legacy caller is synthesised from
   * them, which production refuses unless asked for by name.
   */
  private static identity(
    values: Environment,
    env: EnvironmentMap,
    production: boolean,
    allowInsecureLoopback: boolean,
  ): IdentityConfig {
    const principalsFile = values.EXECUTOR_PRINCIPALS_FILE ?? null;
    const allowLegacyCaller = values.EXECUTOR_ALLOW_LEGACY_CALLER === "true";
    let legacy: IdentityConfig["legacy"] = null;
    if (principalsFile !== null) {
      const given = LEGACY_KEYS.filter((key) => env[key] !== undefined);
      if (given.length > 0) {
        throw new Error(
          `CONFIG_INVALID: EXECUTOR_PRINCIPALS_FILE (principals file with ${given.join(", ")})`,
        );
      }
    } else {
      if (production && !allowLegacyCaller) {
        throw new Error(
          "CONFIG_INVALID: EXECUTOR_PRINCIPALS_FILE (required in production unless EXECUTOR_ALLOW_LEGACY_CALLER=true)",
        );
      }
      const missing = (
        ["EXECUTOR_TENANT_ID", "EXECUTOR_ACTOR_ID", "EXECUTOR_ACTOR_TYPE"] as const
      ).filter((key) => values[key] === undefined);
      if (missing.length > 0) throw new Error(`CONFIG_INVALID: ${missing.join(", ")}`);
      legacy = {
        tenantId: values.EXECUTOR_TENANT_ID ?? "",
        actor: {
          id: values.EXECUTOR_ACTOR_ID ?? "",
          type: values.EXECUTOR_ACTOR_TYPE ?? "",
          ...(values.EXECUTOR_ACTOR_RUNTIME === undefined
            ? {}
            : { runtime: values.EXECUTOR_ACTOR_RUNTIME }),
        },
      };
    }
    const audience = values.EXECUTOR_JWT_AUDIENCE;
    const jwksFile = values.EXECUTOR_JWKS_FILE;
    if ((audience === undefined) !== (jwksFile === undefined)) {
      throw new Error(
        "CONFIG_INVALID: EXECUTOR_JWT_AUDIENCE, EXECUTOR_JWKS_FILE (given together or not at all)",
      );
    }
    if (audience === undefined && values.EXECUTOR_JWKS_URL !== undefined) {
      throw new Error("CONFIG_INVALID: EXECUTOR_JWKS_URL (without EXECUTOR_JWKS_FILE)");
    }
    if (values.EXECUTOR_JWKS_URL === undefined && values.EXECUTOR_JWKS_CA_FILE !== undefined) {
      throw new Error("CONFIG_INVALID: EXECUTOR_JWKS_CA_FILE (without EXECUTOR_JWKS_URL)");
    }
    const jwt =
      audience === undefined || jwksFile === undefined
        ? null
        : {
            audience,
            jwksFile,
            jwksUrl:
              values.EXECUTOR_JWKS_URL === undefined
                ? null
                : ExecutorConfigLoader.serviceUrl(
                    values.EXECUTOR_JWKS_URL,
                    "EXECUTOR_JWKS_URL",
                    allowInsecureLoopback,
                  ),
            jwksCaFile: values.EXECUTOR_JWKS_CA_FILE ?? null,
            refreshSeconds: values.EXECUTOR_JWKS_REFRESH_SECONDS ?? 300,
            clockToleranceSeconds: values.EXECUTOR_JWT_CLOCK_TOLERANCE_SECONDS ?? 30,
          };
    return {
      principalsFile,
      allowLegacyCaller,
      legacy,
      jwt,
      unauthenticated: RateLimiter.parseRule(
        values.EXECUTOR_RATE_LIMIT_UNAUTHENTICATED ?? "20/60",
        "EXECUTOR_RATE_LIMIT_UNAUTHENTICATED",
      ),
      lockout: RateLimiter.parseLockout(
        values.EXECUTOR_AUTH_LOCKOUT ?? "10/60/300",
        "EXECUTOR_AUTH_LOCKOUT",
      ),
    };
  }

  /**
   * The host's own ceilings. A window needs a length, and a sum without a
   * per-currency ceiling would be a ceiling on nothing, so the parts are
   * refused apart rather than silently ignored.
   */
  private static limits(values: Environment): LimitsConfig {
    const ceilings = values.EXECUTOR_HARD_LIMIT_SINGLE_MINOR;
    const count = values.EXECUTOR_HARD_LIMIT_WINDOW_COUNT ?? null;
    const sum = values.EXECUTOR_HARD_LIMIT_WINDOW_SUM_MINOR ?? null;
    const seconds = values.EXECUTOR_HARD_LIMIT_WINDOW_SECONDS ?? null;
    if (ceilings === undefined) {
      const given = (
        [
          "EXECUTOR_HARD_LIMIT_WINDOW_COUNT",
          "EXECUTOR_HARD_LIMIT_WINDOW_SECONDS",
          "EXECUTOR_HARD_LIMIT_WINDOW_SUM_MINOR",
        ] as const
      ).filter((key) => values[key] !== undefined);
      if (given.length > 0) {
        throw new Error(
          `CONFIG_INVALID: EXECUTOR_HARD_LIMIT_SINGLE_MINOR (required with ${given.join(", ")})`,
        );
      }
      return null;
    }
    if ((count !== null || sum !== null) && seconds === null) {
      throw new Error(
        "CONFIG_INVALID: EXECUTOR_HARD_LIMIT_WINDOW_SECONDS (required with a window)",
      );
    }
    return {
      singleMinor: HardLimits.parseCeilings(ceilings, "EXECUTOR_HARD_LIMIT_SINGLE_MINOR"),
      windowSeconds: seconds ?? 60,
      windowCount: count,
      windowSumMinor: sum === null ? null : BigInt(sum),
    };
  }

  /** The downstream credential kind, with the keys of the other kinds refused by name. */
  private static credential(
    values: Environment,
    env: EnvironmentMap,
    allowInsecureLoopback: boolean,
  ): DownstreamCredentialConfig {
    const kind = values.DOWNSTREAM_CREDENTIAL_KIND ?? "STATIC_HEADER";
    const foreign = (Object.keys(CREDENTIAL_KEYS) as (keyof typeof CREDENTIAL_KEYS)[])
      .filter((other) => other !== kind)
      .flatMap((other) => CREDENTIAL_KEYS[other].filter((key) => env[key] !== undefined));
    if (foreign.length > 0) {
      throw new Error(
        `CONFIG_INVALID: DOWNSTREAM_CREDENTIAL_KIND (${kind} with ${foreign.join(", ")})`,
      );
    }
    if (kind === "STATIC_HEADER") {
      if (values.DOWNSTREAM_CREDENTIAL_HEADER === undefined) {
        throw new Error("CONFIG_INVALID: DOWNSTREAM_CREDENTIAL_HEADER");
      }
      return { kind, header: values.DOWNSTREAM_CREDENTIAL_HEADER.toLowerCase() };
    }
    if (kind === "PRIVATE_KEY_JWT") {
      const missing = (["DOWNSTREAM_TOKEN_URL", "DOWNSTREAM_CLIENT_ID"] as const).filter(
        (key) => values[key] === undefined,
      );
      if (missing.length > 0) throw new Error(`CONFIG_INVALID: ${missing.join(", ")}`);
      return {
        kind,
        tokenUrl: ExecutorConfigLoader.serviceUrl(
          values.DOWNSTREAM_TOKEN_URL ?? "",
          "DOWNSTREAM_TOKEN_URL",
          allowInsecureLoopback,
        ),
        clientId: values.DOWNSTREAM_CLIENT_ID ?? "",
        keyId: values.DOWNSTREAM_PRIVATE_KEY_ID ?? null,
        algorithm: values.DOWNSTREAM_PRIVATE_KEY_ALGORITHM ?? "ES256",
        audience: values.DOWNSTREAM_TOKEN_AUDIENCE ?? null,
        scope: values.DOWNSTREAM_TOKEN_SCOPE ?? null,
      };
    }
    if (values.DOWNSTREAM_SIGNING_KEY_ID === undefined) {
      throw new Error("CONFIG_INVALID: DOWNSTREAM_SIGNING_KEY_ID");
    }
    return {
      kind,
      algorithm: values.DOWNSTREAM_SIGNING_ALGORITHM ?? "ed25519",
      keyId: values.DOWNSTREAM_SIGNING_KEY_ID,
    };
  }

  /**
   * TLS unless plaintext is asked for by name, which production refuses.
   * A plaintext listener with TLS material beside it is a contradiction
   * and is refused too, naming what was given.
   */
  private static listener(
    values: Environment,
    env: EnvironmentMap,
    production: boolean,
  ): ListenerConfig {
    const plaintext = values.EXECUTOR_ALLOW_PLAINTEXT_LISTENER === "true";
    if (plaintext) {
      if (production) {
        throw new Error(
          "CONFIG_INVALID: EXECUTOR_ALLOW_PLAINTEXT_LISTENER (forbidden in production)",
        );
      }
      const given = TLS_KEYS.filter((key) => env[key] !== undefined);
      if (given.length > 0) {
        throw new Error(
          `CONFIG_INVALID: EXECUTOR_ALLOW_PLAINTEXT_LISTENER (plaintext listener with ${given.join(", ")})`,
        );
      }
      return { tls: null };
    }
    const certFile = values.EXECUTOR_TLS_CERT_FILE;
    if (certFile === undefined) {
      throw new Error(
        "CONFIG_INVALID: EXECUTOR_TLS_CERT_FILE (required unless EXECUTOR_ALLOW_PLAINTEXT_LISTENER=true)",
      );
    }
    return {
      tls: {
        certFile,
        clientCaFile: values.EXECUTOR_TLS_CLIENT_CA_FILE ?? null,
        minVersion: values.EXECUTOR_TLS_MIN_VERSION === "1.2" ? "TLSv1.2" : "TLSv1.3",
      },
    };
  }

  /** The trust anchors per destination; one origin has one anchor, and a pin set is two or more. */
  private static egress(
    values: Environment,
    escalation: EscalationMode,
    authorityUrl: string,
    downstreamUrl: string,
  ): EgressConfig {
    const pins = (value: string | undefined, key: string): readonly string[] => {
      if (value === undefined) return [];
      const distinct = [...new Set(value.split(","))];
      if (distinct.length < 2)
        throw new Error(`CONFIG_INVALID: ${key} (at least two distinct pins)`);
      return distinct;
    };
    if (values.PRESENCE_CA_FILE !== undefined && escalation !== "DIRECT") {
      throw new Error("CONFIG_INVALID: PRESENCE_CA_FILE (DIRECT escalation only)");
    }
    const authority: TrustAnchor = {
      caFile: values.DECIONIS_CA_FILE ?? null,
      pins: pins(values.DECIONIS_SPKI_PINS, "DECIONIS_SPKI_PINS"),
    };
    const downstream: TrustAnchor = {
      caFile: values.DOWNSTREAM_CA_FILE ?? null,
      pins: pins(values.DOWNSTREAM_SPKI_PINS, "DOWNSTREAM_SPKI_PINS"),
    };
    const sameOrigin = new URL(authorityUrl).origin === new URL(downstreamUrl).origin;
    const sameAnchor =
      authority.caFile === downstream.caFile &&
      authority.pins.join(",") === downstream.pins.join(",");
    if (sameOrigin && !sameAnchor) {
      throw new Error(
        "CONFIG_INVALID: DOWNSTREAM_CA_FILE, DOWNSTREAM_SPKI_PINS (one origin, one trust anchor)",
      );
    }
    return {
      maxResponseBytes: values.EXECUTOR_EGRESS_MAX_RESPONSE_BYTES ?? 1024 * 1024,
      trust: {
        authority,
        presence: { caFile: values.PRESENCE_CA_FILE ?? null, pins: [] },
        downstream,
      },
    };
  }

  /**
   * Where each required secret is: a file (`<NAME>_FILE`) or, outside
   * production, the variable itself. Given both ways, neither way, or in the
   * environment under production is a refusal that names the variable.
   */
  private static locateSecrets(
    env: EnvironmentMap,
    required: readonly SecretName[],
    production: boolean,
  ): {
    readonly files: Readonly<Partial<Record<SecretName, string>>>;
    readonly fromEnvironment: readonly SecretName[];
  } {
    const files: Partial<Record<SecretName, string>> = {};
    const fromEnvironment: SecretName[] = [];
    for (const name of required) {
      const direct = env[name];
      const path = env[`${name}_FILE`];
      if (direct !== undefined && path !== undefined) {
        throw new SecretError("CONFIG_SECRET_AMBIGUOUS", name);
      }
      if (path !== undefined) files[name] = path;
      else if (direct !== undefined) {
        if (production) throw new SecretError("CONFIG_SECRET_IN_ENV", name);
        fromEnvironment.push(name);
      } else throw new SecretError("CONFIG_SECRET_MISSING", name);
    }
    return { files, fromEnvironment };
  }

  private static escalation(values: Environment, allowInsecureLoopback: boolean): EscalationConfig {
    const mode = values.EXECUTOR_ESCALATION;
    if (mode === "NONE") return { mode };
    // Shadow observes; it never escalates, and a managed escalation in shadow
    // is refused by the gate anyway. Saying so at start-up is clearer.
    if (values.EXECUTOR_MODE === "SHADOW") {
      throw new Error("CONFIG_INVALID: EXECUTOR_ESCALATION (shadow never escalates)");
    }
    const required = mode === "DIRECT" ? DIRECT_KEYS : MANAGED_KEYS;
    const missing = required.filter((key) => values[key] === undefined);
    if (missing.length > 0) throw new Error(`CONFIG_INVALID: ${missing.join(", ")}`);
    const methods = ExecutorConfigLoader.methods(values.PRESENCE_VERIFICATION_METHODS ?? "");
    const level = values.PRESENCE_VERIFICATION_LEVEL ?? "STANDARD";
    const approverId = values.PRESENCE_APPROVER_ID ?? "";
    if (mode === "MANAGED") {
      return {
        mode,
        approverId,
        approverRole: values.PRESENCE_APPROVER_ROLE ?? null,
        requirements: { methods, level },
      };
    }
    return {
      mode,
      presence: {
        baseUrl: ExecutorConfigLoader.serviceUrl(
          values.PRESENCE_API_URL ?? "",
          "PRESENCE_API_URL",
          allowInsecureLoopback,
        ),
        organization: values.PRESENCE_ORGANIZATION ?? "",
      },
      approverId,
      requirements: {
        level,
        methods: [...methods],
        hardware_pki_required: values.PRESENCE_HARDWARE_PKI_REQUIRED === "true",
        disallow_virtual_cameras: values.PRESENCE_DISALLOW_VIRTUAL_CAMERAS === "true",
      },
    };
  }

  /** The ceremony methods both shapes accept, as a comma-separated list. */
  private static methods(value: string): readonly VerificationMethod[] {
    const methods = value.split(",").map((method) => method.trim());
    const valid = methods.every(
      (method): method is VerificationMethod =>
        method === "WEBAUTHN" || method === "ACTIVE_LIVENESS",
    );
    if (!valid || methods.length === 0 || new Set(methods).size !== methods.length) {
      throw new Error("CONFIG_INVALID: PRESENCE_VERIFICATION_METHODS");
    }
    return methods as VerificationMethod[];
  }

  /**
   * The same rule the gate applies to the authority address: HTTPS, no
   * credentials in the URL, no query or fragment. Plain HTTP is accepted for
   * loopback only, only when asked for, and never in production.
   */
  /** An https URL, or a loopback http one when that is allowed by name; the gateway's loader shares it. */
  public static serviceUrl(value: string, key: string, allowInsecureLoopback: boolean): string {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new Error(`CONFIG_INVALID: ${key} (not a URL)`);
    }
    if (url.username !== "" || url.password !== "") {
      throw new Error(`CONFIG_INVALID: ${key} (credentials in URL)`);
    }
    if (url.search !== "" || url.hash !== "") {
      throw new Error(`CONFIG_INVALID: ${key} (query or fragment)`);
    }
    const loopback =
      url.hostname === "127.0.0.1" || url.hostname === "localhost" || url.hostname === "[::1]";
    if (url.protocol !== "https:" && !(allowInsecureLoopback && loopback)) {
      throw new Error(`CONFIG_INVALID: ${key} (https required)`);
    }
    return value;
  }
}
