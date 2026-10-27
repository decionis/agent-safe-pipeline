import { ApiProfiles } from "@decionis/agent-safe-pipeline";
import { isAbsolute } from "node:path";
import { z } from "zod";
import {
  ExecutorConfigLoader,
  type EscalationConfig,
  type VerificationMethod,
} from "../config/ExecutorConfig.js";
import { EgressPolicy } from "../egress/EgressPolicy.js";
import type { SecretName } from "../secrets/SecretStore.js";
import { HOSTED_DEFAULT_RATE_LIMIT, type RateLimit } from "./RateLimit.js";
import { PolicyIdSchema, PolicyVersionSchema } from "./PolicySelector.js";

export type GatewayMode = "SHADOW" | "ENFORCEMENT";
export type FailurePolicy = "FAIL_CLOSED" | "FAIL_OPEN";
export type AuthorityKind = "LOCAL" | "DECIONIS";
export type UnmatchedPolicy = "GOVERN" | "PASSTHROUGH";
/**
 * What of a governed request the authority receives. `FULL` is the method,
 * path, query and, within the embedding bound, the body. `FACTS` is the API
 * profile's operation id and path template and the facts it names, and never
 * a raw path, query, header or body byte.
 */
export type PrivacyMode = "FULL" | "FACTS";
export type OutputFormat = "HUMAN" | "JSON";

/** The methods a route governs unless it names its own; a safe method is never consequential. */
export const CONSEQUENTIAL_METHODS = ["POST", "PUT", "PATCH", "DELETE"] as const;
export type ConsequentialMethod = (typeof CONSEQUENTIAL_METHODS)[number];

/** The intent contract's action name: what a route may call the action it governs. */
export const ACTION_NAME = /^[a-z][a-z0-9._:-]*$/;

/** The header a tenant presents its ingress key in; never the URL, never forwarded. */
export const TENANT_KEY_HEADER = "agentsafe-tenant-key";
/** The header a caller presents a subject session in, from the gateway's token exchange; never forwarded. */
export const SESSION_HEADER = "agentsafe-session";
/** The header a caller presents the identity provider's subject token in, per request; never forwarded. */
export const SUBJECT_TOKEN_HEADER = "agentsafe-subject-token";
const TENANT_KEY_DIGEST = /^sha256:[0-9a-f]{64}$/;
/** A tenant's registry id: the DNS label it is served under. */
const HOSTED_TENANT = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
/** A header name as RFC 9110 spells a token, lower-cased. */
const HEADER_TOKEN = /^[a-z0-9!#$%&'*+.^_`|~-]{1,64}$/;
/**
 * Headers an upstream credential may not be carried in: those that describe
 * the hop or frame the request, which the gateway sets or drops itself, and
 * those the authority reads (the intent binds Content-Type and
 * Idempotency-Key), so a credential never reaches the intent.
 */
const CREDENTIAL_HEADERS_REFUSED: ReadonlySet<string> = new Set([
  "host",
  "content-length",
  "content-type",
  "content-encoding",
  "transfer-encoding",
  "connection",
  "keep-alive",
  "upgrade",
  "te",
  "trailer",
  "expect",
  "accept-encoding",
  "idempotency-key",
  "proxy-authorization",
  "proxy-authenticate",
  "proxy-connection",
  TENANT_KEY_HEADER,
]);
const CREDENTIAL_PREFIXES_REFUSED = ["agentsafe-", "x-agent-safe-", "x-forwarded-"] as const;

/** The tenant the demo authority evaluates under; a reserved fixture identifier, never an organization. */
export const LOCAL_TENANT_ID = "00000000-0000-4000-8000-000000000009";
export const DEFAULT_AUTHORITY_ENDPOINT = "https://api.decionis.com";
export const DEFAULT_LISTEN = { host: "127.0.0.1", port: 8080 } as const;
const DEFAULT_TIMEOUT_MS = 4_000;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
const DEFAULT_MAX_EMBEDDED_BODY_BYTES = 64 * 1024;
const DEFAULT_INTENT_TTL_SECONDS = 120;
const DEFAULT_SESSION_TTL_SECONDS = 900;
/** The most a body may be, so the bound is a bound and not a suggestion. */
const MAX_BODY_BYTES = 16 * 1024 * 1024;

/**
 * Who a session is for: the identity provider whose short-lived token names
 * the subject (the customer in context), and where in the token the subject
 * is. The gateway pins that subject for the session.
 */
export interface SubjectConfig {
  readonly issuer: string;
  readonly audience: string;
  /** A JWKS document on disk; the first key set, and the one kept when a refresh fails. */
  readonly jwksFile: string | null;
  /** Where the key set is refreshed from, through the guarded egress; fetched at start without a file. */
  readonly jwksUrl: string | null;
  /** The claim naming the subject; `sub` by default. */
  readonly claim: string;
  /** The longest a session from the token exchange lasts; never past the token's own expiry. */
  readonly sessionTtlSeconds: number;
}

export interface RouteConfig {
  readonly path: string;
  readonly action: string;
  readonly methods: readonly ConsequentialMethod[];
  /** A published immutable policy bundle UUID, not a workspace policy head or rule ID. */
  readonly policyId?: string;
  /** An exact published policy version; when both selectors are set, both must match. */
  readonly policyVersion?: string;
}

/**
 * Everything the gateway runs on, resolved from flags, environment, file and
 * defaults in that order, with no secret value in it: the names of the
 * secrets it needs are in `secrets.required`, and the values are opened by a
 * store at start, the way the executor's are.
 */
export interface GatewayConfig {
  readonly listen: { readonly host: string; readonly port: number };
  /**
   * Run for a tenant by someone else, as Decionis runs hosted shadow: the
   * upstream is public-only, the mode is shadow, the gateway's own status and
   * metrics answer only the operator, a relayed cookie is host-only, and a
   * relayed response is sandboxed (no script runs in it).
   */
  readonly hosted: boolean;
  /**
   * The tenant a hosted gateway runs for, as its registry id: written into the
   * envelope of every chained line, so the tenant is covered by the hash.
   */
  readonly hostedTenant: string | null;
  /**
   * A hosted gateway that is the only gateway its process serves: a host
   * started for one tenant (`agentsafe host --tenant`), or a single hosted
   * gateway. A hosted gateway enforces nowhere else, so no other tenant's
   * process ever holds its credentials or its held requests.
   */
  readonly hostedDedicated: boolean;
  /**
   * The tenant's ingress keys, as `sha256:` digests: one, or two while a
   * rotation overlaps. When there are any, a request that is not the
   * gateway's own must carry a key in `AgentSafe-Tenant-Key` that hashes to
   * one of them. The key itself is never in the configuration.
   */
  readonly tenantKeys: readonly string[];
  /**
   * The rate this gateway admits its traffic at, after the tenant key: a
   * sustained rate and a burst, per process. A hosted gateway without one
   * gets HOSTED_DEFAULT_RATE_LIMIT; otherwise null is no limit.
   */
  readonly rateLimit: RateLimit | null;
  readonly upstream: {
    readonly url: string;
    /** A plain-HTTP upstream off loopback is refused unless this says the network protects the hop. */
    readonly insecure: boolean;
    /**
     * Connect to the upstream only at public addresses, through the guarded
     * egress. For a gateway whose upstream someone else chose, as a hosted
     * tenant does: a name that resolves to a private, shared, platform or
     * loopback address is refused before a socket exists.
     */
    readonly publicOnly: boolean;
    /**
     * Forward nothing until the upstream's origin serves a token bound to this
     * tenant, its organization and that origin, and keep checking that it
     * does (gateway/UpstreamProof.ts). Hosted only: the binding is the
     * hosted tenant and the Decionis organization it runs under.
     */
    readonly proofRequired: boolean;
    /**
     * The credential the gateway, and not its caller, presents to the
     * upstream: one header it sets on every request it forwards, whose value
     * is the secret in `file` (opened as `DOWNSTREAM_CREDENTIAL`, and followed
     * when the file is rotated). A caller's own value of that header is
     * dropped. Null forwards the caller's headers as they are.
     */
    readonly credential: { readonly header: string; readonly file: string } | null;
    readonly system: string;
    readonly environment: string;
    readonly timeoutMs: number;
    readonly maxResponseBytes: number;
  };
  readonly authority: {
    readonly kind: AuthorityKind;
    readonly endpoint: string;
    readonly mode: GatewayMode;
    readonly failurePolicy: FailurePolicy;
    readonly tenantId: string;
    readonly timeoutMs: number;
    readonly allowInsecureLoopback: boolean;
    /**
     * The key is a workspace an example provisioned without an account, which
     * the authority evaluates in shadow only; enforcement needs an owned key.
     */
    readonly provisional: boolean;
  };
  readonly interception: {
    readonly http: boolean;
    readonly routes: readonly RouteConfig[];
    readonly unmatched: UnmatchedPolicy;
    readonly maxBodyBytes: number;
    /** The largest JSON body embedded in the intent for policy to read; 0 embeds none. */
    readonly maxEmbeddedBodyBytes: number;
    /** A request header whose value names the calling principal; carried, never verified. */
    readonly principalHeader: string | null;
    /**
     * The API intent profile (`agent-safe.profile.api/1`) the gateway governs by, after any
     * explicit route: its operations name the action and the facts. Null governs by routes only.
     */
    readonly profile: string | null;
    /** `FACTS`: the authority receives the profile's operation and facts, never the request. */
    readonly privacy: PrivacyMode;
    /**
     * Refuse a call the profile cannot check: a read no profile operation
     * names, a path beneath one, and a write neither a route nor an operation
     * names (a batch included), whatever `unmatched` says. On by default when
     * the gateway pins subjects with a profile.
     */
    readonly refuseUnknownReads: boolean;
  };
  /** Subject-bound sessions: null when the gateway pins no subject. */
  readonly subject: SubjectConfig | null;
  readonly actor: { readonly id: string; readonly type: string; readonly runtime: string };
  /**
   * What the operator calls this enforcement boundary. Null leaves it to be
   * derived from the configuration, which is stable across restarts; see
   * `boundary/BoundaryIdentity.ts`.
   */
  readonly boundary: { readonly id: string | null };
  readonly intentTtlSeconds: number;
  readonly escalation: EscalationConfig;
  readonly evidence: { readonly enabled: boolean; readonly journalDir: string | null };
  readonly output: { readonly format: OutputFormat; readonly verbose: boolean };
  readonly production: boolean;
  readonly secrets: { readonly required: readonly SecretName[] };
  /** Where the value of each setting came from, for `agentsafe config`. */
  readonly sources: Readonly<Record<string, ConfigSource>>;
}

export type ConfigSource = "flag" | "environment" | "file" | "credentials" | "default";

const lowerEnum = <T extends readonly [string, ...string[]]>(values: T) =>
  z.preprocess(
    (value) => (typeof value === "string" ? value.trim().toLowerCase() : value),
    z.enum(values),
  );
const routePath = z.string().trim().min(1).max(500).regex(/^\//, "a route path starts with /");
const actionName = z.string().trim().min(1).max(120).regex(ACTION_NAME);
const method = z.preprocess(
  (value) => (typeof value === "string" ? value.trim().toUpperCase() : value),
  z.enum(CONSEQUENTIAL_METHODS),
);
const positiveInt = z.number().int().positive();
const url = z.string().trim().min(1).max(500);

const RouteSchema = z.strictObject({
  path: routePath,
  action: actionName,
  methods: z.array(method).min(1).max(4).optional(),
  policyId: z.string().trim().toLowerCase().pipe(PolicyIdSchema).optional(),
  policyVersion: z.string().trim().pipe(PolicyVersionSchema).optional(),
});

const AuthoritySchema = z.strictObject({
  endpoint: z.union([z.literal("local"), url]).optional(),
  mode: lowerEnum(["shadow", "enforcement"]).optional(),
  failurePolicy: lowerEnum(["failclosed", "failopen"]).optional(),
  tenantId: z.string().uuid().optional(),
  timeoutMs: positiveInt.max(15_000).optional(),
  allowInsecureLoopback: z.boolean().optional(),
});

const PresenceSchema = z.strictObject({
  managed: z.boolean().optional(),
  approverId: z.string().trim().min(1).max(200).optional(),
  approverRole: z.string().trim().min(1).max(200).optional(),
  level: lowerEnum(["standard", "high_confidence"]).optional(),
  methods: z
    .array(lowerEnum(["webauthn", "active_liveness"]))
    .min(1)
    .max(2)
    .optional(),
});

/** The file, `agentsafe.yaml`: `version: 1` and any of these sections; an unknown key is refused by name. */
export const GatewayFileSchema = z.strictObject({
  version: z.literal(1),
  gateway: z
    .strictObject({
      listen: z.string().trim().min(1).max(64).optional(),
      upstream: url.optional(),
      upstreamInsecure: z.boolean().optional(),
      upstreamPublicOnly: z.boolean().optional(),
      upstreamCredential: z
        .strictObject({
          header: z.string().trim().min(1).max(64),
          file: z.string().trim().min(1).max(500),
        })
        .optional(),
      hosted: z.boolean().optional(),
      tenantKeyDigests: z.array(z.string()).optional(),
      rateLimit: z
        .strictObject({
          requestsPerSecond: z.number().positive().max(10_000),
          burst: z.number().int().min(1).max(100_000),
        })
        .optional(),
      upstreamTimeoutMs: positiveInt.max(120_000).optional(),
      system: z.string().trim().min(1).max(200).optional(),
      environment: z.string().trim().min(1).max(200).optional(),
    })
    .optional(),
  authority: AuthoritySchema.optional(),
  /** The same section under the name the first quickstart used. */
  decionis: AuthoritySchema.optional(),
  interception: z
    .strictObject({
      http: z.boolean().optional(),
      routes: z.array(RouteSchema).max(200).optional(),
      unmatched: lowerEnum(["govern", "passthrough"]).optional(),
      maxBodyBytes: positiveInt.max(MAX_BODY_BYTES).optional(),
      // 0 embeds no body at all: the authority sees its digest, size and type only.
      maxEmbeddedBodyBytes: z.number().int().min(0).max(MAX_BODY_BYTES).optional(),
      principalHeader: z
        .string()
        .trim()
        .min(1)
        .max(128)
        .regex(/^[\w!#$%&'*+.^`|~-]+$/)
        .optional(),
      profile: z.string().trim().min(1).max(120).optional(),
      // facts: the authority receives the profile's operation and facts, never the request.
      privacy: lowerEnum(["full", "facts"]).optional(),
      // true: a read no profile operation names is refused; needs subject and a profile.
      refuseUnknownReads: z.boolean().optional(),
    })
    .optional(),
  subject: z
    .strictObject({
      issuer: z.string().trim().min(1).max(500),
      audience: z.string().trim().min(1).max(500),
      jwksFile: z.string().trim().min(1).max(500).optional(),
      jwksUrl: url.optional(),
      claim: z
        .string()
        .trim()
        .min(1)
        .max(200)
        .regex(/^[^\s"\\]+$/)
        .optional(),
      sessionTtlSeconds: z.number().int().min(60).max(3_600).optional(),
    })
    .optional(),
  actor: z
    .strictObject({
      id: z.string().trim().min(1).max(200).optional(),
      type: z.string().trim().min(1).max(200).optional(),
    })
    .optional(),
  boundary: z
    .strictObject({
      id: z
        .string()
        .trim()
        .min(1)
        .max(200)
        .regex(/^[a-z0-9][\w.:/-]*$/i)
        .optional(),
    })
    .optional(),
  intentTtlSeconds: positiveInt.max(300).optional(),
  presence: PresenceSchema.optional(),
  evidence: z
    .strictObject({
      enabled: z.boolean().optional(),
      journalDir: z.string().trim().min(1).max(500).optional(),
    })
    .optional(),
  output: z
    .strictObject({
      format: lowerEnum(["human", "json"]).optional(),
      verbose: z.boolean().optional(),
    })
    .optional(),
});

export type GatewayFile = z.infer<typeof GatewayFileSchema>;

/** What the command line may override; every field is optional and wins over everything else. */
export interface GatewayFlags {
  readonly upstream?: string;
  readonly port?: number;
  readonly listen?: string;
  readonly mode?: string;
  readonly failurePolicy?: string;
  readonly authority?: string;
  readonly verbose?: boolean;
  readonly json?: boolean;
}

/** A stored login: the key, and the organization and endpoint it belongs to. */
export interface StoredCredentials {
  readonly apiKey: string;
  readonly tenantId: string | null;
  readonly endpoint: string | null;
  /** True for a workspace an example provisioned without an account; absent for a login. */
  readonly provisional?: boolean;
}

export interface GatewayConfigInput {
  readonly flags?: GatewayFlags;
  readonly env: Readonly<Record<string, string | undefined>>;
  /** The parsed file, or null when there is none. */
  readonly file?: unknown;
  /** What `agentsafe login` stored, read by the command outside production; null when absent. */
  readonly credentials?: StoredCredentials | null;
  /** This package's version, for the actor's runtime. */
  readonly version: string;
}

/** A refusal to start that names the setting and never its value. */
export class GatewayConfigError extends Error {
  public constructor(
    public readonly code: string,
    public readonly setting: string,
    detail: string | null = null,
  ) {
    super(`${code}: ${setting}${detail === null ? "" : ` (${detail})`}`);
    this.name = "GatewayConfigError";
  }
}

const ENVIRONMENT = {
  listen: "AGENTSAFE_LISTEN",
  port: "PORT",
  upstream: "AGENTSAFE_UPSTREAM",
  upstreamInsecure: "AGENTSAFE_UPSTREAM_INSECURE",
  upstreamPublicOnly: "AGENTSAFE_UPSTREAM_PUBLIC_ONLY",
  upstreamProofRequired: "AGENTSAFE_UPSTREAM_PROOF_REQUIRED",
  hosted: "AGENTSAFE_HOSTED_GATEWAY",
  hostedTenant: "AGENTSAFE_HOSTED_TENANT",
  hostedDedicated: "AGENTSAFE_HOSTED_DEDICATED",
  upstreamCredentialHeader: "AGENTSAFE_UPSTREAM_CREDENTIAL_HEADER",
  upstreamCredentialFile: "AGENTSAFE_UPSTREAM_CREDENTIAL_FILE",
  tenantKeyDigests: "AGENTSAFE_TENANT_KEY_DIGESTS",
  rateLimitRps: "AGENTSAFE_RATE_LIMIT_RPS",
  rateLimitBurst: "AGENTSAFE_RATE_LIMIT_BURST",
  upstreamTimeoutMs: "AGENTSAFE_UPSTREAM_TIMEOUT_MS",
  system: "AGENTSAFE_UPSTREAM_SYSTEM",
  environment: "AGENTSAFE_ENVIRONMENT",
  authority: "AGENTSAFE_AUTHORITY",
  mode: "AGENTSAFE_MODE",
  legacyMode: "DECIONIS_MODE",
  failurePolicy: "AGENTSAFE_FAILURE_POLICY",
  unmatched: "AGENTSAFE_UNMATCHED",
  endpoint: "DECIONIS_API_URL",
  tenantId: "DECIONIS_TENANT_ID",
  timeoutMs: "DECIONIS_TIMEOUT_MS",
  allowInsecureLoopback: "DECIONIS_ALLOW_INSECURE_LOOPBACK",
  apiKey: "DECIONIS_API_KEY",
  logLevel: "AGENTSAFE_LOG_LEVEL",
  logFormat: "AGENTSAFE_LOG_FORMAT",
  evidenceDir: "AGENTSAFE_EVIDENCE_DIR",
  actorId: "AGENTSAFE_ACTOR_ID",
  actorType: "AGENTSAFE_ACTOR_TYPE",
  boundaryId: "AGENTSAFE_BOUNDARY_ID",
  principalHeader: "AGENTSAFE_PRINCIPAL_HEADER",
  profile: "AGENTSAFE_PROFILE",
  privacy: "AGENTSAFE_PRIVACY",
  presenceApproverId: "PRESENCE_APPROVER_ID",
  presenceApproverRole: "PRESENCE_APPROVER_ROLE",
  presenceLevel: "PRESENCE_VERIFICATION_LEVEL",
  presenceMethods: "PRESENCE_VERIFICATION_METHODS",
  presenceManaged: "AGENTSAFE_PRESENCE_MANAGED",
} as const;

/** Variables the commands read outside the loader: the file, the login directory, the metrics token. */
const COMMAND_ENVIRONMENT = [
  "AGENTSAFE_CONFIG",
  "AGENTSAFE_HOME",
  "AGENTSAFE_METRICS_TOKEN",
  "AGENTSAFE_TENANT_REGISTRY",
  "AGENTSAFE_HOST_TENANT",
  "AGENTSAFE_TLS_CERT_FILE",
  "AGENTSAFE_TLS_KEY_FILE",
  "AGENTSAFE_REDIRECT_LISTEN",
  "AGENTSAFE_APEX_PAGE",
] as const;

/** Every variable the gateway and its commands read, for the reference page. */
export const GATEWAY_ENVIRONMENT: readonly string[] = [
  ...Object.values(ENVIRONMENT),
  ...COMMAND_ENVIRONMENT,
  "DECIONIS_API_KEY_FILE",
  "NODE_ENV",
  "NO_COLOR",
];

/**
 * One value with where it came from. The layers are consulted highest first
 * and the first one that has the setting wins; a layer that has it but
 * cannot parse it is a refusal, not a fall-through, so a typo never lands on
 * a default silently.
 */
interface Resolved<T> {
  readonly value: T;
  readonly source: ConfigSource;
}

type Layer<T> = { readonly source: ConfigSource; readonly raw: T | undefined };

function pick<T>(layers: readonly Layer<T>[], fallback: T): Resolved<T> {
  for (const layer of layers) {
    if (layer.raw !== undefined) return { value: layer.raw, source: layer.source };
  }
  return { value: fallback, source: "default" };
}

/** `host:port`, `:port` (every interface) or a bare port; anything else is refused by setting. */
export function parseListen(value: string, setting: string): { host: string; port: number } {
  const trimmed = value.trim();
  const separator = trimmed.lastIndexOf(":");
  const host = separator === -1 ? "" : trimmed.slice(0, separator).replace(/^\[|\]$/g, "");
  const port = Number(separator === -1 ? trimmed : trimmed.slice(separator + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new GatewayConfigError("CONFIG_INVALID", setting, "host:port");
  }
  return { host: host === "" ? "0.0.0.0" : host, port };
}

function parseBoolean(value: string | undefined, setting: string): boolean | undefined {
  if (value === undefined) return undefined;
  const lower = value.trim().toLowerCase();
  if (lower === "true" || lower === "1" || lower === "yes") return true;
  if (lower === "false" || lower === "0" || lower === "no") return false;
  throw new GatewayConfigError("CONFIG_INVALID", setting, "true or false");
}

function parseInteger(value: string | undefined, setting: string, max: number): number | undefined {
  if (value === undefined) return undefined;
  if (!/^\d{1,9}$/.test(value.trim())) {
    throw new GatewayConfigError("CONFIG_INVALID", setting, `an integer up to ${max}`);
  }
  const parsed = Number(value.trim());
  if (parsed < 1 || parsed > max) {
    throw new GatewayConfigError("CONFIG_INVALID", setting, `an integer up to ${max}`);
  }
  return parsed;
}

function parseMode(value: string | undefined, setting: string): GatewayMode | undefined {
  if (value === undefined) return undefined;
  const upper = value.trim().toUpperCase();
  if (upper === "SHADOW") return "SHADOW";
  if (upper === "ENFORCE" || upper === "ENFORCEMENT") return "ENFORCEMENT";
  throw new GatewayConfigError("CONFIG_INVALID", setting, "shadow or enforcement");
}

function parseFailurePolicy(value: string | undefined, setting: string): FailurePolicy | undefined {
  if (value === undefined) return undefined;
  const lower = value.trim().toLowerCase().replace(/[_-]/g, "");
  if (lower === "failclosed") return "FAIL_CLOSED";
  if (lower === "failopen") return "FAIL_OPEN";
  throw new GatewayConfigError("CONFIG_INVALID", setting, "failClosed or failOpen");
}

function parseAuthority(value: string | undefined, setting: string): AuthorityKind | undefined {
  if (value === undefined) return undefined;
  const lower = value.trim().toLowerCase();
  if (lower === "local" || lower === "demo") return "LOCAL";
  if (lower === "decionis" || lower === "hosted") return "DECIONIS";
  throw new GatewayConfigError("CONFIG_INVALID", setting, "local or decionis");
}

function parseUnmatched(value: string | undefined, setting: string): UnmatchedPolicy | undefined {
  if (value === undefined) return undefined;
  const lower = value.trim().toLowerCase();
  if (lower === "govern") return "GOVERN";
  if (lower === "passthrough") return "PASSTHROUGH";
  throw new GatewayConfigError("CONFIG_INVALID", setting, "govern or passthrough");
}

function parsePrivacy(value: string | undefined, setting: string): PrivacyMode | undefined {
  if (value === undefined) return undefined;
  const lower = value.trim().toLowerCase();
  if (lower === "full") return "FULL";
  if (lower === "facts") return "FACTS";
  throw new GatewayConfigError("CONFIG_INVALID", setting, "full or facts");
}

function parseMethods(
  value: string | undefined,
  setting: string,
): readonly VerificationMethod[] | undefined {
  if (value === undefined) return undefined;
  const methods = value
    .split(",")
    .map((entry) => entry.trim().toUpperCase())
    .filter((entry) => entry !== "");
  for (const entry of methods) {
    if (entry !== "WEBAUTHN" && entry !== "ACTIVE_LIVENESS") {
      throw new GatewayConfigError("CONFIG_INVALID", setting, "WEBAUTHN, ACTIVE_LIVENESS");
    }
  }
  if (methods.length === 0) throw new GatewayConfigError("CONFIG_INVALID", setting);
  return methods as VerificationMethod[];
}

/**
 * Resolves the gateway's configuration. Precedence is the command line,
 * then the environment, then the file, then the stored login for the
 * credential alone, then the defaults; each setting says which layer it
 * came from. Every refusal names the setting and never a value.
 */
export class GatewayConfigLoader {
  public static load(input: GatewayConfigInput): GatewayConfig {
    const flags = input.flags ?? {};
    const env = input.env;
    const production = env["NODE_ENV"] === "production";
    const file = GatewayConfigLoader.file(input.file);
    const credentials = production ? null : (input.credentials ?? null);
    const sources: Record<string, ConfigSource> = {};
    const authoritySection = file?.authority ?? file?.decionis;
    if (file?.authority !== undefined && file.decionis !== undefined) {
      throw new GatewayConfigError("CONFIG_INVALID", "authority", "given twice, as decionis too");
    }
    const resolve = <T>(name: string, layers: readonly Layer<T>[], fallback: T): T => {
      const picked = pick(layers, fallback);
      sources[name] = picked.source;
      return picked.value;
    };

    // The listener: a flag names a port, a variable or the file a host:port.
    const listenFromFlag =
      flags.listen !== undefined
        ? parseListen(flags.listen, "--listen")
        : flags.port !== undefined
          ? { host: DEFAULT_LISTEN.host, port: flags.port }
          : undefined;
    const listenFromEnv =
      env[ENVIRONMENT.listen] !== undefined
        ? parseListen(env[ENVIRONMENT.listen] ?? "", ENVIRONMENT.listen)
        : env[ENVIRONMENT.port] !== undefined
          ? {
              host: DEFAULT_LISTEN.host,
              port: parseInteger(env[ENVIRONMENT.port], ENVIRONMENT.port, 65_535) ?? 0,
            }
          : undefined;
    const listen = resolve<{ host: string; port: number }>(
      "listen",
      [
        { source: "flag", raw: listenFromFlag },
        { source: "environment", raw: listenFromEnv },
        {
          source: "file",
          raw:
            file?.gateway?.listen === undefined
              ? undefined
              : parseListen(file.gateway.listen, "gateway.listen"),
        },
      ],
      { ...DEFAULT_LISTEN },
    );

    const upstreamRaw = resolve<string | null>(
      "upstream",
      [
        { source: "flag", raw: flags.upstream },
        { source: "environment", raw: env[ENVIRONMENT.upstream] },
        { source: "file", raw: file?.gateway?.upstream },
      ],
      null,
    );
    if (upstreamRaw === null) {
      throw new GatewayConfigError(
        "CONFIG_MISSING",
        "upstream",
        "--upstream, AGENTSAFE_UPSTREAM or gateway.upstream",
      );
    }
    const upstreamInsecure = resolve(
      "upstream.insecure",
      [
        {
          source: "environment",
          raw: parseBoolean(env[ENVIRONMENT.upstreamInsecure], ENVIRONMENT.upstreamInsecure),
        },
        { source: "file", raw: file?.gateway?.upstreamInsecure },
      ],
      false,
    );
    const upstreamUrl = GatewayConfigLoader.upstreamUrl(upstreamRaw, upstreamInsecure);
    const hosted = resolve(
      "hosted",
      [
        {
          source: "environment",
          raw: parseBoolean(env[ENVIRONMENT.hosted], ENVIRONMENT.hosted),
        },
        { source: "file", raw: file?.gateway?.hosted },
      ],
      false,
    );
    // A hosted gateway's upstream is its tenant's choice, so it is public-only
    // whatever else says; the setting is still read, so a bad value is named.
    const upstreamPublicOnly =
      resolve(
        "upstream.publicOnly",
        [
          {
            source: "environment",
            raw: parseBoolean(env[ENVIRONMENT.upstreamPublicOnly], ENVIRONMENT.upstreamPublicOnly),
          },
          { source: "file", raw: file?.gateway?.upstreamPublicOnly },
        ],
        false,
      ) || hosted;
    // A public-only upstream is reached over TLS at a public name, or not at
    // all. An address written as the host is checked here, because connecting
    // to one resolves nothing, so the guarded egress's address check never runs.
    if (upstreamPublicOnly) {
      const host = new URL(upstreamUrl).hostname;
      if (!upstreamUrl.startsWith("https:")) {
        throw new GatewayConfigError(
          "CONFIG_INVALID",
          "upstream",
          "a public-only upstream must be https",
        );
      }
      if (EgressPolicy.isLoopbackHost(host) || EgressPolicy.hostAddressRefused(host, true)) {
        throw new GatewayConfigError(
          "CONFIG_INVALID",
          "upstream",
          "a public-only upstream must name a public host",
        );
      }
    }

    const keyFromCredentials =
      credentials !== null &&
      env[ENVIRONMENT.apiKey] === undefined &&
      env[`${ENVIRONMENT.apiKey}_FILE`] === undefined;
    const apiKeyPresent =
      env[ENVIRONMENT.apiKey] !== undefined ||
      env[`${ENVIRONMENT.apiKey}_FILE`] !== undefined ||
      credentials !== null;
    const endpointGiven =
      authoritySection?.endpoint !== undefined && authoritySection.endpoint !== "local";
    const kind = resolve<AuthorityKind>(
      "authority.kind",
      [
        { source: "flag", raw: parseAuthority(flags.authority, "--authority") },
        {
          source: "environment",
          raw: parseAuthority(env[ENVIRONMENT.authority], ENVIRONMENT.authority),
        },
        { source: "file", raw: authoritySection?.endpoint === "local" ? "LOCAL" : undefined },
        {
          source: apiKeyPresent ? (keyFromCredentials ? "credentials" : "environment") : "file",
          raw: apiKeyPresent || endpointGiven ? "DECIONIS" : undefined,
        },
      ],
      "LOCAL",
    );
    if (kind === "LOCAL" && production) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "authority",
        "the local demo authority is refused in production; set DECIONIS_API_KEY",
      );
    }
    // Shadow is the default beside a real authority, because it changes
    // nothing downstream; the demo authority governs nothing real, so it
    // enforces by default and the terminal shows a refusal on the first try.
    const mode = resolve<GatewayMode>(
      "authority.mode",
      [
        { source: "flag", raw: parseMode(flags.mode, "--mode") },
        { source: "environment", raw: parseMode(env[ENVIRONMENT.mode], ENVIRONMENT.mode) },
        {
          source: "environment",
          raw: parseMode(env[ENVIRONMENT.legacyMode], ENVIRONMENT.legacyMode),
        },
        { source: "file", raw: parseMode(authoritySection?.mode, "authority.mode") },
      ],
      kind === "LOCAL" ? "ENFORCEMENT" : "SHADOW",
    );
    // A workspace an example provisioned without an account holds a key the
    // authority accepts in shadow only; starting it in enforcement would fail
    // every action closed, so the refusal is at start, by name.
    const provisional =
      kind === "DECIONIS" && keyFromCredentials && credentials.provisional === true;
    if (provisional && mode === "ENFORCEMENT") {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "authority.mode",
        "the stored login is a provisional workspace, which evaluates in shadow only; run agentsafe login with a key from your Decionis organization to enforce",
      );
    }
    const failurePolicy = resolve<FailurePolicy>(
      "authority.failurePolicy",
      [
        { source: "flag", raw: parseFailurePolicy(flags.failurePolicy, "--failure-policy") },
        {
          source: "environment",
          raw: parseFailurePolicy(env[ENVIRONMENT.failurePolicy], ENVIRONMENT.failurePolicy),
        },
        {
          source: "file",
          raw: parseFailurePolicy(authoritySection?.failurePolicy, "authority.failurePolicy"),
        },
      ],
      "FAIL_CLOSED",
    );
    const endpointRaw = resolve<string>(
      "authority.endpoint",
      [
        { source: "environment", raw: env[ENVIRONMENT.endpoint] },
        { source: "file", raw: endpointGiven ? authoritySection?.endpoint : undefined },
        { source: "credentials", raw: credentials?.endpoint ?? undefined },
      ],
      DEFAULT_AUTHORITY_ENDPOINT,
    );
    const allowInsecureLoopback = resolve(
      "authority.allowInsecureLoopback",
      [
        {
          source: "environment",
          raw: parseBoolean(
            env[ENVIRONMENT.allowInsecureLoopback],
            ENVIRONMENT.allowInsecureLoopback,
          ),
        },
        { source: "file", raw: authoritySection?.allowInsecureLoopback },
      ],
      false,
    );
    if (allowInsecureLoopback && production) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        ENVIRONMENT.allowInsecureLoopback,
        "forbidden in production",
      );
    }
    const endpoint =
      kind === "LOCAL"
        ? "local"
        : GatewayConfigLoader.authorityUrl(
            endpointRaw,
            "authority.endpoint",
            allowInsecureLoopback,
          );
    const tenantRaw = resolve<string | null>(
      "authority.tenantId",
      [
        { source: "environment", raw: env[ENVIRONMENT.tenantId]?.trim() },
        { source: "file", raw: authoritySection?.tenantId },
        { source: "credentials", raw: credentials?.tenantId ?? undefined },
      ],
      null,
    );
    if (kind === "DECIONIS" && !apiKeyPresent) {
      throw new GatewayConfigError(
        "CONFIG_MISSING",
        ENVIRONMENT.apiKey,
        "a Decionis key, or run agentsafe login",
      );
    }
    if (kind === "DECIONIS" && tenantRaw === null) {
      throw new GatewayConfigError(
        "CONFIG_MISSING",
        ENVIRONMENT.tenantId,
        "the key's organization id",
      );
    }
    if (kind === "DECIONIS" && !z.string().uuid().safeParse(tenantRaw).success) {
      throw new GatewayConfigError("CONFIG_INVALID", ENVIRONMENT.tenantId, "a UUID");
    }
    const tenantId = kind === "LOCAL" ? LOCAL_TENANT_ID : (tenantRaw ?? LOCAL_TENANT_ID);
    const timeoutMs = resolve(
      "authority.timeoutMs",
      [
        {
          source: "environment",
          raw: parseInteger(env[ENVIRONMENT.timeoutMs], ENVIRONMENT.timeoutMs, 15_000),
        },
        { source: "file", raw: authoritySection?.timeoutMs },
      ],
      DEFAULT_TIMEOUT_MS,
    );

    const routes = (file?.interception?.routes ?? []).map((route): RouteConfig => ({
      path: route.path,
      action: route.action,
      methods: route.methods ?? [...CONSEQUENTIAL_METHODS],
      ...(route.policyId === undefined ? {} : { policyId: route.policyId }),
      ...(route.policyVersion === undefined ? {} : { policyVersion: route.policyVersion }),
    }));
    sources["interception.routes"] = file?.interception?.routes === undefined ? "default" : "file";
    const unmatched = resolve<UnmatchedPolicy>(
      "interception.unmatched",
      [
        {
          source: "environment",
          raw: parseUnmatched(env[ENVIRONMENT.unmatched], ENVIRONMENT.unmatched),
        },
        {
          source: "file",
          raw: parseUnmatched(file?.interception?.unmatched, "interception.unmatched"),
        },
      ],
      "GOVERN",
    );
    const maxBodyBytes = resolve(
      "interception.maxBodyBytes",
      [{ source: "file", raw: file?.interception?.maxBodyBytes }],
      DEFAULT_MAX_BODY_BYTES,
    );
    const maxEmbeddedBodyBytes = resolve(
      "interception.maxEmbeddedBodyBytes",
      [{ source: "file", raw: file?.interception?.maxEmbeddedBodyBytes }],
      Math.min(DEFAULT_MAX_EMBEDDED_BODY_BYTES, maxBodyBytes),
    );
    if (maxEmbeddedBodyBytes > maxBodyBytes) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "interception.maxEmbeddedBodyBytes",
        "at most interception.maxBodyBytes",
      );
    }
    const principalHeader = resolve<string | null>(
      "interception.principalHeader",
      [
        { source: "environment", raw: env[ENVIRONMENT.principalHeader]?.trim() },
        { source: "file", raw: file?.interception?.principalHeader },
      ],
      null,
    );

    const profile = resolve<string | null>(
      "interception.profile",
      [
        { source: "environment", raw: env[ENVIRONMENT.profile]?.trim() || undefined },
        { source: "file", raw: file?.interception?.profile },
      ],
      null,
    );
    if (profile !== null && ApiProfiles.get(profile) === null) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "interception.profile",
        `one of ${ApiProfiles.ids().join(", ")}`,
      );
    }

    const privacy = resolve<PrivacyMode>(
      "interception.privacy",
      [
        { source: "environment", raw: parsePrivacy(env[ENVIRONMENT.privacy], ENVIRONMENT.privacy) },
        {
          source: "file",
          raw: parsePrivacy(file?.interception?.privacy, "interception.privacy"),
        },
      ],
      "FULL",
    );
    if (privacy === "FACTS") {
      GatewayConfigLoader.factsOnly(
        profile,
        routes,
        principalHeader,
        sources["interception.unmatched"] === "default" ? null : unmatched,
      );
    }

    const subject = GatewayConfigLoader.subject(file, allowInsecureLoopback, sources);
    // Scoping is only as good as what it covers, so pinning subjects with a
    // profile refuses what the profile cannot check unless the file says not.
    const refuseUnknownReads = resolve(
      "interception.refuseUnknownReads",
      [{ source: "file", raw: file?.interception?.refuseUnknownReads }],
      subject !== null && profile !== null,
    );
    if (refuseUnknownReads && (subject === null || profile === null)) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "interception.refuseUnknownReads",
        "needs subject and interception.profile: reads are checked against a session",
      );
    }

    // The tenant key and the subject session headers are the gateway's own
    // credentials: they are stripped before forwarding, and the value of a
    // principal header is sent to the authority, so none of them can be the
    // header that names a principal.
    const ownCredential = [TENANT_KEY_HEADER, SESSION_HEADER, SUBJECT_TOKEN_HEADER].find(
      (header) => header === principalHeader?.toLowerCase(),
    );
    if (ownCredential !== undefined) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "interception.principalHeader",
        `${ownCredential} is the gateway's own credential`,
      );
    }
    const tenantKeys = GatewayConfigLoader.tenantKeys(
      resolve<readonly string[] | null>(
        "tenantKeyDigests",
        [
          {
            source: "environment",
            raw: env[ENVIRONMENT.tenantKeyDigests]
              ?.split(",")
              .map((value) => value.trim())
              .filter((value) => value !== ""),
          },
          { source: "file", raw: file?.gateway?.tenantKeyDigests },
        ],
        null,
      ) ?? [],
    );
    const hostedTenant = env[ENVIRONMENT.hostedTenant]?.trim() || null;
    if (hostedTenant !== null && (!hosted || !HOSTED_TENANT.test(hostedTenant))) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        ENVIRONMENT.hostedTenant,
        "a lower-case DNS label, on a hosted gateway",
      );
    }
    GatewayConfigLoader.requireTenantKey(tenantKeys, hosted);
    const hostedDedicated = resolve(
      "hostedDedicated",
      [
        {
          source: "environment",
          raw: parseBoolean(env[ENVIRONMENT.hostedDedicated], ENVIRONMENT.hostedDedicated),
        },
      ],
      false,
    );
    if (hostedDedicated && !hosted) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        ENVIRONMENT.hostedDedicated,
        "on a hosted gateway",
      );
    }
    // The proof binds the hosted tenant and the organization its key belongs
    // to, so it means nothing on a gateway that has neither.
    const proofRequired = resolve(
      "upstream.proofRequired",
      [
        {
          source: "environment",
          raw: parseBoolean(
            env[ENVIRONMENT.upstreamProofRequired],
            ENVIRONMENT.upstreamProofRequired,
          ),
        },
      ],
      false,
    );
    if (proofRequired && (!hosted || hostedTenant === null || kind !== "DECIONIS")) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        ENVIRONMENT.upstreamProofRequired,
        `a hosted gateway with ${ENVIRONMENT.hostedTenant} and a Decionis organization in ${ENVIRONMENT.tenantId}`,
      );
    }

    const credential = GatewayConfigLoader.upstreamCredential(env, file, principalHeader, resolve);
    // A gateway that holds the upstream's credential is the agent's only way
    // in, so with subjects pinned, a call it cannot check is never let through.
    if (credential !== null && subject !== null && !refuseUnknownReads) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "interception.refuseUnknownReads",
        "a gateway that holds the upstream credential and pins subjects refuses what it cannot check",
      );
    }
    // Hosted enforcement is the tenant's opt-in, and runs only where every
    // control its design asks for is on (design.agentsafe-hosted-shadow.md
    // §14): a process of its own, a Decionis organization, failing closed, a
    // proven upstream, a credential the gateway holds in place of the agent,
    // and evidence written before anything executes.
    if (hosted && mode === "ENFORCEMENT") {
      GatewayConfigLoader.requireHostedEnforcement({
        dedicated: hostedDedicated,
        tenant: hostedTenant,
        kind,
        failurePolicy,
        proofRequired,
        credential,
        evidence: file?.evidence?.enabled ?? true,
      });
    }

    const rateLimit =
      resolve<RateLimit | null>(
        "rateLimit",
        [
          { source: "environment", raw: GatewayConfigLoader.rateLimitFromEnvironment(env) },
          { source: "file", raw: file?.gateway?.rateLimit },
        ],
        null,
      ) ?? (hosted ? HOSTED_DEFAULT_RATE_LIMIT : null);

    const escalation = GatewayConfigLoader.escalation(file, env, mode, kind, resolve);
    const required: SecretName[] = [];
    if (kind === "DECIONIS") required.push("DECIONIS_API_KEY");
    if (credential !== null) required.push("DOWNSTREAM_CREDENTIAL");
    if (escalation.mode === "DIRECT") required.push("PRESENCE_API_KEY");

    const verbose = resolve(
      "output.verbose",
      [
        { source: "flag", raw: flags.verbose === true ? true : undefined },
        {
          source: "environment",
          raw:
            env[ENVIRONMENT.logLevel] === undefined
              ? undefined
              : env[ENVIRONMENT.logLevel]?.trim().toLowerCase() === "debug",
        },
        { source: "file", raw: file?.output?.verbose },
      ],
      false,
    );
    const format = resolve<OutputFormat>(
      "output.format",
      [
        { source: "flag", raw: flags.json === true ? "JSON" : undefined },
        {
          source: "environment",
          raw:
            env[ENVIRONMENT.logFormat] === undefined
              ? undefined
              : env[ENVIRONMENT.logFormat]?.trim().toLowerCase() === "json"
                ? "JSON"
                : "HUMAN",
        },
        {
          source: "file",
          raw:
            file?.output?.format === undefined
              ? undefined
              : file.output.format === "json"
                ? "JSON"
                : "HUMAN",
        },
      ],
      production ? "JSON" : "HUMAN",
    );

    return {
      listen,
      hosted,
      hostedTenant,
      hostedDedicated,
      tenantKeys,
      rateLimit,
      upstream: {
        url: upstreamUrl,
        insecure: upstreamInsecure,
        publicOnly: upstreamPublicOnly,
        proofRequired,
        credential,
        system: resolve(
          "upstream.system",
          [
            { source: "environment", raw: env[ENVIRONMENT.system]?.trim() },
            { source: "file", raw: file?.gateway?.system },
          ],
          new URL(upstreamUrl).host,
        ),
        environment: resolve(
          "upstream.environment",
          [
            { source: "environment", raw: env[ENVIRONMENT.environment]?.trim() },
            { source: "file", raw: file?.gateway?.environment },
          ],
          production ? "production" : "local",
        ),
        timeoutMs: resolve(
          "upstream.timeoutMs",
          [
            {
              source: "environment",
              raw: parseInteger(
                env[ENVIRONMENT.upstreamTimeoutMs],
                ENVIRONMENT.upstreamTimeoutMs,
                120_000,
              ),
            },
            { source: "file", raw: file?.gateway?.upstreamTimeoutMs },
          ],
          DEFAULT_UPSTREAM_TIMEOUT_MS,
        ),
        maxResponseBytes: MAX_BODY_BYTES,
      },
      authority: {
        kind,
        endpoint,
        mode,
        failurePolicy,
        tenantId,
        timeoutMs,
        allowInsecureLoopback,
        provisional,
      },
      boundary: {
        id: resolve<string | null>(
          "boundary.id",
          [
            { source: "environment", raw: env[ENVIRONMENT.boundaryId]?.trim() },
            { source: "file", raw: file?.boundary?.id },
          ],
          null,
        ),
      },
      interception: {
        http: resolve(
          "interception.http",
          [{ source: "file", raw: file?.interception?.http }],
          true,
        ),
        routes,
        unmatched,
        maxBodyBytes,
        maxEmbeddedBodyBytes,
        principalHeader: principalHeader === null ? null : principalHeader.toLowerCase(),
        profile,
        privacy,
        refuseUnknownReads,
      },
      subject,
      actor: {
        id: resolve(
          "actor.id",
          [
            { source: "environment", raw: env[ENVIRONMENT.actorId]?.trim() },
            { source: "file", raw: file?.actor?.id },
          ],
          "agentsafe-gateway",
        ),
        type: resolve(
          "actor.type",
          [
            { source: "environment", raw: env[ENVIRONMENT.actorType]?.trim() },
            { source: "file", raw: file?.actor?.type },
          ],
          "GATEWAY",
        ),
        runtime: `agentsafe/${input.version}`,
      },
      intentTtlSeconds: resolve(
        "intentTtlSeconds",
        [{ source: "file", raw: file?.intentTtlSeconds }],
        DEFAULT_INTENT_TTL_SECONDS,
      ),
      escalation,
      evidence: {
        enabled: resolve(
          "evidence.enabled",
          [{ source: "file", raw: file?.evidence?.enabled }],
          true,
        ),
        journalDir: resolve<string | null>(
          "evidence.journalDir",
          [
            { source: "environment", raw: env[ENVIRONMENT.evidenceDir]?.trim() },
            { source: "file", raw: file?.evidence?.journalDir },
          ],
          null,
        ),
      },
      output: { format, verbose },
      production,
      secrets: { required },
      sources,
    };
  }

  /**
   * The subject section, when there is one: an issuer, an audience and a key
   * set, on disk or at an address the guarded egress fetches. The address is
   * https, or loopback with the authority's loopback allowance.
   */
  private static subject(
    file: GatewayFile | null,
    allowInsecureLoopback: boolean,
    sources: Record<string, ConfigSource>,
  ): SubjectConfig | null {
    const section = file?.subject;
    sources["subject"] = section === undefined ? "default" : "file";
    if (section === undefined) return null;
    if (section.jwksFile === undefined && section.jwksUrl === undefined) {
      throw new GatewayConfigError(
        "CONFIG_MISSING",
        "subject.jwksFile",
        "subject.jwksFile or subject.jwksUrl: the identity provider's keys",
      );
    }
    return {
      issuer: section.issuer,
      audience: section.audience,
      jwksFile: section.jwksFile ?? null,
      jwksUrl:
        section.jwksUrl === undefined
          ? null
          : GatewayConfigLoader.authorityUrl(
              section.jwksUrl,
              "subject.jwksUrl",
              allowInsecureLoopback,
            ),
      claim: section.claim ?? "sub",
      sessionTtlSeconds: section.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS,
    };
  }

  /**
   * Facts-only mode sends the authority a profile's operation and facts, so
   * it governs by a profile alone. Every setting that would put a raw part of
   * the request in front of the authority, or govern a call no operation
   * names, is refused by name rather than quietly overridden: a route (its
   * target is the raw path), a principal header (a raw header value), and an
   * explicit passthrough of unmatched calls (facts-only refuses them).
   */
  private static factsOnly(
    profile: string | null,
    routes: readonly RouteConfig[],
    principalHeader: string | null,
    unmatched: UnmatchedPolicy | null,
  ): void {
    if (profile === null) {
      throw new GatewayConfigError(
        "CONFIG_MISSING",
        "interception.profile",
        "facts-only privacy governs by an API profile's operations",
      );
    }
    if (routes.length > 0) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "interception.routes",
        "facts-only privacy governs by the profile alone; a route sends the raw path",
      );
    }
    if (principalHeader !== null) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "interception.principalHeader",
        "facts-only privacy sends no header value; name the agent in actor.id",
      );
    }
    if (unmatched === "PASSTHROUGH") {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "interception.unmatched",
        "facts-only privacy refuses a call no profile operation names",
      );
    }
  }

  /** The file's shape, refused by the name of the first key that is wrong. */
  private static file(raw: unknown): GatewayFile | null {
    if (raw === null || raw === undefined) return null;
    const parsed = GatewayFileSchema.safeParse(raw);
    if (parsed.success) return parsed.data;
    const issue = parsed.error.issues[0];
    const path = issue === undefined || issue.path.length === 0 ? "version" : issue.path.join(".");
    throw new GatewayConfigError("CONFIG_INVALID", path, issue?.message ?? null);
  }

  /**
   * The upstream is where authorized requests go. TLS is the default; a
   * loopback address may be plain, and anything else may be plain only when
   * the configuration says the network protects that hop.
   */
  /** Both rate variables or neither: a rate without a burst, or the reverse, is refused by name. */
  private static rateLimitFromEnvironment(
    env: Readonly<Record<string, string | undefined>>,
  ): RateLimit | undefined {
    const rps = env[ENVIRONMENT.rateLimitRps]?.trim();
    const burst = env[ENVIRONMENT.rateLimitBurst]?.trim();
    if (rps === undefined && burst === undefined) return undefined;
    const rate = Number(rps);
    if (rps === undefined || rps === "" || !Number.isFinite(rate) || rate <= 0 || rate > 10_000) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        ENVIRONMENT.rateLimitRps,
        "requests per second, above 0 and at most 10000, with AGENTSAFE_RATE_LIMIT_BURST",
      );
    }
    if (
      burst === undefined ||
      !/^\d{1,6}$/.test(burst) ||
      Number(burst) < 1 ||
      Number(burst) > 100_000
    ) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        ENVIRONMENT.rateLimitBurst,
        "a whole number from 1 to 100000, with AGENTSAFE_RATE_LIMIT_RPS",
      );
    }
    return { requestsPerSecond: rate, burst: Number(burst) };
  }

  /**
   * The tenant keys a running gateway may be given in place of its own: held
   * to the same rule as the configuration's, one or two distinct digests,
   * and at least one when it is hosted.
   */
  public static admittedKeys(digests: readonly string[], hosted: boolean): readonly string[] {
    const keys = GatewayConfigLoader.tenantKeys(digests);
    GatewayConfigLoader.requireTenantKey(keys, hosted);
    return keys;
  }

  /**
   * The upstream credential the gateway presents, from the environment or
   * the file: a header and the file holding its value, both or neither. The
   * header is one a credential can travel in without the gateway setting or
   * dropping it, and never one whose value reaches the authority.
   */
  private static upstreamCredential(
    env: Readonly<Record<string, string | undefined>>,
    file: GatewayFile | null,
    principalHeader: string | null,
    resolve: <T>(name: string, layers: readonly Layer<T>[], fallback: T) => T,
  ): { readonly header: string; readonly file: string } | null {
    const header = resolve<string | null>(
      "upstream.credential.header",
      [
        {
          source: "environment",
          raw: env[ENVIRONMENT.upstreamCredentialHeader]?.trim() || undefined,
        },
        { source: "file", raw: file?.gateway?.upstreamCredential?.header },
      ],
      null,
    );
    const path = resolve<string | null>(
      "upstream.credential.file",
      [
        {
          source: "environment",
          raw: env[ENVIRONMENT.upstreamCredentialFile]?.trim() || undefined,
        },
        { source: "file", raw: file?.gateway?.upstreamCredential?.file },
      ],
      null,
    );
    if (header === null && path === null) return null;
    if (header === null || path === null) {
      throw new GatewayConfigError(
        "CONFIG_MISSING",
        header === null ? ENVIRONMENT.upstreamCredentialHeader : ENVIRONMENT.upstreamCredentialFile,
        "an upstream credential needs its header and the file holding its value",
      );
    }
    const name = header.toLowerCase();
    if (
      !HEADER_TOKEN.test(name) ||
      CREDENTIAL_HEADERS_REFUSED.has(name) ||
      CREDENTIAL_PREFIXES_REFUSED.some((prefix) => name.startsWith(prefix)) ||
      name === principalHeader?.toLowerCase()
    ) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "upstream.credential.header",
        "a header the gateway neither sets nor sends to the authority, such as authorization or x-api-key",
      );
    }
    if (!isAbsolute(path)) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "upstream.credential.file",
        "an absolute path",
      );
    }
    return { header: name, file: path };
  }

  /** Every control hosted enforcement needs, refused by the first one missing, by name. */
  private static requireHostedEnforcement(facts: {
    readonly dedicated: boolean;
    readonly tenant: string | null;
    readonly kind: AuthorityKind;
    readonly failurePolicy: FailurePolicy;
    readonly proofRequired: boolean;
    readonly credential: { readonly header: string; readonly file: string } | null;
    readonly evidence: boolean;
  }): void {
    if (!facts.dedicated) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        ENVIRONMENT.hostedDedicated,
        "a hosted gateway enforces only in a process of its own: agentsafe host --tenant",
      );
    }
    if (facts.tenant === null) {
      throw new GatewayConfigError(
        "CONFIG_MISSING",
        ENVIRONMENT.hostedTenant,
        "the tenant a hosted gateway enforces for",
      );
    }
    if (facts.kind !== "DECIONIS") {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "authority",
        "a hosted gateway enforces against a Decionis organization",
      );
    }
    if (facts.failurePolicy !== "FAIL_CLOSED") {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "authority.failurePolicy",
        "a hosted gateway enforces fail-closed",
      );
    }
    if (!facts.proofRequired) {
      throw new GatewayConfigError(
        "CONFIG_MISSING",
        ENVIRONMENT.upstreamProofRequired,
        "a hosted gateway enforces only for an upstream that proves it is the tenant's",
      );
    }
    if (facts.credential === null) {
      throw new GatewayConfigError(
        "CONFIG_MISSING",
        "upstream.credential",
        "a hosted gateway that enforces holds the upstream credential, so the agent cannot go around it",
      );
    }
    if (!facts.evidence) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "evidence.enabled",
        "a hosted gateway that enforces writes evidence before execution",
      );
    }
  }

  /** Hosted, the tenant is the only caller the gateway admits, from day one. */
  private static requireTenantKey(keys: readonly string[], hosted: boolean): void {
    if (hosted && keys.length === 0) {
      throw new GatewayConfigError(
        "CONFIG_MISSING",
        "tenantKeyDigests",
        `${ENVIRONMENT.tenantKeyDigests} or gateway.tenantKeyDigests: a hosted gateway admits only its tenant`,
      );
    }
  }

  /** One or two distinct `sha256:` digests, lower-case hex; anything else is refused by name. */
  private static tenantKeys(digests: readonly string[]): readonly string[] {
    if (
      digests.length > 2 ||
      new Set(digests).size !== digests.length ||
      !digests.every((digest) => TENANT_KEY_DIGEST.test(digest))
    ) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "tenantKeyDigests",
        "one or two distinct sha256:<64 hex> digests",
      );
    }
    return digests;
  }

  private static upstreamUrl(raw: string, insecure: boolean): string {
    let parsed: URL;
    try {
      parsed = new URL(raw.trim());
    } catch {
      throw new GatewayConfigError("CONFIG_INVALID", "upstream", "an absolute http(s) URL");
    }
    if (parsed.username !== "" || parsed.password !== "") {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "upstream",
        "credentials in a URL are refused",
      );
    }
    if (parsed.protocol === "https:") return parsed.href.replace(/\/$/, "");
    if (parsed.protocol !== "http:") {
      throw new GatewayConfigError("CONFIG_INVALID", "upstream", "http or https");
    }
    const loopback =
      parsed.hostname === "localhost" ||
      parsed.hostname === "127.0.0.1" ||
      parsed.hostname === "[::1]";
    if (!loopback && !insecure) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "upstream",
        "plain http off loopback needs gateway.upstreamInsecure: true",
      );
    }
    return parsed.href.replace(/\/$/, "");
  }

  private static authorityUrl(
    raw: string,
    setting: string,
    allowInsecureLoopback: boolean,
  ): string {
    let checked: string;
    try {
      checked = ExecutorConfigLoader.serviceUrl(raw.trim(), setting, allowInsecureLoopback);
    } catch (error) {
      // The executor's message is `CONFIG_INVALID: <key> (<detail>)`; the detail is kept.
      const message = error instanceof Error ? error.message : "";
      const open = message.indexOf("(");
      const detail =
        open === -1 || !message.endsWith(")") ? "an https URL" : message.slice(open + 1, -1);
      throw new GatewayConfigError("CONFIG_INVALID", setting, detail);
    }
    let end = checked.length;
    while (end > 0 && checked.charCodeAt(end - 1) === 47) end -= 1;
    return checked.slice(0, end);
  }

  /**
   * How an `ESCALATE` is resolved, in the executor's own shape. Managed is
   * the gateway's default when Presence is configured at all: Decionis
   * orchestrates the ceremony and this process holds no Presence credential.
   * Direct is available for a deployment that already holds one.
   */
  private static escalation(
    file: GatewayFile | null,
    env: Readonly<Record<string, string | undefined>>,
    mode: GatewayMode,
    kind: AuthorityKind,
    resolve: <T>(name: string, layers: readonly Layer<T>[], fallback: T) => T,
  ): EscalationConfig {
    const managed = resolve(
      "presence.managed",
      [
        {
          source: "environment",
          raw: parseBoolean(env[ENVIRONMENT.presenceManaged], ENVIRONMENT.presenceManaged),
        },
        { source: "file", raw: file?.presence?.managed },
      ],
      false,
    );
    const approverId = resolve<string | null>(
      "presence.approverId",
      [
        { source: "environment", raw: env[ENVIRONMENT.presenceApproverId]?.trim() },
        { source: "file", raw: file?.presence?.approverId },
      ],
      null,
    );
    if (!managed) {
      if (approverId !== null) {
        throw new GatewayConfigError(
          "CONFIG_INVALID",
          "presence.approverId",
          "without presence.managed: true",
        );
      }
      return { mode: "NONE" };
    }
    if (mode === "SHADOW") {
      throw new GatewayConfigError("CONFIG_INVALID", "presence.managed", "shadow never escalates");
    }
    if (kind === "LOCAL") {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "presence.managed",
        "the demo authority holds; it orchestrates nothing",
      );
    }
    if (approverId === null) {
      throw new GatewayConfigError(
        "CONFIG_MISSING",
        "presence.approverId",
        "who approves a managed escalation",
      );
    }
    const level = resolve<"STANDARD" | "HIGH_CONFIDENCE">(
      "presence.level",
      [
        {
          source: "environment",
          raw: GatewayConfigLoader.level(env[ENVIRONMENT.presenceLevel], ENVIRONMENT.presenceLevel),
        },
        { source: "file", raw: GatewayConfigLoader.level(file?.presence?.level, "presence.level") },
      ],
      "STANDARD",
    );
    const methods = resolve<readonly VerificationMethod[]>(
      "presence.methods",
      [
        {
          source: "environment",
          raw: parseMethods(env[ENVIRONMENT.presenceMethods], ENVIRONMENT.presenceMethods),
        },
        {
          source: "file",
          raw:
            file?.presence?.methods === undefined
              ? undefined
              : file.presence.methods.map((entry) => entry.toUpperCase() as VerificationMethod),
        },
      ],
      ["WEBAUTHN"],
    );
    return {
      mode: "MANAGED",
      approverId,
      approverRole: resolve<string | null>(
        "presence.approverRole",
        [
          { source: "environment", raw: env[ENVIRONMENT.presenceApproverRole]?.trim() },
          { source: "file", raw: file?.presence?.approverRole },
        ],
        null,
      ),
      requirements: { methods, level },
    };
  }

  private static level(
    value: string | undefined,
    setting: string,
  ): "STANDARD" | "HIGH_CONFIDENCE" | undefined {
    if (value === undefined) return undefined;
    const upper = value.trim().toUpperCase();
    if (upper === "STANDARD" || upper === "HIGH_CONFIDENCE") return upper;
    throw new GatewayConfigError("CONFIG_INVALID", setting, "STANDARD or HIGH_CONFIDENCE");
  }
}

/** The file `agentsafe init` writes: the smallest working configuration, commented. */
export function renderConfigFile(options: {
  readonly upstream: string;
  readonly listen: string;
  readonly mode: GatewayMode;
  readonly routes: readonly RouteConfig[];
}): string {
  const routes =
    options.routes.length === 0
      ? [
          "  # Name the consequential actions. Until a route names one, every",
          "  # POST, PUT, PATCH and DELETE is governed as http.<method>.",
          "  routes: []",
          "  #  - path: /payments/**",
          "  #    action: payment.create",
          "  #    methods: [POST]",
        ]
      : [
          "  routes:",
          ...options.routes.flatMap((route) => [
            `    - path: ${route.path}`,
            `      action: ${route.action}`,
            `      methods: [${route.methods.join(", ")}]`,
            ...(route.policyId === undefined
              ? []
              : [`      policyId: ${JSON.stringify(route.policyId)}`]),
            ...(route.policyVersion === undefined
              ? []
              : [`      policyVersion: ${JSON.stringify(route.policyVersion)}`]),
          ]),
        ];
  return [
    "# AgentSafe gateway configuration. Precedence: command-line flags, then",
    "# environment variables, then this file, then the defaults.",
    "version: 1",
    "",
    "gateway:",
    `  listen: "${options.listen}"`,
    `  upstream: "${options.upstream}"`,
    "",
    "authority:",
    "  # Without DECIONIS_API_KEY the local demo authority answers, with a",
    "  # synthetic policy on loopback; it is refused in production.",
    "  # endpoint: https://api.decionis.com",
    `  mode: ${options.mode.toLowerCase()}`,
    "  failurePolicy: failClosed",
    "",
    "interception:",
    "  http: true",
    "  # An unsafe request no route names is governed; say passthrough to narrow.",
    "  unmatched: govern",
    ...routes,
    "",
    "presence:",
    "  # Decionis orchestrates the human ceremony on an ESCALATE when this is",
    "  # true and approverId names who approves; the gateway holds otherwise.",
    "  managed: false",
    "",
    "evidence:",
    "  enabled: true",
    "",
  ].join("\n");
}
