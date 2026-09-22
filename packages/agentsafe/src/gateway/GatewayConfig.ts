import { z } from "zod";
import {
  ExecutorConfigLoader,
  type EscalationConfig,
  type VerificationMethod,
} from "../config/ExecutorConfig.js";
import type { SecretName } from "../secrets/SecretStore.js";

export type GatewayMode = "SHADOW" | "ENFORCEMENT";
export type FailurePolicy = "FAIL_CLOSED" | "FAIL_OPEN";
export type AuthorityKind = "LOCAL" | "DECIONIS";
export type UnmatchedPolicy = "GOVERN" | "PASSTHROUGH";
export type OutputFormat = "HUMAN" | "JSON";

/** The methods a route governs unless it names its own; a safe method is never consequential. */
export const CONSEQUENTIAL_METHODS = ["POST", "PUT", "PATCH", "DELETE"] as const;
export type ConsequentialMethod = (typeof CONSEQUENTIAL_METHODS)[number];

/** The intent contract's action name: what a route may call the action it governs. */
export const ACTION_NAME = /^[a-z][a-z0-9._:-]*$/;

/** The tenant the demo authority evaluates under; a reserved fixture identifier, never an organization. */
export const LOCAL_TENANT_ID = "00000000-0000-4000-8000-000000000009";
export const DEFAULT_AUTHORITY_ENDPOINT = "https://api.decionis.com";
export const DEFAULT_LISTEN = { host: "127.0.0.1", port: 8080 } as const;
const DEFAULT_TIMEOUT_MS = 4_000;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
const DEFAULT_MAX_EMBEDDED_BODY_BYTES = 64 * 1024;
const DEFAULT_INTENT_TTL_SECONDS = 120;
/** The most a body may be, so the bound is a bound and not a suggestion. */
const MAX_BODY_BYTES = 16 * 1024 * 1024;

export interface RouteConfig {
  readonly path: string;
  readonly action: string;
  readonly methods: readonly ConsequentialMethod[];
}

/**
 * Everything the gateway runs on, resolved from flags, environment, file and
 * defaults in that order, with no secret value in it: the names of the
 * secrets it needs are in `secrets.required`, and the values are opened by a
 * store at start, the way the executor's are.
 */
export interface GatewayConfig {
  readonly listen: { readonly host: string; readonly port: number };
  readonly upstream: {
    readonly url: string;
    /** A plain-HTTP upstream off loopback is refused unless this says the network protects the hop. */
    readonly insecure: boolean;
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
    readonly maxEmbeddedBodyBytes: number;
    /** A request header whose value names the calling principal; carried, never verified. */
    readonly principalHeader: string | null;
  };
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
      maxEmbeddedBodyBytes: positiveInt.max(MAX_BODY_BYTES).optional(),
      principalHeader: z
        .string()
        .trim()
        .min(1)
        .max(128)
        .regex(/^[\w!#$%&'*+.^`|~-]+$/)
        .optional(),
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

function parseListen(value: string, setting: string): { host: string; port: number } {
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

    const escalation = GatewayConfigLoader.escalation(file, env, mode, kind, resolve);
    const required: SecretName[] = [];
    if (kind === "DECIONIS") required.push("DECIONIS_API_KEY");
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
      upstream: {
        url: upstreamUrl,
        insecure: upstreamInsecure,
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
      },
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
