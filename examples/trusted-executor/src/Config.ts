import { z } from "zod";
import { Secrets } from "./Secrets.js";

/**
 * Every variable the executor reads, in one list so the README's table and
 * the deployment manifest can be checked against it. Secrets may be given
 * as `<NAME>` or as `<NAME>_FILE`; nothing else has a second spelling.
 */
export const CONFIG_KEYS = [
  "EXECUTOR_MODE",
  "EXECUTOR_BIND_ADDRESS",
  "PORT",
  "EXECUTOR_TENANT_ID",
  "EXECUTOR_ACTOR_ID",
  "EXECUTOR_ACTOR_TYPE",
  "EXECUTOR_ACTOR_RUNTIME",
  "EXECUTOR_CALLER_TOKEN",
  "DECIONIS_API_URL",
  "DECIONIS_API_KEY",
  "DECIONIS_ALLOW_INSECURE_LOOPBACK",
  "DOWNSTREAM_URL",
  "DOWNSTREAM_LOOKUP_URL",
  "DOWNSTREAM_SYSTEM",
  "DOWNSTREAM_OPERATION",
  "DOWNSTREAM_ENVIRONMENT",
  "DOWNSTREAM_CREDENTIAL",
  "DOWNSTREAM_CREDENTIAL_HEADER",
  "DOWNSTREAM_TIMEOUT_MS",
] as const;

export type ConfigKey = (typeof CONFIG_KEYS)[number];

/** Secrets: given as the variable or as `<NAME>_FILE`, never both. */
export const SECRET_KEYS = [
  "EXECUTOR_CALLER_TOKEN",
  "DECIONIS_API_KEY",
  "DOWNSTREAM_CREDENTIAL",
] as const satisfies readonly ConfigKey[];

export type ExecutorMode = "SHADOW" | "ENFORCEMENT";

export interface DownstreamConfig {
  readonly url: string;
  /** Read-only lookup for reconciliation; `{idempotency_key}` is substituted. */
  readonly lookupUrl: string | null;
  readonly system: string;
  readonly operation: string;
  readonly environment: string;
  readonly credential: string;
  readonly credentialHeader: string;
  readonly timeoutMs: number;
}

export interface ExecutorConfig {
  readonly mode: ExecutorMode;
  readonly bindAddress: string;
  readonly port: number;
  readonly tenantId: string;
  readonly actor: { readonly id: string; readonly type: string; readonly runtime?: string };
  readonly callerToken: string;
  readonly authority: {
    readonly baseUrl: string;
    readonly apiKey: string;
    readonly allowInsecureLoopback: boolean;
  };
  readonly downstream: DownstreamConfig;
}

const identifier = z.string().trim().min(1).max(200);
const headerName = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(/^[\w!#$%&'*+.^`|~-]+$/);
const booleanFlag = z.enum(["true", "false"]).optional();

const EnvironmentSchema = z.object({
  EXECUTOR_MODE: z.enum(["SHADOW", "ENFORCEMENT"]),
  EXECUTOR_BIND_ADDRESS: z.string().trim().min(1).max(64),
  PORT: z.coerce.number().int().min(1).max(65_535),
  EXECUTOR_TENANT_ID: z.string().uuid(),
  EXECUTOR_ACTOR_ID: identifier,
  EXECUTOR_ACTOR_TYPE: identifier,
  EXECUTOR_ACTOR_RUNTIME: identifier.optional(),
  DECIONIS_API_URL: z.string().trim().min(1).max(500),
  DECIONIS_ALLOW_INSECURE_LOOPBACK: booleanFlag,
  DOWNSTREAM_URL: z.string().trim().min(1).max(500),
  DOWNSTREAM_LOOKUP_URL: z.string().trim().min(1).max(500).optional(),
  DOWNSTREAM_SYSTEM: identifier,
  DOWNSTREAM_OPERATION: identifier,
  DOWNSTREAM_ENVIRONMENT: identifier,
  DOWNSTREAM_CREDENTIAL_HEADER: headerName,
  DOWNSTREAM_TIMEOUT_MS: z.coerce.number().int().min(1).max(15_000),
});

/**
 * Reads the executor's configuration from an environment map. Every failure
 * is a refusal to start that names the variable, never its value. There is
 * no default for anything that identifies a tenant, a system, a person, or
 * a network path: a deployment states all of it.
 */
export class ExecutorConfigLoader {
  public static load(env: Readonly<Record<string, string | undefined>>): ExecutorConfig {
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
    const lookupUrl = values.DOWNSTREAM_LOOKUP_URL;
    if (lookupUrl !== undefined && !lookupUrl.includes("{idempotency_key}")) {
      throw new Error("CONFIG_INVALID: DOWNSTREAM_LOOKUP_URL (must contain {idempotency_key})");
    }
    return {
      mode: values.EXECUTOR_MODE,
      bindAddress: values.EXECUTOR_BIND_ADDRESS,
      port: values.PORT,
      tenantId: values.EXECUTOR_TENANT_ID,
      actor: {
        id: values.EXECUTOR_ACTOR_ID,
        type: values.EXECUTOR_ACTOR_TYPE,
        ...(values.EXECUTOR_ACTOR_RUNTIME === undefined
          ? {}
          : { runtime: values.EXECUTOR_ACTOR_RUNTIME }),
      },
      callerToken: Secrets.resolve(env, "EXECUTOR_CALLER_TOKEN"),
      authority: {
        baseUrl: ExecutorConfigLoader.serviceUrl(
          values.DECIONIS_API_URL,
          "DECIONIS_API_URL",
          allowInsecureLoopback,
        ),
        apiKey: Secrets.resolve(env, "DECIONIS_API_KEY"),
        allowInsecureLoopback,
      },
      downstream: {
        url: ExecutorConfigLoader.serviceUrl(
          values.DOWNSTREAM_URL,
          "DOWNSTREAM_URL",
          allowInsecureLoopback,
        ),
        lookupUrl:
          lookupUrl === undefined
            ? null
            : ExecutorConfigLoader.serviceUrl(
                lookupUrl,
                "DOWNSTREAM_LOOKUP_URL",
                allowInsecureLoopback,
              ),
        system: values.DOWNSTREAM_SYSTEM,
        operation: values.DOWNSTREAM_OPERATION,
        environment: values.DOWNSTREAM_ENVIRONMENT,
        credential: Secrets.resolve(env, "DOWNSTREAM_CREDENTIAL"),
        credentialHeader: values.DOWNSTREAM_CREDENTIAL_HEADER.toLowerCase(),
        timeoutMs: values.DOWNSTREAM_TIMEOUT_MS,
      },
    };
  }

  /**
   * The same rule the gate applies to the authority address: HTTPS, no
   * credentials in the URL, no query or fragment. Plain HTTP is accepted for
   * loopback only, only when asked for, and never in production.
   */
  private static serviceUrl(value: string, key: string, allowInsecureLoopback: boolean): string {
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
