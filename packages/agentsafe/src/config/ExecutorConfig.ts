import { z } from "zod";
import type { PresenceVerificationRequirements } from "@decionis/agent-safe-pipeline";
import { SecretStore } from "../secrets/SecretStore.js";

export type ExecutorMode = "SHADOW" | "ENFORCEMENT";
export type EscalationMode = "NONE" | "DIRECT" | "MANAGED";
export type VerificationMethod = "WEBAUTHN" | "ACTIVE_LIVENESS";
export type VerificationLevel = "STANDARD" | "HIGH_CONFIDENCE";

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
        readonly apiKey: string;
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

export interface ExecutorConfig {
  readonly mode: ExecutorMode;
  readonly bindAddress: string;
  readonly port: number;
  readonly tenantId: string;
  readonly actor: { readonly id: string; readonly type: string; readonly runtime?: string };
  /** How long a proposal stays valid; a ceremony has to finish inside it. */
  readonly intentTtlSeconds: number;
  readonly callerToken: string;
  readonly escalation: EscalationConfig;
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
const booleanFlag = z.enum(["true", "false"]);

const EnvironmentSchema = z.object({
  EXECUTOR_MODE: z.enum(["SHADOW", "ENFORCEMENT"]),
  EXECUTOR_BIND_ADDRESS: z.string().trim().min(1).max(64),
  PORT: z.coerce.number().int().min(1).max(65_535),
  EXECUTOR_TENANT_ID: z.string().uuid(),
  EXECUTOR_ACTOR_ID: identifier,
  EXECUTOR_ACTOR_TYPE: identifier,
  EXECUTOR_ACTOR_RUNTIME: identifier.optional(),
  EXECUTOR_INTENT_TTL_SECONDS: z.coerce.number().int().min(1).max(300),
  EXECUTOR_ESCALATION: z.enum(["NONE", "DIRECT", "MANAGED"]),
  DECIONIS_API_URL: z.string().trim().min(1).max(500),
  DECIONIS_ALLOW_INSECURE_LOOPBACK: booleanFlag.optional(),
  PRESENCE_API_URL: z.string().trim().min(1).max(500).optional(),
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
  DOWNSTREAM_SYSTEM: identifier,
  DOWNSTREAM_OPERATION: identifier,
  DOWNSTREAM_ENVIRONMENT: identifier,
  DOWNSTREAM_CREDENTIAL_HEADER: headerName,
  DOWNSTREAM_TIMEOUT_MS: z.coerce.number().int().min(1).max(15_000),
});

type Environment = z.infer<typeof EnvironmentSchema>;

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
      intentTtlSeconds: values.EXECUTOR_INTENT_TTL_SECONDS,
      callerToken: SecretStore.resolve(env, "EXECUTOR_CALLER_TOKEN"),
      escalation: ExecutorConfigLoader.escalation(env, values, allowInsecureLoopback),
      authority: {
        baseUrl: ExecutorConfigLoader.serviceUrl(
          values.DECIONIS_API_URL,
          "DECIONIS_API_URL",
          allowInsecureLoopback,
        ),
        apiKey: SecretStore.resolve(env, "DECIONIS_API_KEY"),
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
        credential: SecretStore.resolve(env, "DOWNSTREAM_CREDENTIAL"),
        credentialHeader: values.DOWNSTREAM_CREDENTIAL_HEADER.toLowerCase(),
        timeoutMs: values.DOWNSTREAM_TIMEOUT_MS,
      },
    };
  }

  private static escalation(
    env: Readonly<Record<string, string | undefined>>,
    values: Environment,
    allowInsecureLoopback: boolean,
  ): EscalationConfig {
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
        apiKey: SecretStore.resolve(env, "PRESENCE_API_KEY"),
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
