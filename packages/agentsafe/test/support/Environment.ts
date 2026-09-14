import { createServer } from "node:net";
import {
  LOCAL_AUTHORITY_API_KEY,
  LOCAL_PRESENCE_API_KEY,
  type LocalAuthority,
  type LocalPresence,
} from "@decionis/agent-safe-pipeline/testing";

export const LOOPBACK_ORIGIN = "http://127.0.0.1";
export const TENANT_ID = "00000000-0000-4000-8000-000000000007";
export const APPROVER_ID = "synthetic-approver";
export const CALLER_TOKEN = "synthetic-caller-token-0123456789abcdef";
export const DOWNSTREAM_CREDENTIAL = "Bearer synthetic-downstream-credential-0123456789";

export type Escalation = "NONE" | "DIRECT" | "MANAGED";

/** A configuration that reaches no network: every address is a reserved example host. */
export function offlineEnvironment(): Record<string, string> {
  return {
    EXECUTOR_MODE: "ENFORCEMENT",
    EXECUTOR_BIND_ADDRESS: "127.0.0.1",
    PORT: "8443",
    EXECUTOR_TENANT_ID: TENANT_ID,
    EXECUTOR_ACTOR_ID: "synthetic-payout-agent",
    EXECUTOR_ACTOR_TYPE: "AI_AGENT",
    EXECUTOR_INTENT_TTL_SECONDS: "300",
    EXECUTOR_CALLER_TOKEN: CALLER_TOKEN,
    EXECUTOR_ESCALATION: "NONE",
    DECIONIS_API_URL: "https://authority.decionis.example",
    DECIONIS_API_KEY: "synthetic-authority-key",
    DOWNSTREAM_URL: "https://payouts.provider.example/v1/payouts",
    DOWNSTREAM_LOOKUP_URL: "https://payouts.provider.example/v1/payouts/{idempotency_key}",
    DOWNSTREAM_SYSTEM: "payout-rail",
    DOWNSTREAM_OPERATION: "create_payout",
    DOWNSTREAM_ENVIRONMENT: "production",
    DOWNSTREAM_CREDENTIAL: DOWNSTREAM_CREDENTIAL,
    DOWNSTREAM_CREDENTIAL_HEADER: "Authorization",
    DOWNSTREAM_TIMEOUT_MS: "5000",
  };
}

/** The executor's environment against the loopback doubles, as a deployment would mount it. */
export function loopbackEnvironment(
  doubles: { authority: LocalAuthority; presence: LocalPresence; providerBaseUrl: string },
  mode: "SHADOW" | "ENFORCEMENT",
  escalation: Escalation = "NONE",
  presenceBaseUrl: string = doubles.presence.baseUrl,
): Record<string, string> {
  const presenceShape =
    escalation === "NONE"
      ? {}
      : {
          PRESENCE_APPROVER_ID: APPROVER_ID,
          PRESENCE_VERIFICATION_LEVEL: "HIGH_CONFIDENCE",
          PRESENCE_VERIFICATION_METHODS: "WEBAUTHN,ACTIVE_LIVENESS",
          ...(escalation === "DIRECT"
            ? {
                PRESENCE_API_URL: presenceBaseUrl,
                PRESENCE_API_KEY: LOCAL_PRESENCE_API_KEY,
                PRESENCE_ORGANIZATION: "Synthetic Treasury",
                PRESENCE_HARDWARE_PKI_REQUIRED: "false",
                PRESENCE_DISALLOW_VIRTUAL_CAMERAS: "true",
              }
            : { PRESENCE_APPROVER_ROLE: "CRO" }),
        };
  return {
    ...offlineEnvironment(),
    EXECUTOR_MODE: mode,
    EXECUTOR_ESCALATION: escalation,
    ...presenceShape,
    EXECUTOR_ACTOR_RUNTIME: "trusted-executor-tests",
    DECIONIS_API_URL: doubles.authority.baseUrl,
    DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
    DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
    DOWNSTREAM_URL: `${doubles.providerBaseUrl}/dispatches`,
    DOWNSTREAM_LOOKUP_URL: `${doubles.providerBaseUrl}/dispatches/{idempotency_key}`,
    DOWNSTREAM_SYSTEM: "synthetic-payout-rail",
    DOWNSTREAM_ENVIRONMENT: "local",
    DOWNSTREAM_TIMEOUT_MS: "2000",
  };
}

/** A loopback port nothing listens on, for "the service is down" cases. */
export async function closedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

let sequence = 0;

/** A proposal as the caller would send it; the idempotency key is the caller's own. */
export function proposal(
  amountMinor: number,
  overrides: Record<string, unknown> = {},
): { readonly body: Record<string, unknown>; readonly key: string } {
  sequence += 1;
  const key = `payout-${sequence}-v1`;
  return {
    key,
    body: {
      proposal: {
        action: "forward_request",
        target: `payout:synthetic-beneficiary-${sequence}`,
        parameters: { amountMinor, currency: "USD", reference: `synthetic-payout-${sequence}` },
      },
      idempotency_key: key,
      correlation_id: `synthetic-run-${sequence}`,
      ...overrides,
    },
  };
}
