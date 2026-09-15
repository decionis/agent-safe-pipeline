import { ActionRegistry } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { EffectEvidenceRegister } from "../../../src/adapters/EffectEvidenceRegister.js";
import { bankingHandlers } from "../../../src/adapters/banking/BankingHandlers.js";
import { registeredActionNames } from "../../../src/adapters/banking/BankingAdapter.js";
import type { DownstreamConfig } from "../../../src/config/ExecutorConfig.js";
import type { DownstreamCredential } from "../../../src/credential/DownstreamCredential.js";

const downstream = {
  url: "https://core.provider.example/v1/actions",
  lookupUrl: "https://core.provider.example/v1/actions/{idempotency_key}",
  system: "synthetic_core",
  operation: "loan_disbursement",
  environment: "local",
  timeoutMs: 2_000,
} as DownstreamConfig;

const credential: DownstreamCredential = {
  kind: "STATIC_HEADER",
  headersFor: () => Promise.resolve({}),
};

function register(options: Parameters<typeof bankingHandlers>[0] = {}) {
  const registry = new ActionRegistry();
  const names = bankingHandlers(options)({
    registry,
    downstream,
    credential,
    fetch: () => Promise.reject(new Error("not reached")),
    effects: new EffectEvidenceRegister(),
    banking: {
      adapterId: "SYNTHETIC_CORE_BANKING",
      adapterVersion: "0.1.0",
      onEffectMismatch: "HALT",
      lookupByReferenceUrl: null,
    },
  });
  return { registry, names };
}

describe("bankingHandlers", () => {
  it("registers every action this build mirrors, under its transport name", () => {
    const { registry, names } = register();
    expect(names).toEqual(registeredActionNames());
    for (const name of names) expect(registry.has(name)).toBe(true);
    expect(registry.has("forward_request")).toBe(false);
  });

  it("needs no options at all, and takes an identity when one is given", () => {
    expect(register().names.length).toBeGreaterThan(0);
    const named = register({
      id: "synthetic-other-core",
      version: "9.9.9",
      lookupByReferenceUrl: "https://core.provider.example/v1/by/{provider_reference}",
      onMismatch: () => undefined,
    });
    expect(named.names).toEqual(registeredActionNames());
  });

  it("refuses parameters that are not a canonical action, at the registry's own gate", () => {
    const { registry } = register();
    registry.seal();
    const name = registeredActionNames()[0] as string;
    const captured = {
      intent: { action: name, parameters: { amountMinor: 1 } },
    } as unknown as Parameters<typeof registry.validate>[0];
    expect(() => registry.validate(captured)).toThrow("ACTION_PARAMETERS_INVALID");
  });
});
