import { generateKeyPairSync } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { LOCAL_AUTHORITY_ISSUER, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bankingHandlers } from "../../src/adapters/banking/BankingHandlers.js";
import { BankingAdapter } from "../../src/adapters/banking/BankingAdapter.js";
import type { BankingAction } from "../../src/adapters/banking/BankingAction.js";
import { transportActionName, transportTarget } from "../../src/adapters/banking/BankingAction.js";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import { HaltSwitch } from "../../src/incident/HaltSwitch.js";
import { InMemoryExecutionJournal } from "../../src/journal/InMemoryExecutionJournal.js";
import type { ActionResponse } from "../../src/service/Requests.js";
import { ServiceError } from "../../src/service/ServiceError.js";
import { TrustedExecutorService } from "../../src/service/TrustedExecutorService.js";
import { signEffectReceipt } from "../../src/verify/EffectReceipt.js";
import { collectedEvents, loopbackEnvironment, openSecrets } from "../support/Environment.js";
import { BankingDouble } from "../support/BankingDouble.js";
import { bankingAction } from "../support/BankingFixtures.js";

const authority = new LocalAuthority();
const provider = new BankingDouble();

beforeAll(async () => {
  await authority.start();
  await provider.start();
});

afterAll(async () => {
  await provider.stop();
  await authority.stop();
});

const prepareOnly = new BankingAdapter({
  id: "synthetic-core-banking",
  version: "0.1.0",
  transport: {
    execute: () => Promise.reject(new Error("prepare only")),
    reconcile: () => Promise.reject(new Error("prepare only")),
  },
});

interface Built {
  readonly service: TrustedExecutorService;
  readonly halt: HaltSwitch;
  readonly lines: string[];
  readonly securityLines: string[];
}

function build(overrides: Record<string, string> = {}): Built {
  const env: Record<string, string> = {
    ...loopbackEnvironment({ authority, providerBaseUrl: provider.baseUrl }, "ENFORCEMENT"),
    // The binder requires the action's own downstream to be the one this
    // process serves, and the profile's identifiers have no hyphen in them.
    DOWNSTREAM_SYSTEM: "synthetic_core",
    DOWNSTREAM_OPERATION: "loan_disbursement",
    DOWNSTREAM_ENVIRONMENT: "local",
    DOWNSTREAM_URL: provider.executeUrl,
    DOWNSTREAM_LOOKUP_URL: provider.lookupByKeyUrl,
    DOWNSTREAM_LOOKUP_BY_REFERENCE_URL: provider.lookupByReferenceUrl,
    BANKING_ADAPTER_ID: "SYNTHETIC_CORE_BANKING",
    BANKING_ADAPTER_VERSION: "0.1.0",
    EXECUTOR_ACTOR_ID: "synthetic-treasury-agent",
    ...overrides,
  };
  const config = ExecutorConfigLoader.load(env);
  const lines: string[] = [];
  const securityLines: string[] = [];
  const events = collectedEvents(securityLines);
  const halt = new HaltSwitch({ events });
  const service = TrustedExecutorService.create(
    config,
    openSecrets(env, config, events),
    // The adapter's identity and its read-back address come from the
    // configuration, so nothing here names either of them twice.
    bankingHandlers(),
    {
      emit: (line) => lines.push(line),
      security: events,
      journal: new InMemoryExecutionJournal(),
      halt,
    },
  );
  return { service, halt, lines, securityLines };
}

let sequence = 0;

/** A proposal carrying a canonical banking action, as Appendix B.5 maps it. */
function beapProposal(overrides: Partial<BankingAction> = {}): {
  readonly body: Record<string, unknown>;
  readonly action: BankingAction;
} {
  sequence += 1;
  const action = bankingAction({
    action: { type: "DISBURSE_LOAN", request_id: `synthetic-req-beap-${sequence}` },
    downstream: {
      provider: "SYNTHETIC_CORE",
      product: "LENDING",
      operation: "LOAN_DISBURSEMENT",
      environment: "LOCAL",
    },
    ...overrides,
  });
  return {
    action,
    body: {
      proposal: {
        action: transportActionName(action),
        target: transportTarget(action),
        parameters: action as never,
      },
      idempotency_key: action.action.request_id,
    },
  };
}

async function refusal(work: Promise<unknown>): Promise<ServiceError> {
  try {
    await work;
  } catch (error) {
    if (error instanceof ServiceError) return error;
    throw error;
  }
  throw new Error("expected a refusal");
}

const events = (lines: string[]): Record<string, unknown>[] =>
  lines.map((line) => JSON.parse(line) as Record<string, unknown>);

const effectOf = (response: ActionResponse): Record<string, unknown> =>
  (response.effect ?? {}) as Record<string, unknown>;

describe("a BEAP action through the whole boundary", () => {
  it("binds the digests itself, reads the effect back, and confirms only then", async () => {
    const { service, lines, securityLines } = build();
    const proposal = beapProposal();
    const prepared = prepareOnly.prepare(proposal.action);
    provider.answer({ status: 200, body: { status: "POSTED", reference: "fixture_ref_10" } });
    provider.readBack = {
      status: 200,
      body: { status: "POSTED", effect: prepared.expectedEffect },
    };
    const response = await service.propose(proposal.body);
    expect(response.outcome).toBe("COMPLETED");
    expect(response.executed).toBe(true);
    expect(effectOf(response)).toMatchObject({
      outcome: "COMMITTED",
      confirmation: "CONFIRMED",
      comparison: "MATCH",
      observation_method: "READ_AFTER_WRITE",
      expected_effect_digest: prepared.expectedEffectDigest,
      observed_effect_digest: prepared.expectedEffectDigest,
      provider_reference: "fixture_ref_10",
      mismatched_fields: [],
    });
    // The confirmation is this boundary's own reading of what it observed.
    // Whether the authority *records* a confirmed observation depends on its
    // trusted-observer allowlist, which is the deployer's; when it refuses
    // one, the verifier finalizes again without it, so the commit outcome is
    // never traded for an observation.
    expect(response.finalization).toBe("RECORDED");
    // The trusted context the executor computed reaches the authority inside
    // the hashed intent, and the authority recomputes that hash itself.
    const evaluated = authority.requests.find((request) =>
      request.path.includes("enforce-and-bind"),
    );
    const binding = evaluated?.body as Record<string, unknown> | undefined;
    expect(binding?.["context"]).toMatchObject({
      beap_profile: "decionis.beap/v1.0",
      beap_intent_digest: prepared.intentDigest,
      beap_expected_effect_digest: prepared.expectedEffectDigest,
      caller_principal: "legacy-caller",
    });
    expect(binding?.["expected_effect_digest"]).toBe(prepared.expectedEffectDigest);
    expect(evaluated?.recomputedHash).toBe(response.intent_hash);
    expect(lines.length).toBeGreaterThan(0);
    const observed = events(securityLines).filter((line) => line["event"] === "EFFECT_OBSERVED");
    expect(observed.at(-1)).toMatchObject({ comparison: "MATCH", confirmation: "CONFIRMED" });
    service.close();
  });

  it("binds the grant to the expected effect, which the authority cross-checks on the claim", async () => {
    const { service } = build();
    const proposal = beapProposal();
    const prepared = prepareOnly.prepare(proposal.action);
    provider.answer({ status: 202, body: { status: "ACCEPTED" } });
    provider.readBack = null;
    const response = await service.propose(proposal.body);
    expect(response.outcome).toBe("COMPLETED");
    const claim = authority.requests.filter((request) => request.path.includes("claim")).at(-1);
    expect(JSON.stringify(claim?.body ?? {})).toContain(prepared.expectedEffectDigest);
    expect(claim?.response?.status).toBe(200);
    // An acknowledgement is not a confirmation, however the provider said it.
    expect(effectOf(response)).toMatchObject({
      confirmation: "PENDING",
      comparison: "PENDING",
      observed_effect_digest: null,
    });
    service.close();
  });

  it("reports a provider that did something else as a mismatch, and halts on it", async () => {
    const { service, halt, securityLines } = build();
    const proposal = beapProposal();
    const prepared = prepareOnly.prepare(proposal.action);
    provider.answer({ status: 200, body: { status: "POSTED", reference: "fixture_ref_11" } });
    provider.readBack = {
      status: 200,
      body: {
        status: "POSTED",
        effect: { ...prepared.expectedEffect, amount: "1.00" },
      },
    };
    const response = await service.propose(proposal.body);
    // The pipeline's own outcome is unchanged: the handler returned a result.
    expect(response.outcome).toBe("COMPLETED");
    expect(response.executed).toBe(true);
    expect(response.reason_codes).toContain("EFFECT_MISMATCH");
    expect(effectOf(response)).toMatchObject({
      comparison: "MISMATCH",
      confirmation: "UNKNOWN",
      mismatched_fields: ["amount"],
    });
    const mismatch = events(securityLines).find((line) => line["event"] === "EFFECT_MISMATCH");
    expect(mismatch).toMatchObject({ fields: ["amount"] });
    expect(halt.current).toMatchObject({ halted: true, trigger: "EFFECT_MISMATCH" });
    // The next proposal is refused by the halt, with no authority request.
    const requests = authority.requests.length;
    const refused = await refusal(service.propose(beapProposal().body));
    expect([refused.status, refused.code]).toEqual([503, "EXECUTOR_HALTED"]);
    expect(authority.requests.length).toBe(requests);
    service.close();
  });

  it("forwards a verifying provider's receipt to the authority and records its agreement with the observation", async () => {
    // The provider signs receipts with a key the organisation registered with
    // the authority; the executor forwards them unread and compares only what
    // they state with what it observed.
    const keys = generateKeyPairSync("ed25519");
    authority.registerProviderKey({
      kid: "core-receipts-1",
      issuer: "https://core.example",
      publicJwk: keys.publicKey.export({ format: "jwk" }),
    });
    const receiptFor =
      (effect: (expected: string) => Record<string, unknown>) =>
      (headers: IncomingMessage["headers"]): string => {
        const attestation = String(headers["x-agent-safe-claim-attestation"] ?? "");
        const claims = JSON.parse(
          Buffer.from(attestation.split(".")[1] ?? "", "base64url").toString("utf8"),
        ) as {
          sub: string;
          decision_id: string;
          dossier_id: string;
          claim_token_digest: string;
          jti: string;
          binding: { intent_hash: string; expected_effect_digest?: string };
        };
        return signEffectReceipt({
          key: keys.privateKey,
          kid: "core-receipts-1",
          issuer: "https://core.example",
          audience: LOCAL_AUTHORITY_ISSUER,
          attestation: claims,
          effect: {
            ...effect(claims.binding.expected_effect_digest ?? ""),
            effected_at: new Date().toISOString(),
          } as never,
          issuedAt: Math.floor(Date.now() / 1_000),
          jti: `receipt-${Date.now()}`,
        });
      };
    const { service, halt, securityLines } = build();
    const proposal = beapProposal();
    const prepared = prepareOnly.prepare(proposal.action);
    provider.answer({
      status: 200,
      body: { status: "POSTED", reference: "fixture_ref_12" },
      receipt: receiptFor((expected) => ({
        status: "EFFECTED",
        reference: "fixture_ref_12",
        digest: expected,
      })),
    });
    provider.readBack = {
      status: 200,
      body: { status: "POSTED", effect: prepared.expectedEffect },
    };
    const response = await service.propose(proposal.body);
    expect(response.outcome).toBe("COMPLETED");
    expect(effectOf(response)).toMatchObject({
      confirmation: "CONFIRMED",
      receipt_comparison: "MATCH",
      receipt_status: "EFFECTED",
    });
    // The authority verified the receipt under the registered key and
    // recorded it with the commit.
    const finalize = authority.requests
      .filter((request) => request.path.includes("finalize"))
      .at(-1);
    expect((finalize?.body as { effect_receipt?: string }).effect_receipt).toMatch(/^[\w-]+\./);
    expect(finalize?.response?.body).toMatchObject({
      effect_receipt: { verified: true, verification_code: "EFFECT_RECEIPT_VERIFIED" },
    });
    const observed = events(securityLines).filter((line) => line["event"] === "EFFECT_OBSERVED");
    expect(observed.at(-1)).toMatchObject({ comparison: "MATCH", receipt: "MATCH" });
    expect(halt.current.halted).toBe(false);

    // The same provider, whose receipt names another effect than the one it
    // let the executor read back: two witnesses disagree, and the boundary
    // treats that as the institution's exception.
    provider.answer({
      status: 200,
      body: { status: "POSTED", reference: "fixture_ref_13" },
      receipt: receiptFor(() => ({ status: "EFFECTED", digest: `sha256:${"7".repeat(64)}` })),
    });
    const contradicted = await service.propose(beapProposal().body);
    expect(contradicted.outcome).toBe("COMPLETED");
    expect(contradicted.reason_codes).toContain("EFFECT_MISMATCH");
    expect(effectOf(contradicted)).toMatchObject({
      comparison: "MATCH",
      confirmation: "UNKNOWN",
      receipt_comparison: "MISMATCH",
    });
    const mismatch = events(securityLines).find(
      (line) => line["event"] === "EFFECT_RECEIPT_MISMATCH",
    );
    expect(mismatch).toMatchObject({ receipt_status: "EFFECTED" });
    expect(halt.current).toMatchObject({ halted: true, trigger: "EFFECT_MISMATCH" });
    service.close();
  });

  it("reports a provider's refusal as definitely not executed, with the effect agreeing", async () => {
    const built = build();
    const proposal = beapProposal();
    provider.answer({ status: 409, body: { status: "REJECTED", reason_code: "LIMIT" } });
    provider.readBack = null;
    const response = await built.service.propose(proposal.body);
    // Both halves say the same thing now. Before the pipeline had a signal
    // for a refusal, this read `COMPLETED, executed: true` with an effect
    // block saying nothing was effected.
    expect(response.outcome).toBe("DEFINITELY_NOT_EXECUTED");
    expect(response.executed).toBe(false);
    expect(response.finalization).toBe("RECORDED");
    expect(response.reason_codes).toContain("POLICY_STATE_CHANGED");
    // The observation still reached the authority: the adapter registered it
    // before the refusal was thrown.
    const finalize = authority.requests.filter((one) => one.path.includes("finalize")).at(-1);
    expect((finalize?.body as { readonly outcome?: string } | undefined)?.outcome).toBe("FAILED");
    // And there is nothing to reconcile, because nothing is unknown.
    expect(response.recovery).toBeNull();
    built.service.close();
  });

  it("alerts without halting when the institution's policy says so", async () => {
    const { service, halt, securityLines } = build({ EXECUTOR_ON_EFFECT_MISMATCH: "ALERT" });
    const proposal = beapProposal();
    const prepared = prepareOnly.prepare(proposal.action);
    provider.answer({ status: 200, body: { status: "POSTED", reference: "fixture_ref_12" } });
    provider.readBack = {
      status: 200,
      body: { status: "POSTED", effect: { ...prepared.expectedEffect, currency: "EUR" } },
    };
    const response = await service.propose(proposal.body);
    expect(effectOf(response)["mismatched_fields"]).toEqual(["currency"]);
    expect(events(securityLines).some((line) => line["event"] === "EFFECT_MISMATCH")).toBe(true);
    expect(halt.halted).toBe(false);
    service.close();
  });

  it("refuses every disagreement between the transport and the action, before the authority", async () => {
    const { service } = build();
    const cases: [Record<string, unknown>, string][] = [
      [{ action: "beap.corporate_payments.send_payment" }, "BANKING_ACTION_NAME_MISMATCH"],
      [{ target: "loan:fixture_loan_00000" }, "BANKING_TARGET_MISMATCH"],
    ];
    for (const [override, code] of cases) {
      const proposal = beapProposal();
      const requests = authority.requests.length;
      const refused = await refusal(
        service.propose({
          ...proposal.body,
          proposal: { ...(proposal.body["proposal"] as object), ...override },
        }),
      );
      expect([refused.status, refused.code], code).toEqual([422, code]);
      expect(authority.requests.length, code).toBe(requests);
    }
    const mismatchedKey = beapProposal();
    expect(
      (
        await refusal(
          service.propose({ ...mismatchedKey.body, idempotency_key: "synthetic-other" }),
        )
      ).code,
    ).toBe("BANKING_REQUEST_ID_MISMATCH");
    const foreignDownstream = beapProposal({
      downstream: { provider: "OTHER_CORE", operation: "LOAN_DISBURSEMENT" },
    });
    expect((await refusal(service.propose(foreignDownstream.body))).code).toBe(
      "BANKING_DOWNSTREAM_MISMATCH",
    );
    const someoneElse = beapProposal({
      actor: { type: "AGENT", id: "synthetic-someone-else" },
    });
    expect((await refusal(service.propose(someoneElse.body))).code).toBe("BANKING_ACTOR_MISMATCH");
    service.close();
  });

  it("refuses a malformed action, and an amount the profile's arithmetic will not read", async () => {
    const { service } = build();
    const scaled = beapProposal({ financial_context: { amount: "250000.0", currency: "CHF" } });
    expect((await refusal(service.propose(scaled.body))).code).toBe("BANKING_ACTION_INVALID");
    const unknownCurrency = beapProposal({
      financial_context: { amount: "250000.00", currency: "XXX" },
    });
    expect((await refusal(service.propose(unknownCurrency.body))).code).toBe(
      "BANKING_ACTION_INVALID",
    );
    const notAnAction = beapProposal();
    expect(
      (
        await refusal(
          service.propose({
            ...notAnAction.body,
            proposal: {
              ...(notAnAction.body["proposal"] as object),
              parameters: { amountMinor: 1 },
            },
          }),
        )
      ).code,
    ).toBe("BANKING_ACTION_INVALID");
    service.close();
  });

  it("leaves an action outside the family alone, with no effect block at all", async () => {
    const { service } = build();
    expect(
      (
        await refusal(
          service.propose({
            proposal: { action: "forward_request", target: "payout:x", parameters: {} },
            idempotency_key: "synthetic-key-plain",
          }),
        )
      ).code,
    ).toBe("ACTION_NOT_REGISTERED");
    service.close();
  });

  it("carries no provider body, parameter, or credential into any line", async () => {
    const { service, lines, securityLines } = build();
    const proposal = beapProposal();
    const prepared = prepareOnly.prepare(proposal.action);
    provider.answer({ status: 200, body: { status: "POSTED", reference: "fixture_ref_13" } });
    provider.readBack = {
      status: 200,
      body: { status: "POSTED", effect: prepared.expectedEffect },
    };
    await service.propose(proposal.body);
    const security = securityLines.join("\n");
    expect(security).not.toContain("fixture_account_1921");
    expect(security).not.toContain("250000.00");
    expect(security).not.toContain("Bearer");
    expect(lines.join("\n")).not.toContain("Bearer");
    service.close();
  });
});
