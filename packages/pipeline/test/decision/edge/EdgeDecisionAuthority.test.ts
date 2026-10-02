import { z } from "zod";
import { describe, expect, it, vi } from "vitest";
import type { DecisionAuthority, GateDecision } from "../../../src/decision/DecisionAuthority.js";
import { DecionisGate } from "../../../src/decision/DecionisGate.js";
import { EdgeBundleManager } from "../../../src/decision/edge/EdgeBundleManager.js";
import type { BundleRead, EdgeBundleSource } from "../../../src/decision/edge/EdgeBundleSource.js";
import {
  EdgeDecisionAuthority,
  type EdgeDecisionAuthorityOptions,
  type EdgeDecisionRecord,
} from "../../../src/decision/edge/EdgeDecisionAuthority.js";
import { EdgeModule } from "../../../src/decision/edge/EdgeModule.js";
import { ActionRegistry } from "../../../src/execution/ActionRegistry.js";
import {
  LocalAuthorizationVerifier,
  LocalGrants,
} from "../../../src/execution/LocalAuthorizationVerifier.js";
import { InMemoryReplayStore, type ReplayStore } from "../../../src/execution/ReplayStore.js";
import { SafeExecutor } from "../../../src/execution/SafeExecutor.js";
import { IntentCapture } from "../../../src/intent/IntentCapture.js";
import { immutableGateDecision } from "../../../src/decision/ImmutableGateDecision.js";
import {
  doubleClaims,
  edgeModuleDouble,
  signedBundle,
  type DoubleBehaviour,
} from "../../support/EdgeModuleDouble.js";

const SECRET_PARAMETER = "GB82WEST12345698765432";

function intent(action: string, ttlSeconds = 120) {
  return new IntentCapture({ ttlSeconds }).capture(
    {
      action,
      target: "core:account:synthetic-1",
      parameters: { amount: 125_000, currency: "GBP", beneficiary_iban: SECRET_PARAMETER },
    },
    {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: { id: "synthetic-payments-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "core", operation: "payment" },
      idempotencyKey: `${action}-1`,
      context: {},
    },
  );
}

function claimsNow(overrides: Record<string, string> = {}) {
  return doubleClaims({
    nbf: new Date(Date.now() - 3_600_000).toISOString(),
    exp: new Date(Date.now() + 86_400_000).toISOString(),
    ...overrides,
  });
}

class FixedSource implements EdgeBundleSource {
  public readonly kind = "url";
  public constructor(public answer: BundleRead) {}
  public async read(): Promise<BundleRead> {
    return this.answer;
  }
}

/** A hosted authority double: what DecionisGate would answer, without a network. */
function hostedDouble(verdict: "ALLOW" | "ESCALATE" | "BLOCK" = "ESCALATE") {
  const evaluate = vi.fn(async (captured: { intentHash: string }) =>
    immutableGateDecision({
      verdict,
      decisionId: `hosted-${verdict.toLowerCase()}`,
      dossierId: "hosted-dossier",
      intentHash: captured.intentHash,
      reasonCodes: [`HOSTED_${verdict}`],
      authorization: null,
      failClosed: false,
    }),
  ) as unknown as DecisionAuthority["evaluate"] & ReturnType<typeof vi.fn>;
  const authority: DecisionAuthority = { evaluationMode: "ENFORCEMENT", evaluate };
  return { authority, evaluate };
}

async function setup(
  options: {
    behaviour?: DoubleBehaviour;
    onUnavailable?: "hosted" | "block";
    mode?: "ENFORCEMENT" | "SHADOW";
    hosted?: DecisionAuthority;
    read?: BundleRead;
    record?: EdgeDecisionAuthorityOptions["record"];
    replay?: ReplayStore;
    shareReplay?: boolean;
  } = {},
) {
  const double = edgeModuleDouble(options.behaviour);
  const module = EdgeModule.fromExports(double.exports);
  const source = new FixedSource(
    options.read ?? { ok: true, signedBundle: signedBundle(claimsNow()) },
  );
  const bundles = new EdgeBundleManager({ module, source, orgId: "org-1" });
  await bundles.refresh();
  const records: EdgeDecisionRecord[] = [];
  const grants = new LocalGrants();
  const hosted = hostedDouble();
  const replay = options.replay ?? new InMemoryReplayStore();
  const authority = new EdgeDecisionAuthority({
    module,
    bundles,
    hosted: options.hosted ?? hosted.authority,
    grants,
    ...(options.shareReplay === true || options.replay !== undefined ? { replay } : {}),
    ...(options.mode === undefined ? {} : { mode: options.mode }),
    ...(options.onUnavailable === undefined ? {} : { onUnavailable: options.onUnavailable }),
    record: options.record ?? ((record) => records.push(record)),
  });
  const execute = vi.fn(async () => ({ posted: true }));
  const registry = new ActionRegistry();
  for (const action of ["payment.allow", "payment.block", "payment.escalate"]) {
    registry.register(action, { parametersSchema: z.object({}).passthrough(), execute });
  }
  registry.seal();
  const verifier = new LocalAuthorizationVerifier({
    grants,
    replay,
    record: (record) => records.push(record as unknown as EdgeDecisionRecord),
  });
  const executor = new SafeExecutor(registry, verifier);
  return { double, module, bundles, source, records, grants, hosted, authority, execute, executor };
}

describe("EdgeDecisionAuthority", () => {
  it("decides ALLOW locally on the binding enforce-and-bind would receive, and executes once", async () => {
    const { authority, double, executor, execute, hosted } = await setup();
    const captured = intent("payment.allow");
    const decision = await authority.evaluate(captured);
    expect(hosted.evaluate).not.toHaveBeenCalled();
    expect(double.decideInputs).toHaveLength(1);
    const input = double.decideInputs[0] as Record<string, unknown>;
    expect(input["binding"]).toEqual(JSON.parse(JSON.stringify(DecionisGate.binding(captured))));
    expect(input["mode"]).toBe("ENFORCEMENT");
    expect(Date.parse(String(input["now"]))).toBeLessThanOrEqual(Date.now());
    expect(decision).toMatchObject({
      verdict: "ALLOW",
      intentHash: captured.intentHash,
      reasonCodes: ["POLICY_ALLOW"],
      failClosed: false,
      dossierId: `edge:sha256:${"e".repeat(64)}`,
    });
    expect(decision.decisionId).toMatch(/^edge:[0-9a-f]{40}$/);
    expect(decision.authorization?.expiresAt).toBe(captured.intent.expiresAt);
    expect(Object.isFrozen(decision)).toBe(true);

    const first = await executor.run(captured, decision);
    expect(first).toMatchObject({ outcome: "COMPLETED", finalization: "RECORDED" });
    expect(execute).toHaveBeenCalledTimes(1);

    // The same decision again, and a fresh local decision for the same intent: neither runs.
    expect((await executor.run(captured, decision)).outcome).toBe("BLOCKED");
    const again = await authority.evaluate(captured);
    expect(again.verdict).toBe("ALLOW");
    const replay = await executor.run(captured, again);
    expect(replay).toMatchObject({ outcome: "BLOCKED", reason: "AUTHORIZATION_INVALID" });
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("refuses to decide again about an intent the shared store says has run", async () => {
    const { authority, double, executor, execute, records } = await setup({ shareReplay: true });
    const captured = intent("payment.allow");
    const decision = await authority.evaluate(captured);
    expect((await executor.run(captured, decision)).outcome).toBe("COMPLETED");
    const decided = double.decideInputs.length;
    const recorded = records.length;
    const again = await authority.evaluate(captured);
    expect(again).toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      reasonCodes: ["INTENT_ALREADY_CONSUMED"],
      authorization: null,
    });
    // Not a decision: the module is not asked and nothing is recorded or counted.
    expect(double.decideInputs).toHaveLength(decided);
    expect(records).toHaveLength(recorded);
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("fails closed when the shared store cannot be asked, and asks it only in enforcement", async () => {
    const consumed = vi.fn(async () => {
      throw new Error("connection refused");
    });
    const replay: ReplayStore = { claim: async () => true, consumed };
    const { authority, double } = await setup({ replay });
    const refused = await authority.evaluate(intent("payment.allow"));
    expect(refused).toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      reasonCodes: ["EDGE_REPLAY_STORE_UNAVAILABLE"],
    });
    expect(double.decideInputs).toHaveLength(0);

    const shadow = await setup({
      replay,
      mode: "SHADOW",
      hosted: { evaluationMode: "SHADOW", evaluate: vi.fn() },
    });
    expect((await shadow.authority.evaluate(intent("payment.allow"))).verdict).toBe("ALLOW");
    expect(consumed).toHaveBeenCalledTimes(1);
  });

  it("decides as before when the store has no way to be asked", async () => {
    const replay: ReplayStore = { claim: async () => true };
    const { authority } = await setup({ replay });
    expect((await authority.evaluate(intent("payment.allow"))).verdict).toBe("ALLOW");
  });

  it("bounds the local authorization by the bundle's expiry when that comes first", async () => {
    const exp = new Date(Date.now() + 30_000).toISOString();
    const { authority } = await setup({
      read: { ok: true, signedBundle: signedBundle(claimsNow({ exp })) },
    });
    const decision = await authority.evaluate(intent("payment.allow", 120));
    expect(decision.authorization?.expiresAt).toBe(exp);
  });

  it("refuses BLOCK locally, without asking Decionis", async () => {
    const { authority, executor, execute, hosted } = await setup();
    const captured = intent("payment.block");
    const decision = await authority.evaluate(captured);
    expect(decision).toMatchObject({
      verdict: "BLOCK",
      authorization: null,
      failClosed: false,
      reasonCodes: ["POLICY_BLOCK"],
    });
    expect(hosted.evaluate).not.toHaveBeenCalled();
    expect((await executor.run(captured, decision)).outcome).toBe("BLOCKED");
    expect(execute).not.toHaveBeenCalled();
  });

  it("hands an ESCALATE, with its escalation options, to the hosted authority", async () => {
    const { authority, hosted, records } = await setup();
    const captured = intent("payment.escalate");
    const options = { escalation: { mode: "MANAGED" as const } };
    const decision = await authority.evaluate(captured, undefined, options);
    expect(hosted.evaluate).toHaveBeenCalledWith(captured, undefined, options);
    expect(decision.decisionId).toBe("hosted-escalate");
    expect(records[0]).toMatchObject({
      event: "EDGE_DECISION",
      verdict: "ESCALATE",
      delegated: true,
    });
  });

  it("evaluates approval evidence only hosted", async () => {
    const { authority, hosted, double } = await setup();
    const captured = intent("payment.allow");
    const evidence = {
      humanApproval: { provider: "presence" as const, requestId: "r", receiptDossierId: "d" },
    };
    await authority.evaluate(captured, evidence);
    expect(hosted.evaluate).toHaveBeenCalledWith(captured, evidence, {});
    expect(double.decideInputs).toHaveLength(0);
  });

  it("records each local decision on the evidence stream with no parameter in it", async () => {
    const { authority, records } = await setup();
    const captured = intent("payment.allow");
    const decision = await authority.evaluate(captured);
    expect(records).toEqual([
      {
        event: "EDGE_DECISION",
        mode: "ENFORCEMENT",
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
        decision_id: decision.decisionId,
        verdict: "ALLOW",
        reason_codes: ["POLICY_ALLOW"],
        policy_version: "policy-2026.10",
        bundle_id: "bundle-1",
        kid: "decionis-policy-bundle-test-v1",
        jti: "jti-1",
        evaluation_digest: `sha256:${"e".repeat(64)}`,
        delegated: false,
      },
    ]);
    const line = JSON.stringify(records);
    expect(line).not.toContain(SECRET_PARAMETER);
    expect(line).not.toContain("125000");
    expect(line).not.toContain("GBP");
  });

  it("makes no decision it cannot record", async () => {
    const { authority, hosted } = await setup({
      record: () => {
        throw new Error("evidence stream down");
      },
    });
    for (const action of ["payment.allow", "payment.escalate"]) {
      expect(await authority.evaluate(intent(action))).toMatchObject({
        verdict: "BLOCK",
        failClosed: true,
        reasonCodes: ["EDGE_RECORD_UNAVAILABLE"],
        authorization: null,
      });
    }
    expect(hosted.evaluate).not.toHaveBeenCalled();
    const unavailable = await setup({
      read: { ok: false, code: "BUNDLE_FETCH_FAILED" },
      record: () => {
        throw new Error("evidence stream down");
      },
    });
    expect((await unavailable.authority.evaluate(intent("payment.allow"))).reasonCodes).toEqual([
      "EDGE_RECORD_UNAVAILABLE",
    ]);
    expect(unavailable.hosted.evaluate).not.toHaveBeenCalled();
  });

  describe("when no local decision can be made", () => {
    const causes: [string, Parameters<typeof setup>[0], string, string | null][] = [
      [
        "no bundle was ever loaded",
        { read: { ok: false, code: "BUNDLE_HTTP_503" } },
        "EDGE_BUNDLE_UNAVAILABLE",
        null,
      ],
      [
        "the module refuses",
        { behaviour: { decide: () => ({ ok: false, error: { code: "bundle_expired" } }) } },
        "EDGE_MODULE_REFUSED",
        "bundle_expired",
      ],
      [
        "the module refuses with a code it cannot vouch for",
        { behaviour: { decide: () => ({ ok: false, error: { code: "Not A Code" } }) } },
        "EDGE_MODULE_REFUSED",
        null,
      ],
      [
        "the module faults",
        { behaviour: { decide: () => "garbage" } },
        "EDGE_MODULE_FAULTED",
        null,
      ],
      [
        "the result cannot be read",
        { behaviour: { decide: () => ({ ok: true, result: { verdict: "MAYBE" } }) } },
        "EDGE_RESULT_INVALID",
        null,
      ],
      [
        "the result names another bundle",
        {
          behaviour: {
            decide: () => ({
              ok: true,
              result: {
                verdict: "ALLOW",
                reason_codes: [],
                policy_version: "policy-2026.10",
                bundle: {
                  bundle_id: "other",
                  policy_version: "policy-2026.10",
                  kid: "decionis-policy-bundle-test-v1",
                  jti: "j",
                },
                authority_requirement: null,
                evaluation_digest: `sha256:${"e".repeat(64)}`,
              },
            }),
          },
        },
        "EDGE_RESULT_INVALID",
        null,
      ],
    ];
    for (const [name, options, reason, moduleCode] of causes) {
      it(`asks Decionis by default when ${name}`, async () => {
        const { authority, hosted, records } = await setup(options);
        const captured = intent("payment.allow");
        const decision = await authority.evaluate(captured);
        expect(hosted.evaluate).toHaveBeenCalledWith(captured, undefined, {});
        expect(decision.decisionId).toBe("hosted-escalate");
        expect(records).toEqual([
          {
            event: "EDGE_UNAVAILABLE",
            mode: "ENFORCEMENT",
            intent_id: captured.intent.intentId,
            intent_hash: captured.intentHash,
            reason,
            module_code: moduleCode,
            fallback: "HOSTED",
          },
        ]);
      });

      it(`fails closed under onUnavailable=block when ${name}`, async () => {
        const { authority, hosted, records } = await setup({ ...options, onUnavailable: "block" });
        const decision = await authority.evaluate(intent("payment.allow"));
        expect(decision).toMatchObject({
          verdict: "BLOCK",
          failClosed: true,
          reasonCodes: [reason],
          authorization: null,
        });
        expect(hosted.evaluate).not.toHaveBeenCalled();
        expect(records[0]).toMatchObject({ event: "EDGE_UNAVAILABLE", fallback: "BLOCK" });
      });
    }
  });

  it("follows onUnavailable both ways once the bundle expires, and never allows on it", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const start = Date.parse("2026-10-02T00:00:00.000Z");
      vi.setSystemTime(start);
      const claims = doubleClaims({
        nbf: "2026-10-01T00:00:00.000Z",
        exp: "2026-10-02T00:05:00.000Z",
      });
      const read: BundleRead = { ok: true, signedBundle: signedBundle(claims) };
      const hostedWay = await setup({ read });
      const blockWay = await setup({ read, onUnavailable: "block" });
      expect((await hostedWay.authority.evaluate(intent("payment.allow"))).verdict).toBe("ALLOW");
      vi.setSystemTime(Date.parse("2026-10-02T00:05:00.000Z"));
      const hosted = await hostedWay.authority.evaluate(intent("payment.allow"));
      expect(hosted.decisionId).toBe("hosted-escalate");
      expect(hostedWay.records.at(-1)).toMatchObject({ reason: "EDGE_BUNDLE_UNAVAILABLE" });
      const blocked = await blockWay.authority.evaluate(intent("payment.allow"));
      expect(blocked).toMatchObject({ verdict: "BLOCK", failClosed: true, authorization: null });
      expect(blockWay.double.loaded.size).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("decides on the new bundle after a refresh swaps it in", async () => {
    const { authority, source, bundles, records, double } = await setup();
    await authority.evaluate(intent("payment.allow"));
    source.answer = {
      ok: true,
      signedBundle: signedBundle(claimsNow({ bundle_id: "bundle-2", jti: "jti-2" })),
    };
    await bundles.refresh();
    await authority.evaluate(intent("payment.allow"));
    expect(records.map((record) => (record as { bundle_id: string }).bundle_id)).toEqual([
      "bundle-1",
      "bundle-2",
    ]);
    expect(double.loaded).toEqual(new Set([2]));
  });

  it("refuses an intent already expired rather than authorizing it", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const { authority } = await setup({
        behaviour: {
          decide: (_handle, input) => ({
            ok: true,
            result: {
              verdict: "ALLOW",
              reason_codes: [],
              policy_version: "policy-2026.10",
              bundle: {
                bundle_id: "bundle-1",
                policy_version: "policy-2026.10",
                kid: "decionis-policy-bundle-test-v1",
                jti: "jti-1",
              },
              authority_requirement: null,
              evaluation_digest: `sha256:${"e".repeat(64)}`,
              echo: input["mode"],
            },
          }),
        },
      });
      const captured = intent("payment.allow", 1);
      vi.setSystemTime(Date.parse(captured.intent.expiresAt));
      expect(await authority.evaluate(captured)).toMatchObject({
        verdict: "BLOCK",
        failClosed: true,
        reasonCodes: ["INTENT_EXPIRED"],
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("in shadow, records the verdict and never authorizes or escalates", async () => {
    const shadowHosted: DecisionAuthority = { evaluationMode: "SHADOW", evaluate: vi.fn() };
    const { authority, double } = await setup({ mode: "SHADOW", hosted: shadowHosted });
    expect(authority.evaluationMode).toBe("SHADOW");
    const allow = await authority.evaluate(intent("payment.allow"));
    expect(allow).toMatchObject({ verdict: "ALLOW", authorization: null });
    const escalate = await authority.evaluate(intent("payment.escalate"));
    expect(escalate).toMatchObject({ verdict: "ESCALATE", authorization: null });
    expect(shadowHosted.evaluate).not.toHaveBeenCalled();
    expect(double.decideInputs.map((input) => input["mode"])).toEqual(["SHADOW", "SHADOW"]);
  });

  it("refuses a configuration it cannot honour", async () => {
    const { module, bundles, grants } = await setup();
    const base = { module, bundles, grants, hosted: hostedDouble().authority };
    expect(() => new EdgeDecisionAuthority({ ...base, mode: "SHADOW" })).toThrow(
      "EDGE_MODE_MISMATCH",
    );
    expect(
      () => new EdgeDecisionAuthority({ ...base, mode: "PARALLEL" as unknown as "SHADOW" }),
    ).toThrow("EDGE_MODE_INVALID");
    expect(
      () => new EdgeDecisionAuthority({ ...base, onUnavailable: "allow" as unknown as "block" }),
    ).toThrow("EDGE_ON_UNAVAILABLE_INVALID");
    const modeless: DecisionAuthority = { evaluate: vi.fn() };
    expect(new EdgeDecisionAuthority({ ...base, hosted: modeless }).evaluationMode).toBe(
      "ENFORCEMENT",
    );
  });

  it("works without a record sink", async () => {
    const double = edgeModuleDouble();
    const module = EdgeModule.fromExports(double.exports);
    const bundles = new EdgeBundleManager({
      module,
      source: new FixedSource({ ok: true, signedBundle: signedBundle(claimsNow()) }),
      orgId: "org-1",
    });
    await bundles.refresh();
    const authority = new EdgeDecisionAuthority({
      module,
      bundles,
      grants: new LocalGrants(),
      hosted: hostedDouble().authority,
    });
    const decision: GateDecision = await authority.evaluate(intent("payment.block"));
    expect(decision.verdict).toBe("BLOCK");
    bundles.stop();
    expect((await authority.evaluate(intent("payment.block"))).decisionId).toBe("hosted-escalate");
  });
});
