import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { DecionisGate } from "../../src/decision/DecionisGate.js";
import type {
  DecisionAuthority,
  DecisionEvaluationMode,
  DecisionVerdict,
} from "../../src/decision/DecisionAuthority.js";
import { createFixtureAuthorityPair } from "../../src/decision/FixtureDecisionAuthority.js";
import { ShadowGate } from "../../src/decision/ShadowGate.js";
import { ActionRegistry } from "../../src/execution/ActionRegistry.js";
import { SafeExecutor } from "../../src/execution/SafeExecutor.js";
import { captured, json, stubAuthority, verdictBody } from "../support/AuthorityDouble.js";

const VERDICTS: readonly DecisionVerdict[] = ["ALLOW", "ESCALATE", "BLOCK"];
const RANK: Record<DecisionVerdict, number> = { ALLOW: 0, ESCALATE: 1, BLOCK: 2 };
const MODES: readonly DecisionEvaluationMode[] = ["SHADOW", "ENFORCEMENT"];

function registry() {
  return new ActionRegistry()
    .register("deploy", {
      parametersSchema: z.object({ environment: z.string() }).strict(),
      execute: async ({ parameters, dispatch }) =>
        await dispatch.run(async () => ({ deployed: parameters.environment })),
    })
    .seal();
}

describe("ShadowGate", () => {
  it("is never less restrictive than the local authority, in either mode", async () => {
    for (const mode of MODES) {
      for (const localVerdict of VERDICTS) {
        for (const hostedVerdict of VERDICTS) {
          const intent = captured();
          const gate = new ShadowGate(
            stubAuthority(localVerdict),
            stubAuthority(hostedVerdict),
            mode,
          );
          const decision = await gate.evaluate(intent);
          const label = `${mode} local=${localVerdict} hosted=${hostedVerdict}`;

          expect(RANK[decision.verdict], label).toBeGreaterThanOrEqual(RANK[localVerdict]);
          expect(decision.hosted, label).toMatchObject({
            mode,
            verdict: hostedVerdict,
            decisionId: `stub-${hostedVerdict.toLowerCase()}`,
            dossierId: `stub-dossier-${hostedVerdict.toLowerCase()}`,
            reasonCodes: [`STUB_${hostedVerdict}`],
            failClosed: false,
          });
          if (mode === "SHADOW") {
            // The local decision governs, field for field, and the hosted verdict is only recorded.
            expect(decision, label).toMatchObject({
              verdict: localVerdict,
              decisionId: `stub-${localVerdict.toLowerCase()}`,
              reasonCodes: [`STUB_${localVerdict}`],
            });
            expect(decision.hosted?.governs, label).toBe(false);
          } else {
            const hostedGoverns = RANK[hostedVerdict] >= RANK[localVerdict];
            const governing = hostedGoverns ? hostedVerdict : localVerdict;
            expect(decision.hosted?.governs, label).toBe(hostedGoverns);
            expect(decision, label).toMatchObject({
              verdict: governing,
              decisionId: `stub-${governing.toLowerCase()}`,
              reasonCodes: [`STUB_${governing}`],
            });
          }
          expect(Object.isFrozen(decision), label).toBe(true);
          expect(Object.isFrozen(decision.hosted), label).toBe(true);
          expect(Object.isFrozen(decision.hosted?.reasonCodes), label).toBe(true);
        }
      }
    }
  });

  it("keeps the local grant in SHADOW mode and the hosted grant in ENFORCEMENT mode", async () => {
    const intent = captured();
    const local = stubAuthority("ALLOW", {
      authorization: { token: "local-token", expiresAt: intent.intent.expiresAt },
    });
    const hosted = stubAuthority("ALLOW", {
      authorization: { token: "hosted-token", expiresAt: intent.intent.expiresAt },
    });

    const shadow = await new ShadowGate(local, hosted, "SHADOW").evaluate(intent);
    expect(shadow.authorization?.token).toBe("local-token");
    expect(shadow.hosted?.governs).toBe(false);

    const enforced = await new ShadowGate(local, hosted, "ENFORCEMENT").evaluate(intent);
    expect(enforced.authorization?.token).toBe("hosted-token");
    expect(enforced.hosted?.governs).toBe(true);
  });

  it("records a hosted authority that throws as fail-closed, and lets the local decision stand in SHADOW mode", async () => {
    const intent = captured();
    const broken: DecisionAuthority = {
      evaluate: async () => {
        throw new Error("socket hang up");
      },
    };
    const synchronous: DecisionAuthority = {
      evaluate: () => {
        throw new Error("not even a promise");
      },
    };

    for (const hosted of [broken, synchronous]) {
      const shadow = await new ShadowGate(stubAuthority("ALLOW"), hosted, "SHADOW").evaluate(
        intent,
      );
      expect(shadow).toMatchObject({ verdict: "ALLOW", failClosed: false });
      expect(shadow.authorization?.token).toBe("stub-token");
      expect(shadow.hosted).toMatchObject({
        governs: false,
        verdict: "BLOCK",
        failClosed: true,
        dossierId: null,
        reasonCodes: ["AUTHORITY_UNAVAILABLE"],
      });

      const enforced = await new ShadowGate(stubAuthority("ALLOW"), hosted, "ENFORCEMENT").evaluate(
        intent,
      );
      expect(enforced).toMatchObject({
        verdict: "BLOCK",
        failClosed: true,
        authorization: null,
        reasonCodes: ["AUTHORITY_UNAVAILABLE"],
      });
      expect(enforced.hosted?.governs).toBe(true);
    }
  });

  it("refuses a hosted decision about a different intent", async () => {
    const intent = captured();
    const foreign = stubAuthority("ALLOW", { intentHash: `sha256:${"f".repeat(64)}` });

    const enforced = await new ShadowGate(stubAuthority("ALLOW"), foreign, "ENFORCEMENT").evaluate(
      intent,
    );
    expect(enforced).toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      authorization: null,
      intentHash: intent.intentHash,
      reasonCodes: ["AUTHORITY_BINDING_MISMATCH"],
    });
    expect(enforced.hosted).toMatchObject({ verdict: "BLOCK", failClosed: true });
  });

  it("passes evidence and options to both authorities unchanged, and propagates a local failure", async () => {
    const intent = captured();
    const evidence = {
      humanApproval: {
        provider: "presence" as const,
        requestId: "synthetic-presence-request",
        receiptDossierId: "synthetic-presence-receipt",
      },
    };
    const options = { escalation: { mode: "MANAGED" as const } };
    const local = vi.fn(stubAuthority("ESCALATE").evaluate);
    const hosted = vi.fn(stubAuthority("ESCALATE").evaluate);

    await new ShadowGate({ evaluate: local }, { evaluate: hosted }, "SHADOW").evaluate(
      intent,
      evidence,
      options,
    );
    expect(local).toHaveBeenCalledWith(intent, evidence, options);
    expect(hosted).toHaveBeenCalledWith(intent, evidence, options);

    const failing: DecisionAuthority = {
      evaluate: async () => {
        throw new Error("LOCAL_FAILURE");
      },
    };
    await expect(
      new ShadowGate(failing, stubAuthority("ALLOW"), "SHADOW").evaluate(intent),
    ).rejects.toThrow("LOCAL_FAILURE");
  });

  it("declares the mode it can issue grants in, and rejects any other mode", () => {
    const local = stubAuthority("ALLOW");
    const hosted = stubAuthority("ALLOW");
    expect(new ShadowGate(local, hosted, "ENFORCEMENT").evaluationMode).toBe("ENFORCEMENT");
    expect(new ShadowGate(local, hosted, "SHADOW").evaluationMode).toBeUndefined();
    expect(
      new ShadowGate({ ...local, evaluationMode: "SHADOW" }, hosted, "SHADOW").evaluationMode,
    ).toBe("SHADOW");
    expect(
      () => new ShadowGate(local, hosted, "PARALLEL" as unknown as DecisionEvaluationMode),
    ).toThrow("DECIONIS_GATE_MODE_INVALID");
  });

  it("executes exactly as the fixture alone would when the hosted shadow evaluation blocks", async () => {
    const intent = captured();
    const { authority, verifier } = createFixtureAuthorityPair(() => "ALLOW", {
      unsafeAllowDevelopmentFixture: true,
    });
    const fetchMock = vi.fn<typeof fetch>(async () => json(verdictBody(intent, "BLOCK", "SHADOW")));
    const hosted = new DecionisGate({
      baseUrl: "http://127.0.0.1:3001",
      apiKey: "test-key",
      allowInsecureLoopback: true,
      fetch: fetchMock,
      mode: "SHADOW",
    });

    const decision = await new ShadowGate(authority, hosted, "SHADOW").evaluate(intent);
    const result = await new SafeExecutor(registry(), verifier).run(intent, decision);

    expect(decision.verdict).toBe("ALLOW");
    expect(decision.hosted).toMatchObject({
      mode: "SHADOW",
      governs: false,
      verdict: "BLOCK",
      decisionId: "decision-1",
      dossierId: "dossier-1",
      reasonCodes: ["POLICY_BLOCK"],
      failClosed: false,
    });
    expect(result.outcome).toBe("COMPLETED");
    expect(result.executed).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, request] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(request.body as string)).toMatchObject({ mode: "SHADOW" });
  });
});
