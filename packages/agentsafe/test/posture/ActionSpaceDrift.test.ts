import { describe, expect, it, vi } from "vitest";
import type {
  CapturedIntent,
  DecisionAuthority,
  DecisionGate,
} from "@decionis/agent-safe-pipeline";
import { ActionSpaceDrift, MAX_REMEMBERED_RELEASES } from "../../src/posture/ActionSpaceDrift.js";

const digest = (n: number): string => `sha256:${n.toString(16).padStart(64, "0")}`;
const LOADED = digest(1);

function decision(actionManifestDigest?: string | null, decisionId = "decision-1"): DecisionGate {
  return {
    verdict: "ALLOW",
    decisionId,
    dossierId: null,
    intentHash: digest(99),
    reasonCodes: [],
    authorization: null,
    failClosed: false,
    ...(actionManifestDigest === undefined ? {} : { actionManifestDigest }),
  };
}

function drift(loaded: string | null = LOADED) {
  const recorded: [string, string][] = [];
  const check = new ActionSpaceDrift(loaded, (release, seen) =>
    recorded.push([release, seen.decisionId]),
  );
  return { check, recorded };
}

describe("the action space against the deciding release", () => {
  it("is unchecked until a decision names its release's action space", () => {
    const { check, recorded } = drift();
    expect(check.status()).toEqual({
      loaded: LOADED,
      release: null,
      state: "UNCHECKED",
      drifted: [],
    });
    // Absent or null, a decision names nothing to compare.
    check.observe(decision());
    check.observe(decision(null));
    expect(check.state).toBe("UNCHECKED");
    expect(recorded).toEqual([]);
  });

  it("reports nothing when the release was checked against what this gateway loaded", () => {
    const { check, recorded } = drift();
    check.observe(decision(LOADED));
    expect(check.status()).toEqual({
      loaded: LOADED,
      release: LOADED,
      state: "MATCH",
      drifted: [],
    });
    expect(recorded).toEqual([]);
  });

  it("records a drifting release once, and each other drifting release once", () => {
    const { check, recorded } = drift();
    check.observe(decision(digest(2), "decision-1"));
    check.observe(decision(digest(2), "decision-2"));
    expect(check.state).toBe("DRIFT");
    expect(recorded).toEqual([[digest(2), "decision-1"]]);
    check.observe(decision(digest(3), "decision-3"));
    // A decision that names none leaves the last answer standing.
    check.observe(decision(null, "decision-4"));
    expect(check.status()).toEqual({
      loaded: LOADED,
      release: digest(3),
      state: "DRIFT",
      drifted: [digest(2), digest(3)],
    });
    // A release that matches again shows as such; the record of the drift stays.
    check.observe(decision(LOADED, "decision-5"));
    check.observe(decision(digest(2), "decision-6"));
    expect(check.status().state).toBe("DRIFT");
    expect(recorded).toEqual([
      [digest(2), "decision-1"],
      [digest(3), "decision-3"],
    ]);
  });

  it("drifts on every named release when this gateway's action space has no digest", () => {
    const { check, recorded } = drift(null);
    check.observe(decision(LOADED));
    expect(check.state).toBe("DRIFT");
    expect(recorded).toEqual([[LOADED, "decision-1"]]);
  });

  it("remembers a bounded number of releases, and records a forgotten one again", () => {
    const { check, recorded } = drift();
    for (let n = 2; n < MAX_REMEMBERED_RELEASES + 3; n += 1) check.observe(decision(digest(n)));
    expect(recorded).toHaveLength(MAX_REMEMBERED_RELEASES + 1);
    expect(check.status().drifted).toHaveLength(MAX_REMEMBERED_RELEASES);
    expect(check.status().drifted[0]).toBe(digest(3));
    check.observe(decision(digest(3)));
    expect(recorded).toHaveLength(MAX_REMEMBERED_RELEASES + 1);
    check.observe(decision(digest(2)));
    expect(recorded).toHaveLength(MAX_REMEMBERED_RELEASES + 2);
    expect(check.status().drifted.at(-1)).toBe(digest(2));
  });

  it("never lets a record that cannot be written reach the decision", () => {
    const check = new ActionSpaceDrift(LOADED, () => {
      throw new Error("DISK_FULL");
    });
    expect(() => check.observe(decision(digest(2)))).not.toThrow();
    expect(check.state).toBe("DRIFT");
  });

  it("observes each decision an authority returns, and returns it unchanged", async () => {
    const { check, recorded } = drift();
    const answer = decision(digest(2));
    const evaluate = vi.fn<DecisionAuthority["evaluate"]>(async () => answer);
    const observed = check.observing({ evaluationMode: "SHADOW", evaluate });
    expect(observed.evaluationMode).toBe("SHADOW");
    const captured = { intentHash: digest(99) } as CapturedIntent;
    const evidence = { signals: [{ token: "a.b.c" }] };
    const options = { escalation: { mode: "MANAGED" as const } };
    await expect(observed.evaluate(captured, evidence, options)).resolves.toBe(answer);
    expect(evaluate).toHaveBeenCalledWith(captured, evidence, options);
    expect(recorded).toEqual([[digest(2), "decision-1"]]);
    // An authority that declares no mode is handed on declaring none.
    expect(check.observing({ evaluate })).not.toHaveProperty("evaluationMode");
  });
});
