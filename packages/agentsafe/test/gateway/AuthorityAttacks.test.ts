import { describe, expect, it } from "vitest";
import { ATTACK_VERSION, runAuthorityAttacks } from "../../src/gateway/AuthorityAttacks.js";

/**
 * The six attacks `agentsafe test` shows, held to what each must produce.
 *
 * Asserting only `held` would pass if every attack were refused for the wrong
 * reason — a typo in a registry name refuses everything. So each one is
 * pinned to the refusal the lifecycle is supposed to raise for it.
 */
describe("the attacks after an authority is issued", () => {
  it("refuses all six, each with the refusal that belongs to it", async () => {
    const report = await runAuthorityAttacks();

    expect(report.version).toBe(ATTACK_VERSION);
    expect(report.attempts).toBe(6);
    expect(report.held).toBe(true);
    expect(Object.fromEntries(report.results.map((result) => [result.id, result.refusal]))).toEqual(
      {
        "exact-action-mutation": "INTENT_BINDING_MISMATCH",
        "target-substitution": "INTENT_BINDING_MISMATCH",
        replay: "AUTHORIZATION_INVALID",
        "workload-substitution": "WORKLOAD_MISMATCH",
        "boundary-substitution": "BOUNDARY_MISMATCH",
        "valid-identity-invalid-action": "DECISION_NOT_ALLOW",
      },
    );
    for (const result of report.results) {
      expect(result.held, result.id).toBe(true);
      expect(result.attempt.length, result.id).toBeGreaterThan(0);
      expect(result.expected.length, result.id).toBeGreaterThan(0);
    }
  });

  it("counts the one execution the replay had to make, and no other", async () => {
    const report = await runAuthorityAttacks();
    // A grant cannot be replayed until it has been claimed once. That single
    // authorized dispatch is the only one in the whole run.
    expect(report.executions).toBe(1);
    expect(report.results.find((result) => result.id === "replay")?.held).toBe(true);
  });

  it("is deterministic, so a second run says the same thing", async () => {
    const [first, second] = await Promise.all([runAuthorityAttacks(), runAuthorityAttacks()]);
    expect(second.results.map((result) => [result.id, result.refusal, result.held])).toEqual(
      first.results.map((result) => [result.id, result.refusal, result.held]),
    );
  });
});
