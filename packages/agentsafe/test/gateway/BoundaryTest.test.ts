import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  BOUNDARY_CASES,
  BOUNDARY_TEST_VERSION,
  runBoundaryTest,
  type BoundaryCase,
  type BoundaryTestReport,
} from "../../src/gateway/BoundaryTest.js";
import { startDemoAuthority, type DemoAuthorityHandle } from "../../src/gateway/DemoAuthority.js";

let authority: DemoAuthorityHandle;
let report: BoundaryTestReport;

const shared = (): Promise<DemoAuthorityHandle> =>
  Promise.resolve({ baseUrl: authority.baseUrl, apiKey: authority.apiKey, stop: async () => {} });

const byId = (id: string) => {
  const result = report.cases.find((candidate) => candidate.id === id);
  if (result === undefined) throw new Error(`no case ${id}`);
  return result;
};

beforeAll(async () => {
  authority = await startDemoAuthority();
  report = await runBoundaryTest({ version: "9.9.9-test", demoAuthority: shared });
}, 30_000);

afterAll(async () => {
  await authority.stop();
});

describe("the boundary test", () => {
  it("reports every case the three ways, and holds", () => {
    expect(report.version).toBe(BOUNDARY_TEST_VERSION);
    expect(report.runtime).toBe("9.9.9-test");
    expect(report.authority).toBe("local/demo");
    expect(report.target).toBe("synthetic loopback");
    expect(report.cases.map((result) => result.id)).toEqual(BOUNDARY_CASES.map((c) => c.id));
    expect(report.exposure).toEqual({ adversarial: 6, direct: 6, shadow: 6, enforcement: 0 });
    expect(report.workFlowed).toBe(true);
    expect(report.evidence.verified).toBe(true);
    expect(report.evidence.lines).toBeGreaterThan(10);
    expect(report.verdict).toBe("BOUNDARY_HOLDS");
    expect(Date.parse(report.at)).not.toBeNaN();
  });

  it("lets a read and a routine payment through, the payment once, with a dossier", () => {
    const read = byId("read");
    expect(read.direct.reached).toBe(true);
    expect(read.shadow).toMatchObject({ reached: true, state: null, verdict: null });
    expect(read.enforcement).toMatchObject({ reached: true, state: null, status: 200 });
    const routine = byId("routine-payment");
    expect(routine.shadow).toMatchObject({ reached: true, state: "SHADOW", verdict: "ALLOW" });
    expect(routine.enforcement).toMatchObject({
      reached: true,
      forwarded: 1,
      status: 201,
      state: "ALLOW",
      verdict: "ALLOW",
      execution: "FORWARDED",
      dossier: true,
    });
  });

  it("refuses, holds and never forwards what the policy stops", () => {
    expect(byId("large-payment").shadow).toMatchObject({ reached: true, verdict: "BLOCK" });
    expect(byId("large-payment").enforcement).toMatchObject({
      reached: false,
      forwarded: 0,
      status: 403,
      state: "BLOCK",
      execution: "NOT_FORWARDED",
    });
    for (const id of ["approval-payment", "destructive-delete", "unreadable-body"]) {
      expect(byId(id).direct.reached, id).toBe(true);
      expect(byId(id).shadow, id).toMatchObject({ reached: true, verdict: "ESCALATE" });
      expect(byId(id).enforcement, id).toMatchObject({
        reached: false,
        status: 202,
        state: "ESCALATE",
        execution: "HELD",
      });
    }
  });

  it("shows a forged approval reaching the target directly and changing nothing at the boundary", () => {
    const forged = byId("forged-approval");
    expect(forged.direct.forgedHeadersReached).toBe(true);
    expect(forged.shadow.forgedHeadersReached).toBe(false);
    expect(forged.enforcement).toMatchObject({ reached: false, state: "BLOCK", status: 403 });
    expect(forged.enforcement.forgedHeadersReached).toBe(false);
  });

  it("fails closed in an outage, and shows what the explicit fail-open policy would do instead", () => {
    const outage = byId("authority-outage");
    expect(outage.direct.reached).toBe(true);
    expect(outage.shadow).toMatchObject({ reached: true, state: "SHADOW", verdict: null });
    expect(outage.enforcement).toMatchObject({
      reached: false,
      status: 503,
      state: "AUTHORITY_UNAVAILABLE",
      verdict: null,
      execution: "NOT_FORWARDED",
    });
    expect(outage.failOpen).toMatchObject({
      reached: true,
      forwarded: 1,
      state: "AUTHORITY_UNAVAILABLE",
      execution: "FORWARDED_UNGOVERNED",
    });
    for (const result of report.cases) {
      if (result.id !== "authority-outage") expect(result.failOpen, result.id).toBeNull();
    }
  });

  it("calls the boundary broken when something adversarial gets through or routine work does not", async () => {
    const allowed: BoundaryCase = {
      id: "misfiled",
      title: "A small payment filed as adversarial",
      adversarial: true,
      method: "POST",
      path: "/payments",
      headers: { "content-type": "application/json" },
      body: '{"amount":5}',
      outage: false,
    };
    const broken = await runBoundaryTest({
      version: "1",
      cases: [allowed],
      demoAuthority: shared,
    });
    expect(broken.exposure).toEqual({ adversarial: 1, direct: 1, shadow: 1, enforcement: 1 });
    expect(broken.verdict).toBe("BOUNDARY_BROKEN");
    const stopped = await runBoundaryTest({
      version: "1",
      cases: [{ ...allowed, adversarial: false, body: '{"amount":25000}' }],
      demoAuthority: shared,
    });
    expect(stopped.workFlowed).toBe(false);
    expect(stopped.verdict).toBe("BOUNDARY_BROKEN");
  });

  it("records a request the transport refused as not reached, and an observation that never came as none", async () => {
    const unsendable: BoundaryCase = {
      id: "unsendable",
      title: "A request no transport accepts",
      adversarial: true,
      method: "POST",
      path: "/payments",
      headers: { "bad header": "x" },
      body: "{}",
      outage: false,
    };
    const run = await runBoundaryTest({
      version: "1",
      cases: [unsendable, BOUNDARY_CASES[1] as BoundaryCase],
      demoAuthority: shared,
      observationTimeoutMs: 0,
    });
    const [none, routine] = run.cases;
    expect(none?.direct).toMatchObject({ reached: false, status: null, execution: null });
    expect(none?.enforcement).toMatchObject({ reached: false, status: null, state: null });
    expect(routine?.shadow).toMatchObject({ reached: true, state: "SHADOW" });
    expect(run.exposure.enforcement).toBe(0);
  });
});
