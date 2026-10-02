import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { HashChain } from "../../src/audit/HashChain.js";
import { EVIDENCE_STREAM } from "../../src/audit/HashChainedAuditSink.js";
import { readUsageReport } from "../../src/edge/UsageReport.js";
import {
  FileUsageDelivery,
  UrlUsageDelivery,
  UsageMeter,
  type UsageDelivery,
  type UsageMeterOptions,
} from "../../src/edge/UsageMeter.js";
import { collectedEvents } from "../support/Environment.js";
import { vectorKey } from "../support/UsageReportVector.js";

class RecordingDelivery implements UsageDelivery {
  public readonly kind = "file";
  public readonly reports: { period: string; installation: string; report: string }[] = [];
  public answers: string[] = [];

  public async deliver(period: string, installation: string, report: string): Promise<string> {
    this.reports.push({ period, installation, report });
    return this.answers.shift() ?? "DELIVERED";
  }
}

function harness(overrides: Partial<UsageMeterOptions> = {}, now = "2026-09-10T00:00:00.000Z") {
  const lines: string[] = [];
  const security: string[] = [];
  const events = collectedEvents(security);
  const chain = overrides.chain ?? new HashChain(EVIDENCE_STREAM);
  const clock = { now: Date.parse(now) };
  const delivery = new RecordingDelivery();
  const meter = new UsageMeter({
    orgId: "org-synthetic",
    chain,
    installationId: null,
    stateDir: null,
    checkpointLines: 1_000,
    events,
    key: () => vectorKey(),
    delivery,
    clock: () => clock.now,
    ...overrides,
  });
  /** Links a decision as EdgeRuntime.record does, counting it as its line is written. */
  const decide = (fields: Record<string, string | boolean> = {}): void => {
    const at = new Date(clock.now).toISOString();
    const record = {
      at,
      mode: "ENFORCEMENT",
      verdict: "ALLOW",
      delegated: false,
      jti: "jti-1",
      ...fields,
    };
    chain.link({ event: "EDGE_DECISION", ...record }, (line) => {
      lines.push(line);
      meter.observe({ ...record, seq: chain.head.seq, hash: chain.head.hash });
    });
  };
  const other = (): void => {
    chain.link({ event: "EXECUTION_COMPLETED" }, (line) => lines.push(line));
  };
  const securityEvents = (): Record<string, unknown>[] =>
    security.map((line) => JSON.parse(line) as Record<string, unknown>);
  return { meter, chain, clock, delivery, decide, other, lines, securityEvents };
}

const october = (day: number): number =>
  Date.parse(`2026-10-${String(day).padStart(2, "0")}T00:00:00.000Z`);

describe("UsageMeter", () => {
  it("counts this month's governed actions: decisions not delegated", () => {
    const { meter, decide } = harness();
    decide();
    decide({ verdict: "ESCALATE", delegated: true });
    decide({ mode: "SHADOW", verdict: "BLOCK" });
    expect(meter.governed()).toBe(2);
    expect(meter.reporting).toBe(true);
    expect(harness({ key: null }).meter.reporting).toBe(false);
  });

  it("reports each completed month once, signed, with what the chain counted", async () => {
    const { meter, decide, clock, delivery, securityEvents } = harness();
    decide();
    decide({ verdict: "ESCALATE", delegated: true, jti: "jti-2" });
    expect(meter.undelivered()).toEqual([]);
    await meter.report();
    expect(delivery.reports).toEqual([]);
    clock.now = october(1);
    decide();
    expect(meter.undelivered()).toEqual(["2026-09"]);
    await meter.report();
    expect(delivery.reports).toHaveLength(1);
    const sent = delivery.reports[0];
    expect(sent?.period).toBe("2026-09");
    expect(sent?.installation).toBe(meter.installationId);
    expect(meter.installationId).toMatch(/^inst_[0-9a-f-]{36}$/);
    const read = await readUsageReport(sent?.report ?? "", vectorKey().publicJwk);
    expect(read).toMatchObject({
      ok: true,
      claims: {
        iss: meter.installationId,
        aud: "org-synthetic",
        iat: october(1) / 1000,
        period: "2026-09",
        counts: { total: 2, by_verdict: { ALLOW: 1, ESCALATE: 1, BLOCK: 0 } },
        delegated: 1,
        chain: { stream: EVIDENCE_STREAM, first_seq: 1, last_seq: 2 },
        bundles: ["jti-1", "jti-2"],
      },
    });
    expect(securityEvents().at(-1)).toMatchObject({
      event: "EDGE_USAGE_REPORTED",
      period: "2026-09",
      destination: "file",
      total: 2,
    });
    expect(meter.undelivered()).toEqual([]);
    await meter.report();
    expect(delivery.reports).toHaveLength(1);
    // October's decision is still counted for October.
    expect(meter.governed()).toBe(1);
  });

  it("reports a month with nothing counted, so a quiet installation is never overdue", async () => {
    const { meter, clock, delivery } = harness({}, "2026-08-20T00:00:00.000Z");
    clock.now = october(2);
    expect(meter.undelivered()).toEqual(["2026-08", "2026-09"]);
    await meter.report();
    expect(delivery.reports.map((report) => report.period)).toEqual(["2026-08", "2026-09"]);
    const read = await readUsageReport(delivery.reports[1]?.report ?? "", vectorKey().publicJwk);
    expect(read).toMatchObject({
      ok: true,
      claims: { counts: { total: 0 }, chain: { first_seq: null, last_hash: null } },
    });
  });

  it("never reports a month that ended before the installation began, nor more than a year back", () => {
    const { meter, clock } = harness({}, "2026-09-30T23:59:59.999Z");
    clock.now = october(1);
    expect(meter.undelivered()).toEqual(["2026-09"]);
    const fresh = harness({}, "2026-10-01T00:00:00.000Z");
    fresh.clock.now = october(31);
    expect(fresh.meter.undelivered()).toEqual([]);
    const old = harness({}, "2020-01-15T00:00:00.000Z");
    old.clock.now = october(2);
    expect(old.meter.undelivered()).toEqual([
      "2025-10",
      "2025-11",
      "2025-12",
      "2026-01",
      "2026-02",
      "2026-03",
      "2026-04",
      "2026-05",
      "2026-06",
      "2026-07",
      "2026-08",
      "2026-09",
    ]);
  });

  it("keeps a report it could not deliver, says why, and delivers it on the next round", async () => {
    const { meter, decide, clock, delivery, securityEvents } = harness();
    decide();
    clock.now = october(1);
    delivery.answers = ["USAGE_HTTP_503"];
    await meter.report();
    expect(securityEvents().at(-1)).toEqual(
      expect.objectContaining({
        event: "EDGE_USAGE_REPORT_FAILED",
        period: "2026-09",
        code: "USAGE_HTTP_503",
      }),
    );
    expect(meter.undelivered()).toEqual(["2026-09"]);
    await meter.report();
    expect(meter.undelivered()).toEqual([]);
    const read = await readUsageReport(delivery.reports[1]?.report ?? "", vectorKey().publicJwk);
    expect(read).toMatchObject({ claims: { counts: { total: 1 } } });
  });

  it("does not report without a key or a destination, and says so when the key cannot sign", async () => {
    for (const overrides of [{ key: null }, { delivery: null }]) {
      const { meter, clock, delivery } = harness(overrides);
      clock.now = october(1);
      await meter.report();
      expect(delivery.reports).toEqual([]);
    }
    const broken = harness({
      key: () => {
        throw new Error("KEY_UNREADABLE");
      },
    });
    broken.clock.now = october(1);
    await broken.meter.report();
    expect(broken.securityEvents().at(-1)).toEqual(
      expect.objectContaining({ event: "EDGE_USAGE_REPORT_FAILED", code: "USAGE_SIGN_FAILED" }),
    );
    expect(broken.meter.undelivered()).toEqual(["2026-09"]);
  });

  it("persists the tally with the chain's head and resumes it on the same chain", async () => {
    const stateDir = join(mkdtempSync(join(tmpdir(), "usage-")), "edge");
    const first = harness({ stateDir, checkpointLines: 2 });
    first.decide();
    expect(existsSync(join(stateDir, "usage.json"))).toBe(false);
    first.other();
    expect(statSync(join(stateDir, "usage.json")).mode & 0o777).toBe(0o600);
    first.decide({ jti: "jti-2" });
    first.meter.stop();
    const persisted = JSON.parse(readFileSync(join(stateDir, "usage.json"), "utf8")) as Record<
      string,
      unknown
    >;
    expect(persisted).toMatchObject({
      version: 1,
      installation_id: first.meter.installationId,
      head: first.chain.head,
      delivered: [],
    });
    // The chain resumes from the head the journal persisted beside it.
    const chain = new HashChain(EVIDENCE_STREAM, first.chain.head);
    const second = harness({ stateDir, chain });
    expect(second.meter.installationId).toBe(first.meter.installationId);
    expect(second.meter.governed()).toBe(2);
    expect(second.securityEvents()).toEqual([]);
    second.clock.now = october(1);
    await second.meter.report();
    const read = await readUsageReport(
      second.delivery.reports[0]?.report ?? "",
      vectorKey().publicJwk,
    );
    expect(read).toMatchObject({
      claims: { counts: { total: 2 }, chain: { first_seq: 1, last_seq: 3 } },
    });
    const after = JSON.parse(readFileSync(join(stateDir, "usage.json"), "utf8")) as Record<
      string,
      unknown
    >;
    expect(after["delivered"]).toEqual(["2026-09"]);
    expect(after["periods"]).toEqual({});
  });

  it("drops a tally whose chain did not resume, and warns", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "usage-"));
    const first = harness({ stateDir });
    first.decide();
    first.meter.stop();
    const fromGenesis = harness({ stateDir });
    expect(fromGenesis.meter.installationId).not.toBe(first.meter.installationId);
    expect(fromGenesis.meter.governed()).toBe(0);
    expect(fromGenesis.securityEvents()).toEqual([
      expect.objectContaining({ event: "EDGE_USAGE_TALLY_RESET", head: 0 }),
    ]);
    const elsewhere = harness({
      stateDir,
      chain: new HashChain(EVIDENCE_STREAM, {
        seq: first.chain.head.seq,
        hash: `sha256:${"9".repeat(64)}`,
      }),
    });
    expect(elsewhere.securityEvents()[0]).toMatchObject({ event: "EDGE_USAGE_TALLY_RESET" });
  });

  it("keeps an installation id the operator chose, and drops a tally kept under another", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "usage-"));
    const first = harness({ stateDir, installationId: "branch-7.executor-0" });
    first.decide();
    first.meter.stop();
    expect(first.meter.installationId).toBe("branch-7.executor-0");
    const chain = new HashChain(EVIDENCE_STREAM, first.chain.head);
    const same = harness({ stateDir, chain, installationId: "branch-7.executor-0" });
    expect(same.meter.governed()).toBe(1);
    same.meter.stop();
    const renamed = harness({
      stateDir,
      chain: new HashChain(EVIDENCE_STREAM, first.chain.head),
      installationId: "branch-7.executor-1",
    });
    expect(renamed.meter.installationId).toBe("branch-7.executor-1");
    expect(renamed.meter.governed()).toBe(0);
    expect(renamed.securityEvents()[0]).toMatchObject({ event: "EDGE_USAGE_TALLY_RESET" });
  });

  it("ignores a state file it cannot read, and says when it cannot write one", () => {
    const directory = mkdtempSync(join(tmpdir(), "usage-"));
    writeFileSync(join(directory, "usage.json"), "{not json");
    const unreadable = harness({ stateDir: directory });
    expect(unreadable.securityEvents()).toEqual([]);
    writeFileSync(join(directory, "usage.json"), JSON.stringify({ version: 2 }));
    expect(harness({ stateDir: directory }).securityEvents()).toEqual([]);
    const blocked = join(directory, "blocked");
    writeFileSync(blocked, "a file where the directory should be");
    const failing = harness({ stateDir: blocked });
    failing.meter.stop();
    expect(failing.securityEvents()).toEqual([
      expect.objectContaining({ event: "EDGE_USAGE_PERSIST_FAILED" }),
    ]);
  });

  it("forgets months older than a report can still be made for", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "usage-"));
    const meterHarness = harness({ stateDir }, "2025-08-10T00:00:00.000Z");
    meterHarness.decide();
    meterHarness.clock.now = Date.parse("2025-09-02T00:00:00.000Z");
    await meterHarness.meter.report();
    meterHarness.clock.now = Date.parse("2025-09-03T00:00:00.000Z");
    meterHarness.decide();
    const persisted = (): { delivered: string[]; periods: Record<string, unknown> } =>
      JSON.parse(readFileSync(join(stateDir, "usage.json"), "utf8")) as {
        delivered: string[];
        periods: Record<string, unknown>;
      };
    // A year after August 2025 ends, its delivery is still inside the window...
    meterHarness.clock.now = Date.parse("2026-08-31T23:59:59.999Z");
    meterHarness.meter.stop();
    expect(persisted().delivered).toEqual(["2025-08"]);
    expect(Object.keys(persisted().periods)).toEqual(["2025-09"]);
    // ...and from September 2026 it is not.
    meterHarness.clock.now = Date.parse("2026-09-01T00:00:00.000Z");
    meterHarness.meter.stop();
    expect(persisted().delivered).toEqual([]);
    expect(Object.keys(persisted().periods)).toEqual(["2025-09"]);
    meterHarness.clock.now = october(1);
    meterHarness.meter.stop();
    expect(Object.keys(persisted().periods)).toEqual([]);
  });
});

describe("usage deliveries", () => {
  it("writes the report for an operator to upload, atomically and readable by the owner only", async () => {
    const directory = join(mkdtempSync(join(tmpdir(), "reports-")), "usage");
    const delivery = new FileUsageDelivery(directory);
    expect(delivery.kind).toBe("file");
    await expect(delivery.deliver("2026-09", "branch 7/executor", "a.b.c")).resolves.toBe(
      "DELIVERED",
    );
    const path = join(directory, "usage-2026-09-branch_7_executor.jws");
    expect(readFileSync(path, "utf8")).toBe("a.b.c\n");
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(existsSync(`${path}.tmp`)).toBe(false);
    const blocked = join(directory, "usage-2026-09-branch_7_executor.jws");
    await expect(new FileUsageDelivery(blocked).deliver("2026-09", "x", "a.b.c")).resolves.toBe(
      "USAGE_WRITE_FAILED",
    );
  });

  it("posts the report to Decionis with the organisation's key, and reads a duplicate as delivered", async () => {
    const requests: { url: string; init: RequestInit }[] = [];
    const answers = [
      new Response(JSON.stringify({ report: {} }), { status: 201 }),
      new Response(JSON.stringify({ replay: true }), { status: 200 }),
      new Response(JSON.stringify({ error: "USAGE_REPORT_DUPLICATE" }), { status: 409 }),
      new Response(JSON.stringify({ error: "USAGE_REPORT_CONCURRENT" }), { status: 409 }),
      new Response(JSON.stringify({ error: "USAGE_REPORT_KEY_UNKNOWN" }), { status: 422 }),
      new Response(JSON.stringify({ error: "VALIDATION_ERROR" }), { status: 400 }),
      new Response(JSON.stringify({ error: 7 }), { status: 409 }),
      new Response("<html>", { status: 503 }),
    ];
    const delivery = new UrlUsageDelivery({
      baseUrl: "https://api.decionis.example/",
      apiKey: () => "synthetic-api-key",
      fetch: (async (url: string, init: RequestInit) => {
        requests.push({ url, init });
        return answers.shift() ?? new Response("", { status: 500 });
      }) as typeof fetch,
    });
    expect(delivery.kind).toBe("url");
    const results: string[] = [];
    for (let attempt = 0; attempt < 8; attempt += 1) {
      results.push(await delivery.deliver("2026-09", "i", "a.b.c"));
    }
    expect(results).toEqual([
      "DELIVERED",
      "DELIVERED",
      "DELIVERED",
      "USAGE_REPORT_CONCURRENT",
      "USAGE_REPORT_KEY_UNKNOWN",
      "USAGE_HTTP_400",
      "USAGE_HTTP_409",
      "USAGE_HTTP_503",
    ]);
    expect(requests[0]?.url).toBe("https://api.decionis.example/v1/edge/usage-reports");
    expect(requests[0]?.init).toMatchObject({
      method: "POST",
      headers: {
        authorization: "Bearer synthetic-api-key",
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({ report: "a.b.c" }),
    });
    const down = new UrlUsageDelivery({
      baseUrl: "https://api.decionis.example",
      apiKey: () => "k",
      fetch: (async () => {
        throw new Error("ECONNREFUSED");
      }) as typeof fetch,
    });
    await expect(down.deliver("2026-09", "i", "a.b.c")).resolves.toBe("USAGE_SEND_FAILED");
  });
});
