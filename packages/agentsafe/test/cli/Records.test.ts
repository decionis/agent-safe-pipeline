import { describe, expect, it } from "vitest";
import { writeCredentials } from "../../src/cli/Credentials.js";
import { RECORDS_COMMANDS, runRecords } from "../../src/cli/Records.js";
import { packageVersion } from "../../src/Version.js";
import { fakeProcess } from "../support/GatewayHarness.js";

const lastJson = (lines: readonly string[]): Record<string, unknown> =>
  JSON.parse(lines.at(-1) ?? "null") as Record<string, unknown>;

/** Two synthetic commerce records: a payment to a recently changed account, and a duplicate. */
const records = [
  {
    occurred_at: "2026-09-10T23:59:59.999Z",
    amount: { currency: "USD", scale: 2, amount_minor: 1_250_000 },
    action: {
      actor: { type: "ERP", id: "business-central" },
      platform: "business-central",
      idempotency_key: "bc:payment-0001",
      action_type: "PAYMENT_RELEASE",
      payload: {
        payment_id: "a".repeat(64),
        vendor_id: "b".repeat(64),
        amount: 12_500,
        currency: "USD",
      },
    },
    facts: {
      observed_at: "2026-09-10T23:59:59.999Z",
      source: "business-central.history",
      currency: "USD",
      beneficiary: { changed_at: "2026-09-07T23:59:59.999Z" },
      payment: { prior_payment_count: 0 },
    },
  },
  {
    occurred_at: "2026-09-12T23:59:59.999Z",
    amount: { currency: "USD", scale: 2, amount_minor: 30_000 },
    action: {
      actor: { type: "ERP", id: "business-central" },
      platform: "business-central",
      idempotency_key: "bc:payment-0002",
      action_type: "PAYMENT_RELEASE",
      payload: {
        payment_id: "c".repeat(64),
        vendor_id: "d".repeat(64),
        amount: 300,
        currency: "USD",
      },
    },
    facts: {
      observed_at: "2026-09-12T23:59:59.999Z",
      source: "business-central.history",
      currency: "USD",
      beneficiary: { changed_at: null },
      payment: { prior_payment_count: 1 },
    },
  },
];
const file = `${records.map((record) => JSON.stringify(record)).join("\n")}\n`;
const KEY = "synthetic-key";
const POLICY = "30000000-0000-4000-8000-000000000001";
const args = [
  "upload",
  "payments.jsonl",
  "--kind",
  "transaction",
  "--platform",
  "business-central",
  "--from",
  "2026-07-03T00:00:00.000Z",
  "--to",
  "2026-10-01T00:00:00.000Z",
];
const signed = {
  version: "decionis.assessments.records/1",
  domain: "commerce",
  received: 2,
  assessed: 2,
  policy_id: POLICY,
  findings: {
    verification: "signed",
    artifact: {
      findings_id: "60000000-0000-4000-8000-000000000001",
      status: "complete",
      findings: [
        { type: "PaymentToRecentlyChangedBeneficiary" },
        { type: "DuplicateInvoicePayment" },
      ],
      coverage: { gaps: [] },
    },
  },
};

function recorder(status = 201, body: unknown = signed) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetch = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status });
  }) as unknown as typeof globalThis.fetch;
  return { calls, fetch };
}

describe("agentsafe records upload", () => {
  it("sends a JSON Lines file to the central policy intake with this machine's key", async () => {
    const { calls, fetch } = recorder();
    const io = fakeProcess({
      env: { DECIONIS_API_KEY: KEY },
      files: { "payments.jsonl": file },
      fetch,
    });
    await runRecords(io, [...args, "--policy", POLICY, "--total", "2"]);
    expect(io.exits).toEqual([0]);
    expect(calls).toHaveLength(1);
    const [call] = calls;
    expect(call!.url).toMatch(
      /^https:\/\/api\.decionis\.com\/v1\/assessments\/[0-9a-f-]{36}\/records$/,
    );
    expect((call!.init.headers as Record<string, string>).authorization).toBe(`Bearer ${KEY}`);
    const body = JSON.parse(String(call!.init.body)) as Record<string, unknown>;
    expect(body).toMatchObject({
      version: "decionis.assessments.records/1",
      domain: "commerce",
      kind: "transaction",
      platform: "business-central",
      producer: { product: "agentsafe", surface: "cli", version: packageVersion() },
      as_of: "2026-10-01T00:00:00.000Z",
      window: { from: "2026-07-03T00:00:00.000Z", to: "2026-10-01T00:00:00.000Z" },
      policy_id: POLICY,
      total: 2,
      truncated: false,
      file: { format: "jsonl", name: "payments.jsonl", content: file },
    });
    expect(call!.url).toContain(String(body.assessment_id));
    const out = io.out.join("");
    expect(out).toContain(
      "Signed findings 60000000-0000-4000-8000-000000000001 (signed, complete).",
    );
    expect(out).toContain("1 PaymentToRecentlyChangedBeneficiary, 1 DuplicateInvoicePayment");
    expect(out).toContain("nothing changed in any policy");
  });

  it("maps the same file and window to the same assessment, and prints JSON on request", async () => {
    const first = recorder();
    const again = recorder(200);
    for (const { fetch } of [first, again]) {
      const io = fakeProcess({
        env: { DECIONIS_API_KEY: KEY },
        files: { "payments.jsonl": file },
        fetch,
      });
      await runRecords(io, [...args, "--json"]);
      expect(io.exits).toEqual([0]);
      expect(JSON.parse(io.out.join(""))).toMatchObject({ assessed: 2 });
    }
    expect(first.calls[0]!.url).toBe(again.calls[0]!.url);
  });

  it("uses the stored login and its endpoint when no key is set", async () => {
    const { calls, fetch } = recorder();
    const io = fakeProcess({ files: { "payments.jsonl": file }, fetch });
    writeCredentials(io, { apiKey: KEY, tenantId: null, endpoint: "https://api.decionis.example" });
    await runRecords(io, args);
    expect(io.exits).toEqual([0]);
    expect(calls[0]!.url.startsWith("https://api.decionis.example/v1/assessments/")).toBe(true);
    expect((calls[0]!.init.headers as Record<string, string>).authorization).toBe(`Bearer ${KEY}`);
  });

  it("relays Decionis's refusal with the line it names", async () => {
    const { fetch } = recorder(422, { error: "ASSESSMENT_RECORD_INVALID", record: 2 });
    const io = fakeProcess({
      env: { DECIONIS_API_KEY: KEY },
      files: { "payments.jsonl": file },
      fetch,
    });
    await runRecords(io, args);
    expect(io.exits).toEqual([1]);
    expect(lastJson(io.err)).toEqual({
      event: "RECORDS_REFUSED",
      status: 422,
      error: "ASSESSMENT_RECORD_INVALID",
      record: 2,
    });
  });

  it("refuses locally before sending anything", async () => {
    const cases: [readonly string[], Record<string, string>, Record<string, string>, string][] = [
      [
        args,
        { "payments.jsonl": `${file}not json\n` },
        { DECIONIS_API_KEY: KEY },
        "LINE_INVALID: 3",
      ],
      [args, {}, { DECIONIS_API_KEY: KEY }, "FILE_UNREADABLE"],
      [args, { "payments.jsonl": "\n\n" }, { DECIONIS_API_KEY: KEY }, "FILE_EMPTY"],
      [args, { "payments.jsonl": file }, {}, "KEY_REQUIRED"],
      [
        [...args.slice(0, 7), "2026-10-02T00:00:00.000Z", ...args.slice(8)],
        { "payments.jsonl": file },
        { DECIONIS_API_KEY: KEY },
        "WINDOW_INVALID",
      ],
      [
        [...args, "--domain", "loans"],
        { "payments.jsonl": file },
        { DECIONIS_API_KEY: KEY },
        "DOMAIN_INVALID",
      ],
      [
        [...args, "--endpoint", "http://api.decionis.example"],
        { "payments.jsonl": file },
        { DECIONIS_API_KEY: KEY },
        "ENDPOINT_INVALID",
      ],
    ];
    for (const [argv, files, env, code] of cases) {
      const { calls, fetch } = recorder();
      const io = fakeProcess({ env, files, fetch });
      await runRecords(io, argv);
      expect(io.exits).toEqual([2]);
      expect(lastJson(io.err)).toMatchObject({ event: "RECORDS_USAGE", code });
      expect(calls).toHaveLength(0);
    }
    const unknown = fakeProcess();
    await runRecords(unknown, ["download"]);
    expect(unknown.exits).toEqual([2]);
    expect(lastJson(unknown.err)).toEqual({
      event: "RECORDS_COMMAND_REQUIRED",
      commands: [...RECORDS_COMMANDS],
    });
  });
});
