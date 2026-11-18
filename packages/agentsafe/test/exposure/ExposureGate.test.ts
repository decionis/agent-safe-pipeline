import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { ChainFields } from "../../src/audit/HashChain.js";
import type { ExposureFacts } from "../../src/exposure/ExposureFacts.js";
import { ExposureGate } from "../../src/exposure/ExposureGate.js";
import {
  ExposureUnavailable,
  type ExposureAnswer,
  type ExposureLedger,
  type ExposureLimit,
  type ExposureReservationRequest,
} from "../../src/exposure/ExposureLedger.js";

const ORG = "00000000-0000-4000-8000-0000000000AA";
const binding = {
  intentId: "11111111-1111-4111-8111-111111111111",
  intentHash: `sha256:${"ab".repeat(32)}`,
  capturedAt: "2026-11-18T10:00:00.000Z",
};
const facts: ExposureFacts = {
  actionType: "PAYMENT_RELEASE",
  amount: 700,
  currency: "USD",
  subjects: { vendor: " Vendor-1 ", agent: "agent-a" },
};

function limit(overrides: Partial<ExposureLimit> & { key: string }): ExposureLimit {
  return {
    kind: "payment_release",
    subject: "org",
    onExceed: "ESCALATE",
    actionTypes: ["PAYMENT_RELEASE"],
    ...overrides,
  };
}

/** A scripted ledger: answers by limit key, and remembers what it was asked. */
class ScriptedLedger implements ExposureLedger {
  public readonly reserves: { key: string; request: ExposureReservationRequest }[] = [];
  public readonly ends: string[] = [];
  public limitsError: ExposureUnavailable | null = null;
  public endErrors: ExposureUnavailable[] = [];

  public constructor(
    private readonly list: readonly ExposureLimit[],
    private readonly answers: Record<string, ExposureAnswer | ExposureUnavailable> = {},
  ) {}

  public limits(): Promise<readonly ExposureLimit[]> {
    return this.limitsError === null
      ? Promise.resolve(this.list)
      : Promise.reject(this.limitsError);
  }

  public reserve(key: string, request: ExposureReservationRequest): Promise<ExposureAnswer> {
    this.reserves.push({ key, request });
    const answer = this.answers[key] ?? {
      decision: "PROCEED",
      reasonCode: "EXPOSURE_WITHIN_LIMIT",
      reservationId: `r-${key}`,
      replayed: false,
    };
    return answer instanceof ExposureUnavailable ? Promise.reject(answer) : Promise.resolve(answer);
  }

  public settle(key: string, id: string, amount?: number): Promise<void> {
    return this.end(`settle:${key}:${id}:${String(amount)}`);
  }

  public release(key: string, id: string): Promise<void> {
    return this.end(`release:${key}:${id}`);
  }

  private end(call: string): Promise<void> {
    this.ends.push(call);
    const error = this.endErrors.shift();
    return error === undefined ? Promise.resolve() : Promise.reject(error);
  }
}

function gateFor(ledger: ExposureLedger, actorType = "agent") {
  const lines: ChainFields[] = [];
  const counts: string[] = [];
  const gate = new ExposureGate({
    ledger,
    orgId: ORG,
    actorType,
    evidence: (fields) => lines.push(fields),
    count: (outcome) => counts.push(outcome),
    sleep: () => Promise.resolve(),
  });
  return { gate, lines, counts };
}

describe("the exposure gate", () => {
  it("digests subjects as Commerce does: versioned, org-scoped, trimmed and lower-cased", () => {
    const { gate } = gateFor(new ScriptedLedger([]));
    const expected = createHash("sha256")
      .update(["decionis-exposure-v1", ORG.toLowerCase(), "vendor", "vendor-1"].join("\n"))
      .digest("hex");
    expect(gate.digest("vendor", " Vendor-1 ")).toBe(expected);
    expect(gate.digest("vendor", "VENDOR-1")).toBe(expected);
  });

  it("reserves only against limits whose action type, actor type and subject it can state", async () => {
    const ledger = new ScriptedLedger([
      limit({ key: "b-vendor", subject: "vendor" }),
      limit({ key: "a-org" }),
      limit({ key: "refunds", actionTypes: ["REFUND_REQUEST"] }),
      limit({ key: "humans", actorTypes: ["user"] }),
      limit({ key: "per-customer", subject: "customer" }),
    ]);
    const { gate, lines } = gateFor(ledger);
    const check = await gate.reserve(facts, binding, false);
    expect(check).toEqual({
      status: "WITHIN_LIMIT",
      held: [
        { limitKey: "a-org", reservationId: "r-a-org" },
        { limitKey: "b-vendor", reservationId: "r-b-vendor" },
      ],
      unstated: ["per-customer"],
    });
    expect(ledger.reserves.map((entry) => entry.key)).toEqual(["a-org", "b-vendor"]);
    expect(lines[0]).toMatchObject({ event: "EXPOSURE_RESERVED", unstated: ["per-customer"] });
  });

  it("binds each reservation to its request and keeps it stable for the same intent", async () => {
    const ledger = new ScriptedLedger([limit({ key: "v", subject: "vendor" })]);
    const { gate } = gateFor(ledger);
    await gate.reserve(facts, binding, false);
    await gate.reserve(facts, binding, false);
    const [first, second] = ledger.reserves.map((entry) => entry.request);
    expect(first).toEqual(second);
    expect(first).toMatchObject({
      reservation_key: `agentsafe:${"ab".repeat(32)}`,
      occurred_at: binding.capturedAt,
      source: { platform: "agentsafe", channel: "gateway", record_id: binding.intentId },
    });
    expect(first?.actor).toBeUndefined();
    await gate.reserve({ ...facts, amount: 701 }, binding, false);
    expect(ledger.reserves[2]?.request.request_digest).not.toBe(first?.request_digest);
  });

  it("reserves a retry under the key of the attempt it retries, and only a well-formed one", () => {
    const earlier = `agentsafe:${"cd".repeat(32)}`;
    const own = `agentsafe:${"ab".repeat(32)}`;
    expect(ExposureGate.reservationKey({ ...binding, retryOf: earlier })).toBe(earlier);
    // Shadow never takes an enforced key; a malformed record is never used.
    expect(ExposureGate.reservationKey({ ...binding, retryOf: earlier }, true)).toBe(
      `agentsafe-shadow:${"ab".repeat(32)}`,
    );
    for (const retryOf of [`agentsafe-shadow:${"cd".repeat(32)}`, "agentsafe:short", ""]) {
      expect(ExposureGate.reservationKey({ ...binding, retryOf })).toBe(own);
    }
  });

  it("states the actor and the step for a sequence limit, and skips one it cannot", async () => {
    const ledger = new ScriptedLedger([
      limit({
        key: "sod",
        kind: "sequence",
        subject: "vendor",
        steps: ["vendor_bank_change", "payment_release"],
      }),
      limit({
        key: "sod-other",
        kind: "sequence",
        subject: "vendor",
        steps: ["invoice_post", "vendor_create"],
      }),
    ]);
    const { gate } = gateFor(ledger);
    await gate.reserve(facts, binding, false);
    expect(ledger.reserves).toHaveLength(1);
    expect(ledger.reserves[0]?.request).toMatchObject({
      step: "payment_release",
      actor: { kind: "agent", id_digest: gate.digest("actor", "agent-a") },
    });
  });

  it("counts nothing for a zero amount, except a sequence step", async () => {
    const ledger = new ScriptedLedger([limit({ key: "org" })]);
    const { gate, counts } = gateFor(ledger);
    expect(await gate.reserve({ ...facts, amount: 0 }, binding, false)).toMatchObject({
      status: "WITHIN_LIMIT",
      held: [],
    });
    expect(counts).toEqual(["NOT_APPLICABLE"]);
  });

  it("gives back what it held when a later limit refuses", async () => {
    const ledger = new ScriptedLedger(
      [limit({ key: "a" }), limit({ key: "b" }), limit({ key: "c" })],
      {
        b: {
          decision: "HOLD",
          reasonCode: "EXPOSURE_LIMIT_EXCEEDED",
          reservationId: null,
          replayed: false,
        },
      },
    );
    const { gate } = gateFor(ledger);
    const check = await gate.reserve(facts, binding, false);
    expect(check).toMatchObject({ status: "EXCEEDED", limitKey: "b", onExceed: "HOLD" });
    expect(ledger.reserves.map((entry) => entry.key)).toEqual(["a", "b"]);
    expect(ledger.ends).toEqual(["release:a:r-a"]);
    expect(await gate.conclude(check, "NOT_EXECUTED", binding)).toBe("NONE");
  });

  it("releases on a fault unless the route fails open", async () => {
    const fault = new ExposureUnavailable("EXPOSURE_POLICY_INVALID", false);
    const closed = new ScriptedLedger([limit({ key: "a" }), limit({ key: "b" })], { b: fault });
    const { gate, lines } = gateFor(closed);
    expect(await gate.reserve(facts, binding, false)).toMatchObject({
      status: "UNAVAILABLE",
      code: "EXPOSURE_POLICY_INVALID",
      held: [],
      ungoverned: false,
    });
    expect(closed.ends).toEqual(["release:a:r-a"]);
    expect(lines.at(-1)).toMatchObject({ event: "EXPOSURE_UNAVAILABLE" });

    const open = new ScriptedLedger([limit({ key: "a" }), limit({ key: "b" })], { b: fault });
    const opened = gateFor(open);
    const check = await opened.gate.reserve(facts, binding, true);
    expect(check).toMatchObject({
      status: "UNAVAILABLE",
      held: [{ limitKey: "a" }],
      ungoverned: true,
    });
    expect(open.ends).toEqual([]);
    expect(await opened.gate.conclude(check, "COMMITTED", binding, 650)).toBe("SETTLED");
    expect(open.ends).toEqual(["settle:a:r-a:650"]);
  });

  it("does not retry what cannot be retried without counting twice", async () => {
    const ledger = new ScriptedLedger([limit({ key: "a" })], {
      a: new ExposureUnavailable("EXPOSURE_RESERVATION_CONFLICT", false),
    });
    const { gate } = gateFor(ledger);
    expect(await gate.reserve(facts, binding, false)).toMatchObject({ status: "UNAVAILABLE" });
    expect(ledger.reserves).toHaveLength(1);
  });

  it("retries limits when the ledger is briefly away, then fails closed", async () => {
    const ledger = new ScriptedLedger([limit({ key: "a" })]);
    ledger.limitsError = new ExposureUnavailable("EXPOSURE_UNREACHABLE", true);
    const { gate } = gateFor(ledger);
    expect(await gate.reserve(facts, binding, false)).toMatchObject({
      status: "UNAVAILABLE",
      code: "EXPOSURE_UNREACHABLE",
    });
  });

  it("releases on a payment not executed, keeps on an unknown one, and records an end that failed", async () => {
    const ledger = new ScriptedLedger([limit({ key: "a" })]);
    const { gate, lines, counts } = gateFor(ledger);
    const check = await gate.reserve(facts, binding, false);
    expect(await gate.conclude(check, "INDETERMINATE", binding)).toBe("KEPT");
    expect(ledger.ends).toEqual([]);
    ledger.endErrors = [
      new ExposureUnavailable("EXPOSURE_HTTP_500", true),
      new ExposureUnavailable("EXPOSURE_HTTP_500", true),
      new ExposureUnavailable("EXPOSURE_HTTP_500", true),
    ];
    expect(await gate.conclude(check, "NOT_EXECUTED", binding)).toBe("FAILED");
    expect(ledger.ends).toHaveLength(3);
    expect(lines.find((line) => line["event"] === "EXPOSURE_RELEASE_FAILED")).toMatchObject({
      limit_key: "a",
      reservation_id: "r-a",
      reason_code: "EXPOSURE_HTTP_500",
    });
    expect(counts).toContain("RELEASE_FAILED");
    expect(await gate.conclude(check, "NOT_EXECUTED", binding)).toBe("RELEASED");
  });

  it("in shadow, previews read-only when the ledger can say a subject's usage", async () => {
    const asked: string[] = [];
    class ReadingLedger extends ScriptedLedger {
      public constructor(
        list: readonly ExposureLimit[],
        private readonly usage: Record<string, { currency: string; used: number }[] | null>,
        private readonly fault: ExposureUnavailable | null = null,
      ) {
        super(list);
      }
      public subjectUsage(kind: string, digest: string) {
        asked.push(`${kind}:${digest}`);
        if (this.fault !== null) return Promise.reject(this.fault);
        return Promise.resolve(new Map(Object.entries(this.usage)));
      }
    }
    const caps = (max: number) => [{ currency: facts.currency, maxAmount: max }];
    const at = (used: number) => [{ currency: facts.currency, used }];
    // Exactly at the cap is within it, one minor unit over is not: the ledger's own comparison.
    const within = new ReadingLedger([limit({ key: "org", caps: caps(facts.amount + 100) })], {
      org: at(100),
    });
    expect(await gateFor(within).gate.observe(facts, binding)).toMatchObject({
      status: "WITHIN_LIMIT",
    });
    expect(within.reserves).toHaveLength(0);
    expect(within.ends).toHaveLength(0);
    expect(asked.at(-1)).toBe(`vendor:${"0".repeat(64)}`);
    const over = new ReadingLedger([limit({ key: "org", caps: caps(facts.amount + 100) })], {
      org: at(101),
    });
    const { gate, lines } = gateFor(over);
    expect(await gate.observe(facts, binding)).toMatchObject({
      status: "EXCEEDED",
      limitKey: "org",
      reasonCode: "EXPOSURE_LIMIT_EXCEEDED",
    });
    expect(over.reserves).toHaveLength(0);
    expect(lines.at(-1)).toMatchObject({
      event: "EXPOSURE_OBSERVED",
      would: "EXCEEDED",
      read_only: true,
    });
    // A currency without a cap is not limited; a sequence limit counts steps and is named.
    const sequence = new ReadingLedger(
      [
        limit({ key: "uncapped", caps: [{ currency: "XXX", maxAmount: 1 }] }),
        limit({ key: "sod", kind: "sequence", subject: "vendor", steps: ["payment_release"] }),
      ],
      { uncapped: at(0), sod: null },
    );
    const seq = gateFor(sequence);
    expect(await seq.gate.observe(facts, binding)).toMatchObject({ status: "WITHIN_LIMIT" });
    expect(seq.lines.at(-1)).toMatchObject({ unpreviewed: ["sod"] });
    // The read failing is unavailable, as a reservation failing is.
    const down = new ReadingLedger(
      [limit({ key: "org", caps: caps(1) })],
      {},
      new ExposureUnavailable("EXPOSURE_HTTP_503", true),
    );
    expect(await gateFor(down).gate.observe(facts, binding)).toMatchObject({
      status: "UNAVAILABLE",
      code: "EXPOSURE_HTTP_503",
    });
  });

  it("in shadow, reserves under a key of its own and releases at once", async () => {
    const ledger = new ScriptedLedger([limit({ key: "a" })]);
    const { gate, lines } = gateFor(ledger);
    expect(await gate.observe(facts, binding)).toMatchObject({ status: "WITHIN_LIMIT" });
    expect(ledger.reserves[0]?.request.reservation_key).toBe(`agentsafe-shadow:${"ab".repeat(32)}`);
    expect(ledger.ends).toEqual(["release:a:r-a"]);
    expect(lines.at(-1)).toMatchObject({ event: "EXPOSURE_OBSERVED", would: "WITHIN_LIMIT" });
  });

  it("never lets an evidence line that cannot be written change an outcome", async () => {
    const gate = new ExposureGate({
      ledger: new ScriptedLedger([limit({ key: "a" })]),
      orgId: ORG,
      actorType: "agent",
      evidence: () => {
        throw new Error("JOURNAL_UNAVAILABLE");
      },
    });
    expect(await gate.reserve(facts, binding, false)).toMatchObject({ status: "WITHIN_LIMIT" });
  });
});
