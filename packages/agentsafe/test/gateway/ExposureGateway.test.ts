import { createHash } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { Gateway } from "../../src/gateway/Gateway.js";
import type { InterceptedRequest } from "../../src/gateway/InterceptedRequest.js";
import {
  collectedIo,
  testConfig,
  UpstreamDouble,
  type CollectedIo,
} from "../support/GatewayHarness.js";
import { ExposureLedgerDouble } from "../support/ExposureLedgerDouble.js";

const TENANT = "00000000-0000-4000-8000-000000000009";
const VENDOR = "Vendor-ACME-0042";
const AGENT = "agent-payables-7";
const exposure = {
  amount: "/body/amount_minor",
  currency: "/body/currency",
  subjects: { vendor: "/body/payee_id", agent: "/headers/x-agent-id" },
};
const FILE = {
  version: 1,
  interception: {
    routes: [
      { path: "/payments", action: "payment.release", methods: ["POST"], exposure },
      { path: "/refuse/payments", action: "payment.release", methods: ["POST"], exposure },
      { path: "/fail/payments", action: "payment.release", methods: ["POST"], exposure },
      {
        path: "/open/payments",
        action: "payment.release",
        methods: ["POST"],
        exposure: { ...exposure, failurePolicy: "failOpen" },
      },
      { path: "/orders", action: "order.create", methods: ["POST"] },
    ],
  },
};

/** The digest the ledger must receive for a subject: never the identifier itself. */
function digest(kind: string, id: string): string {
  return createHash("sha256")
    .update(["decionis-exposure-v1", TENANT, kind, id.trim().toLowerCase()].join("\n"))
    .digest("hex");
}

function payment(
  path = "/payments",
  amount = 40_000,
  vendor = VENDOR,
  idempotencyKey?: string,
): InterceptedRequest {
  return {
    method: "POST",
    path,
    search: "",
    headers: {
      "content-type": "application/json",
      "x-agent-id": AGENT,
      ...(idempotencyKey === undefined ? {} : { "idempotency-key": idempotencyKey }),
    },
    body: Buffer.from(
      JSON.stringify({ payee_id: vendor, amount_minor: amount, currency: "usd" }),
      "utf8",
    ),
    remoteAddress: "127.0.0.1",
    encrypted: false,
  };
}

function json(body: Buffer): Record<string, unknown> {
  return JSON.parse(body.toString("utf8")) as Record<string, unknown>;
}

function header(response: { headers: readonly (readonly [string, string])[] }, name: string) {
  return response.headers.find(([key]) => key === name)?.[1];
}

/** The gateway's own chained lines, by event. */
function events(io: CollectedIo, event: string): Record<string, unknown>[] {
  return io.out
    .map((line) => {
      try {
        return JSON.parse(line) as Record<string, unknown>;
      } catch {
        return {};
      }
    })
    .filter((line) => line["stream"] === "agent-safe.gateway-events/1" && line["event"] === event);
}

function interceptions(io: CollectedIo): Record<string, unknown>[] {
  return io.out
    .map((line) => {
      try {
        return JSON.parse(line) as Record<string, unknown>;
      } catch {
        return {};
      }
    })
    .filter((line) => line["event"] === "INTERCEPTED");
}

describe("a route that releases money", () => {
  const upstream = new UpstreamDouble();
  const authority = new LocalAuthority({ policy: () => "ALLOW" });
  let ledger: ExposureLedgerDouble;

  beforeAll(async () => {
    await upstream.start();
    await authority.start();
  });
  afterAll(async () => {
    await authority.stop();
    await upstream.stop();
  });
  beforeEach(() => {
    ledger = new ExposureLedgerDouble([
      { key: "org-daily", subject: "org", caps: { USD: 1_000_000 } },
      { key: "vendor-daily", subject: "vendor", caps: { USD: 100_000 } },
    ]);
  });

  async function gatewayFor(
    mode: "enforcement" | "shadow" = "enforcement",
    file: unknown = FILE,
  ): Promise<{ gateway: Gateway; io: CollectedIo }> {
    const env = {
      DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
      DECIONIS_TENANT_ID: TENANT,
      DECIONIS_API_URL: authority.baseUrl,
      DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
      AGENTSAFE_MODE: mode,
    };
    const io = collectedIo();
    const gateway = await Gateway.create(testConfig(upstream.baseUrl, { env, file }), {
      env,
      io,
      version: "0.0.0-test",
      authorityFetch: ledger.transport(),
    });
    return { gateway, io };
  }

  it("reserves against every covering limit, forwards once, and settles", async () => {
    const { gateway, io } = await gatewayFor();
    try {
      const sent = upstream.seen.length;
      const response = await gateway.govern(payment(), "payment.release");
      expect(response.status).toBe(201);
      expect(header(response, "agentsafe-execution")).toBe("FORWARDED");
      expect(header(response, "agentsafe-exposure")).toBe("WITHIN_LIMIT");
      expect(upstream.seen).toHaveLength(sent + 1);
      expect(ledger.reservations.map((entry) => [entry.limitKey, entry.state])).toEqual([
        ["org-daily", "SETTLED"],
        ["vendor-daily", "SETTLED"],
      ]);
      // The ledger's own key, the gateway's: never the caller's.
      expect(
        ledger.calls.every((call) => call.authorization === `Bearer ${LOCAL_AUTHORITY_API_KEY}`),
      ).toBe(true);
      const [reserved] = events(io, "EXPOSURE_RESERVED");
      expect(reserved).toMatchObject({ limits: ["org-daily", "vendor-daily"], unstated: [] });
      expect(events(io, "EXPOSURE_SETTLED")[0]).toMatchObject({
        limits: ["org-daily", "vendor-daily"],
      });
      expect(interceptions(io).at(-1)).toMatchObject({
        state: "ALLOW",
        execution: "FORWARDED",
        exposure: { status: "WITHIN_LIMIT", settlement: "SETTLED" },
      });
    } finally {
      await gateway.close();
    }
  });

  it("sends the ledger subject digests, an intent-derived key and no raw identifier", async () => {
    const { gateway } = await gatewayFor();
    try {
      const response = await gateway.govern(payment(), "payment.release");
      const intentHash = header(response, "agentsafe-intent-hash") ?? "";
      const reserves = ledger.calls.filter((call) => call.path.endsWith("/reservations"));
      expect(reserves).toHaveLength(2);
      for (const call of reserves) {
        expect(call.body).not.toContain(VENDOR);
        expect(call.body).not.toContain(VENDOR.toLowerCase());
        expect(call.body).not.toContain(AGENT);
        const body = JSON.parse(call.body) as Record<string, unknown>;
        expect(body["reservation_key"]).toBe(`agentsafe:${intentHash.replace("sha256:", "")}`);
        expect(body).toMatchObject({
          amount: 40_000,
          currency: "USD",
          action_type: "PAYMENT_RELEASE",
          source: { platform: "agentsafe", channel: "gateway" },
        });
      }
      const vendor = JSON.parse(ledger.reservesOf("vendor-daily")[0]!.body) as {
        subject: unknown;
      };
      expect(vendor.subject).toEqual({ kind: "vendor", id_digest: digest("vendor", VENDOR) });
      const org = JSON.parse(ledger.reservesOf("org-daily")[0]!.body) as { subject: unknown };
      expect(org.subject).toEqual({ kind: "org" });
    } finally {
      await gateway.close();
    }
  });

  it("refuses a payment over a limit, sends nothing, and releases what it had reserved", async () => {
    const { gateway, io } = await gatewayFor();
    try {
      expect((await gateway.govern(payment("/payments", 80_000), "payment.release")).status).toBe(
        201,
      );
      const sent = upstream.seen.length;
      const response = await gateway.govern(payment("/payments", 30_000), "payment.release");
      expect(response.status).toBe(409);
      expect(header(response, "agentsafe-execution")).toBe("NOT_FORWARDED");
      expect(json(response.body)).toMatchObject({
        state: "EXPOSURE_EXCEEDED",
        verdict: "ALLOW",
        reason_codes: ["EXPOSURE_LIMIT_EXCEEDED", "EXPOSURE_ON_EXCEED_ESCALATE"],
        execution: "NOT_FORWARDED",
        exposure: { limit_key: "vendor-daily", on_exceed: "ESCALATE" },
      });
      expect(upstream.seen).toHaveLength(sent);
      // org-daily was reserved first, in key order, and given back.
      const second = ledger.reservations.slice(2);
      expect(second.map((entry) => [entry.limitKey, entry.state])).toEqual([
        ["org-daily", "RELEASED"],
      ]);
      expect(ledger.used("org-daily")).toBe(80_000);
      expect(events(io, "EXPOSURE_EXCEEDED")[0]).toMatchObject({
        limit_key: "vendor-daily",
        reason_code: "EXPOSURE_LIMIT_EXCEEDED",
      });
      expect(interceptions(io).at(-1)).toMatchObject({
        state: "EXPOSURE_EXCEEDED",
        execution: "NOT_FORWARDED",
        exposure: { status: "EXCEEDED", limits: ["vendor-daily"] },
      });
      // Another vendor is its own subject.
      expect(
        (await gateway.govern(payment("/payments", 30_000, "vendor-other"), "payment.release"))
          .status,
      ).toBe(201);
    } finally {
      await gateway.close();
    }
  });

  it("answers a HOLD limit by holding nothing and naming it", async () => {
    ledger.limits = [
      { key: "vendor-daily", subject: "vendor", caps: { USD: 10 }, on_exceed: "HOLD" },
    ];
    const { gateway } = await gatewayFor();
    try {
      const response = await gateway.govern(payment(), "payment.release");
      expect(response.status).toBe(409);
      expect(json(response.body)).toMatchObject({
        reason_codes: ["EXPOSURE_LIMIT_EXCEEDED", "EXPOSURE_ON_EXCEED_HOLD"],
      });
    } finally {
      await gateway.close();
    }
  });

  it("refuses a currency the limit does not cap rather than converting it", async () => {
    ledger.limits = [{ key: "vendor-daily", subject: "vendor", caps: { EUR: 1_000_000 } }];
    const { gateway } = await gatewayFor();
    try {
      const response = await gateway.govern(payment(), "payment.release");
      expect(response.status).toBe(409);
      expect(json(response.body)["reason_codes"]).toContain("EXPOSURE_CURRENCY_NOT_CAPPED");
    } finally {
      await gateway.close();
    }
  });

  it("fails closed when the ledger is down, and forwards nothing", async () => {
    ledger.down = true;
    const { gateway, io } = await gatewayFor();
    try {
      const sent = upstream.seen.length;
      const response = await gateway.govern(payment(), "payment.release");
      expect(response.status).toBe(503);
      expect(header(response, "retry-after")).toBe("5");
      expect(json(response.body)).toMatchObject({
        state: "EXPOSURE_UNAVAILABLE",
        verdict: "ALLOW",
        reason_codes: ["EXPOSURE_UNAVAILABLE", "EXPOSURE_UNAVAILABLE"],
        execution: "NOT_FORWARDED",
      });
      expect(upstream.seen).toHaveLength(sent);
      expect(events(io, "EXPOSURE_UNAVAILABLE")[0]).toMatchObject({
        failure_policy: "FAIL_CLOSED",
      });
    } finally {
      await gateway.close();
    }
  });

  it("fails closed when the ledger cannot be reached at all", async () => {
    ledger.unreachable = true;
    const { gateway } = await gatewayFor();
    try {
      const sent = upstream.seen.length;
      const response = await gateway.govern(payment(), "payment.release");
      expect(response.status).toBe(503);
      expect(json(response.body)["reason_codes"]).toEqual([
        "EXPOSURE_UNAVAILABLE",
        "EXPOSURE_UNREACHABLE",
      ]);
      expect(upstream.seen).toHaveLength(sent);
    } finally {
      await gateway.close();
    }
  });

  it("forwards ungoverned only where the route explicitly fails open, and says so", async () => {
    ledger.down = true;
    const { gateway, io } = await gatewayFor();
    try {
      const sent = upstream.seen.length;
      const response = await gateway.govern(payment("/open/payments"), "payment.release");
      expect(response.status).toBe(201);
      expect(header(response, "agentsafe-exposure")).toBe("UNGOVERNED");
      expect(upstream.seen).toHaveLength(sent + 1);
      expect(events(io, "EXPOSURE_UNGOVERNED")[0]).toMatchObject({ failure_policy: "FAIL_OPEN" });
    } finally {
      await gateway.close();
    }
  });

  it("releases the reservations when the upstream refuses the payment", async () => {
    const { gateway, io } = await gatewayFor();
    try {
      const response = await gateway.govern(payment("/refuse/payments"), "payment.release");
      expect(response.status).toBe(422);
      expect(ledger.reservations.map((entry) => entry.state)).toEqual(["RELEASED", "RELEASED"]);
      expect(ledger.used("vendor-daily")).toBe(0);
      expect(events(io, "EXPOSURE_RELEASED")).toHaveLength(1);
    } finally {
      await gateway.close();
    }
  });

  it("keeps the reservations when nobody can say whether the payment happened", async () => {
    const { gateway, io } = await gatewayFor();
    try {
      const response = await gateway.govern(payment("/fail/payments"), "payment.release");
      expect(header(response, "agentsafe-execution")).toBe("INDETERMINATE");
      expect(ledger.reservations.map((entry) => entry.state)).toEqual(["RESERVED", "RESERVED"]);
      expect(events(io, "EXPOSURE_KEPT")[0]).toMatchObject({
        reason_codes: ["EXECUTION_INDETERMINATE"],
      });
    } finally {
      await gateway.close();
    }
  });

  describe("a retry, under the same idempotency key, of a payment nobody could account for", () => {
    const KEY = "synthetic-retry-key-1";
    const keys = (): string[] =>
      ledger
        .reservesOf("vendor-daily")
        .map((call) => (JSON.parse(call.body) as { reservation_key: string }).reservation_key);

    it("ends what the first attempt kept with its own outcome, and never draws twice", async () => {
      const { gateway, io } = await gatewayFor();
      try {
        // 60,000 twice would pass the vendor's 100,000 cap: one payment, counted once, does not.
        upstream.next.push(500);
        const first = await gateway.govern(
          payment("/payments", 60_000, VENDOR, KEY),
          "payment.release",
        );
        expect(header(first, "agentsafe-execution")).toBe("INDETERMINATE");
        expect(ledger.reservations.map((entry) => entry.state)).toEqual(["RESERVED", "RESERVED"]);
        const retry = await gateway.govern(
          payment("/payments", 60_000, VENDOR, KEY),
          "payment.release",
        );
        expect(retry.status).toBe(201);
        expect(header(retry, "agentsafe-exposure")).toBe("WITHIN_LIMIT");
        expect(ledger.reservations.map((entry) => entry.state)).toEqual(["SETTLED", "SETTLED"]);
        expect(ledger.used("vendor-daily")).toBe(60_000);
        expect(new Set(keys()).size).toBe(1);
        expect(events(io, "EXPOSURE_RESERVED").at(-1)).toMatchObject({
          retry_of: true,
          replayed: ["org-daily", "vendor-daily"],
        });
      } finally {
        await gateway.close();
      }
    });

    it("releases what the first attempt kept when the retry is refused", async () => {
      const { gateway } = await gatewayFor();
      try {
        upstream.next.push(500, 422);
        await gateway.govern(payment("/payments", 40_000, VENDOR, KEY), "payment.release");
        const retry = await gateway.govern(
          payment("/payments", 40_000, VENDOR, KEY),
          "payment.release",
        );
        expect(retry.status).toBe(422);
        expect(ledger.reservations.map((entry) => entry.state)).toEqual(["RELEASED", "RELEASED"]);
        expect(ledger.used("vendor-daily")).toBe(0);
      } finally {
        await gateway.close();
      }
    });

    it("keeps one reservation across retries that stay unknown", async () => {
      const { gateway } = await gatewayFor();
      try {
        upstream.next.push(500, 500);
        await gateway.govern(payment("/payments", 40_000, VENDOR, KEY), "payment.release");
        await gateway.govern(payment("/payments", 40_000, VENDOR, KEY), "payment.release");
        const last = await gateway.govern(
          payment("/payments", 40_000, VENDOR, KEY),
          "payment.release",
        );
        expect(last.status).toBe(201);
        expect(ledger.reservations.map((entry) => entry.state)).toEqual(["SETTLED", "SETTLED"]);
        expect(new Set(keys()).size).toBe(1);
      } finally {
        await gateway.close();
      }
    });

    it("draws afresh, under its own key, where the kept reservation was released by hand", async () => {
      const { gateway } = await gatewayFor();
      try {
        upstream.next.push(500);
        await gateway.govern(payment("/payments", 40_000, VENDOR, KEY), "payment.release");
        for (const entry of ledger.reservations) entry.state = "RELEASED";
        const retry = await gateway.govern(
          payment("/payments", 40_000, VENDOR, KEY),
          "payment.release",
        );
        expect(retry.status).toBe(201);
        expect(ledger.reservations.map((entry) => entry.state)).toEqual([
          "RELEASED",
          "RELEASED",
          "SETTLED",
          "SETTLED",
        ]);
        expect(ledger.used("vendor-daily")).toBe(40_000);
        expect(new Set(keys()).size).toBe(2);
      } finally {
        await gateway.close();
      }
    });

    it("draws again for another request, or one without a key", async () => {
      const { gateway } = await gatewayFor();
      try {
        upstream.next.push(500);
        await gateway.govern(payment("/payments", 40_000, VENDOR), "payment.release");
        await gateway.govern(payment("/payments", 40_000, VENDOR), "payment.release");
        expect(ledger.used("vendor-daily")).toBe(80_000);
        expect(new Set(keys()).size).toBe(2);
      } finally {
        await gateway.close();
      }
    });
  });

  describe("a change of a vendor's bank details, then a payment to that vendor", () => {
    const BANK_FILE = {
      version: 1,
      interception: {
        routes: [
          {
            path: "/vendors/:vendor/bank-account",
            action: "vendor.bank.change",
            methods: ["PUT"],
            exposure: { actionType: "VENDOR_BANK_CHANGE", subjects: { vendor: "/path/vendor" } },
          },
          {
            path: "/payments",
            action: "payment.release",
            methods: ["POST"],
            exposure: { ...exposure, subjects: { vendor: "/body/payee_id" } },
          },
        ],
      },
    };
    const change = (vendor = VENDOR): InterceptedRequest => ({
      method: "PUT",
      path: `/vendors/${vendor}/bank-account`,
      search: "",
      headers: { "content-type": "application/json" },
      body: Buffer.from(JSON.stringify({ iban: "GB00SYNTHETIC0000" }), "utf8"),
      remoteAddress: "127.0.0.1",
      encrypted: false,
    });

    beforeEach(() => {
      ledger = new ExposureLedgerDouble([
        { key: "vendor-daily", subject: "vendor", caps: { USD: 100_000 } },
        {
          key: "vendor-bank-cooling",
          kind: "sequence",
          subject: "vendor",
          caps: {},
          steps: ["vendor_bank_change", "payment_release"],
          action_types: ["VENDOR_BANK_CHANGE", "PAYMENT_RELEASE"],
          cooling_off_seconds: 259_200,
          on_exceed: "HOLD",
        },
      ]);
    });

    it("records the change as the vendor's step, with no amount, and settles it once it happened", async () => {
      const { gateway } = await gatewayFor("enforcement", BANK_FILE);
      try {
        const response = await gateway.govern(change(), "vendor.bank.change");
        expect(response.status).toBe(201);
        const [reserve] = ledger.reservesOf("vendor-bank-cooling");
        expect(JSON.parse(reserve!.body)).toMatchObject({
          subject: { kind: "vendor", id_digest: digest("vendor", VENDOR) },
          amount: 0,
          currency: "XXX",
          action_type: "VENDOR_BANK_CHANGE",
          step: "vendor_bank_change",
        });
        // No amount limit counts a change that moves no money.
        expect(ledger.reservesOf("vendor-daily")).toHaveLength(0);
        expect(ledger.reservations.map((entry) => [entry.limitKey, entry.state])).toEqual([
          ["vendor-bank-cooling", "SETTLED"],
        ]);
      } finally {
        await gateway.close();
      }
    });

    it("then holds a payment to that vendor, sends nothing, and lets another vendor's through", async () => {
      const { gateway } = await gatewayFor("enforcement", BANK_FILE);
      try {
        await gateway.govern(change(), "vendor.bank.change");
        const sent = upstream.seen.length;
        const held = await gateway.govern(payment(), "payment.release");
        expect(held.status).toBe(409);
        expect(header(held, "agentsafe-execution")).toBe("NOT_FORWARDED");
        expect(json(held.body)).toMatchObject({
          state: "EXPOSURE_EXCEEDED",
          reason_codes: ["SOD_COOLING_OFF", "EXPOSURE_ON_EXCEED_HOLD"],
          exposure: { limit_key: "vendor-bank-cooling", on_exceed: "HOLD" },
        });
        expect(upstream.seen).toHaveLength(sent);
        const other = await gateway.govern(
          payment("/payments", 40_000, "Vendor-OTHER-7"),
          "payment.release",
        );
        expect(other.status).toBe(201);
      } finally {
        await gateway.close();
      }
    });
  });

  it("retries a reservation whose answer was lost under the same key, and draws once", async () => {
    ledger.failReservesAfterWrite = 1;
    const { gateway } = await gatewayFor();
    try {
      const response = await gateway.govern(payment(), "payment.release");
      expect(response.status).toBe(201);
      const keys = ledger
        .reservesOf("org-daily")
        .map((call) => (JSON.parse(call.body) as { reservation_key: string }).reservation_key);
      expect(keys).toHaveLength(2);
      expect(new Set(keys).size).toBe(1);
      expect(ledger.reservations.filter((entry) => entry.limitKey === "org-daily")).toHaveLength(1);
      expect(ledger.used("org-daily")).toBe(40_000);
    } finally {
      await gateway.close();
    }
  });

  it("retries a settle that failed, and records one that kept failing", async () => {
    ledger.failEnds = 1;
    const first = await gatewayFor();
    try {
      expect((await first.gateway.govern(payment(), "payment.release")).status).toBe(201);
      expect(ledger.reservations.map((entry) => entry.state)).toEqual(["SETTLED", "SETTLED"]);
    } finally {
      await first.gateway.close();
    }
    ledger.failEnds = 100;
    const second = await gatewayFor();
    try {
      const response = await second.gateway.govern(payment("/payments", 1_000), "payment.release");
      // What already executed is unchanged by a ledger that cannot record it.
      expect(response.status).toBe(201);
      expect(events(second.io, "EXPOSURE_SETTLE_FAILED")).toHaveLength(2);
      expect(interceptions(second.io).at(-1)).toMatchObject({
        exposure: { settlement: "FAILED" },
      });
    } finally {
      await second.gateway.close();
    }
  });

  it("refuses a payment whose amount it cannot read before asking anyone", async () => {
    const { gateway } = await gatewayFor();
    try {
      const before = authority.requests.length;
      const request = {
        ...payment(),
        body: Buffer.from(
          JSON.stringify({ payee_id: VENDOR, amount_minor: "12.5", currency: "USD" }),
        ),
      };
      const response = await gateway.govern(request, "payment.release");
      expect(response.status).toBe(400);
      expect(json(response.body)).toMatchObject({
        reason_codes: ["EXPOSURE_AMOUNT_UNREADABLE"],
        execution: "NOT_FORWARDED",
      });
      expect(authority.requests).toHaveLength(before);
      expect(ledger.calls).toHaveLength(0);
    } finally {
      await gateway.close();
    }
  });

  it("refuses a direct caller that renames a money route's action, before asking anyone", async () => {
    const { gateway } = await gatewayFor();
    try {
      const before = authority.requests.length;
      const response = await gateway.govern(payment(), "http.post");
      expect(response.status).toBe(400);
      expect(json(response.body)["reason_codes"]).toEqual(["ROUTE_ACTION_MISMATCH"]);
      expect(authority.requests).toHaveLength(before);
      expect(ledger.calls).toHaveLength(0);
    } finally {
      await gateway.close();
    }
  });

  it("leaves a route that declares nothing exactly as it was", async () => {
    const { gateway, io } = await gatewayFor();
    try {
      const request = { ...payment(), path: "/orders" };
      const response = await gateway.govern(request, "order.create");
      expect(response.status).toBe(201);
      expect(header(response, "agentsafe-exposure")).toBeUndefined();
      expect(ledger.calls).toHaveLength(0);
      expect(interceptions(io).at(-1)?.["exposure"]).toBeUndefined();
    } finally {
      await gateway.close();
    }
  });

  it("never asks the ledger when no route releases money", async () => {
    const { gateway } = await gatewayFor("enforcement", {
      version: 1,
      interception: {
        routes: [{ path: "/payments", action: "payment.release", methods: ["POST"] }],
      },
    });
    try {
      expect((await gateway.govern(payment(), "payment.release")).status).toBe(201);
      expect(ledger.calls).toHaveLength(0);
    } finally {
      await gateway.close();
    }
  });

  it("in shadow, forwards unchanged and reports what the ledger would have said, counting nothing", async () => {
    ledger.limits = [{ key: "vendor-daily", subject: "vendor", caps: { USD: 10 } }];
    const { gateway, io } = await gatewayFor("shadow");
    try {
      const sent = upstream.seen.length;
      const response = await gateway.govern(payment(), "payment.release");
      expect(response.status).toBe(201);
      expect(upstream.seen).toHaveLength(sent + 1);
    } finally {
      await gateway.close();
    }
    const [observed] = events(io, "EXPOSURE_OBSERVED");
    expect(observed).toMatchObject({ would: "EXCEEDED", limit_key: "vendor-daily" });
    expect(interceptions(io).at(-1)).toMatchObject({
      state: "SHADOW",
      exposure: { status: "EXCEEDED" },
    });
    expect(ledger.used("vendor-daily")).toBe(0);
    expect(ledger.reservesOf("vendor-daily")).toHaveLength(0);
    expect(observed).toMatchObject({ read_only: true });
    expect(gateway.status().shadow?.exposure).toEqual({ EXCEEDED: 1 });
  });

  it("in shadow, asks the ledger read-only and reserves nothing", async () => {
    const { gateway, io } = await gatewayFor("shadow");
    try {
      await gateway.govern(payment(), "payment.release");
    } finally {
      await gateway.close();
    }
    // A hosted gateway's shadow key may only read: every call is a GET, none a reservation.
    expect(ledger.reservations).toHaveLength(0);
    expect(ledger.calls.every((call) => call.method === "GET")).toBe(true);
    expect(events(io, "EXPOSURE_OBSERVED")[0]).toMatchObject({
      would: "WITHIN_LIMIT",
      read_only: true,
    });
  });
});
