import { describe, expect, it } from "vitest";
import { DecionisExposureLedger } from "../../src/exposure/DecionisExposureLedger.js";
import { ExposureUnavailable } from "../../src/exposure/ExposureLedger.js";

interface Seen {
  readonly url: string;
  readonly method: string;
  readonly headers: Headers;
  readonly body: string | null;
}

function ledgerAnswering(answer: (seen: Seen) => Response | Promise<Response>) {
  const seen: Seen[] = [];
  const ledger = new DecionisExposureLedger({
    baseUrl: "https://api.decionis.example/",
    apiKey: () => "synthetic-key",
    timeoutMs: 1_000,
    fetch: async (input, init) => {
      const entry = {
        url: String(input),
        method: init?.method ?? "GET",
        headers: new Headers(init?.headers ?? {}),
        body: typeof init?.body === "string" ? init.body : null,
      };
      seen.push(entry);
      return await answer(entry);
    },
  });
  return { ledger, seen };
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

async function codeOf(promise: Promise<unknown>): Promise<[string, boolean]> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ExposureUnavailable) return [error.code, error.retryable];
    throw error;
  }
  throw new Error("expected a refusal");
}

const request = {
  subject: { kind: "org" },
  amount: 1,
  currency: "USD",
  action_type: "PAYMENT_RELEASE",
  reservation_key: "agentsafe:ab",
  request_digest: "a".repeat(64),
  occurred_at: "2026-11-18T10:00:00.000Z",
  source: { platform: "agentsafe" },
};

describe("the Decionis exposure ledger client", () => {
  it("reads the limits from GET /v1/commerce/exposure with the gateway's key", async () => {
    const { ledger, seen } = ledgerAnswering(() =>
      json(200, {
        service: "decionis",
        policy_version: "v1",
        limits: [
          {
            key: "vendor-daily",
            kind: "payment_release",
            subject: "vendor",
            window_seconds: 86_400,
            caps: [{ currency: "USD", max_amount: 10 }],
            on_exceed: "HOLD",
            action_types: ["PAYMENT_RELEASE"],
            usage: [],
          },
        ],
      }),
    );
    expect(await ledger.limits()).toEqual([
      {
        key: "vendor-daily",
        kind: "payment_release",
        subject: "vendor",
        onExceed: "HOLD",
        actionTypes: ["PAYMENT_RELEASE"],
        caps: [{ currency: "USD", maxAmount: 10 }],
      },
    ]);
    expect(seen[0]).toMatchObject({
      url: "https://api.decionis.example/v1/commerce/exposure",
      method: "GET",
    });
    expect(seen[0]?.headers.get("authorization")).toBe("Bearer synthetic-key");
    expect(seen[0]?.url).not.toContain("org_id");
  });

  it("reads one subject's usage read-only, and refuses a subject it would have to escape", async () => {
    const { ledger, seen } = ledgerAnswering(() =>
      json(200, {
        limits: [
          {
            key: "vendor-daily",
            kind: "payment_release",
            subject: "vendor",
            on_exceed: "HOLD",
            action_types: ["PAYMENT_RELEASE"],
            subject_usage: [{ currency: "USD", used: 7 }],
          },
          {
            key: "sod",
            kind: "sequence",
            subject: "vendor",
            on_exceed: "ESCALATE",
            action_types: ["PAYMENT_RELEASE"],
            subject_usage: null,
          },
        ],
      }),
    );
    const usage = await ledger.subjectUsage("vendor", "ab".repeat(32));
    expect(usage.get("vendor-daily")).toEqual([{ currency: "USD", used: 7 }]);
    expect(usage.get("sod")).toBeNull();
    expect(seen[0]).toMatchObject({
      method: "GET",
      url: `https://api.decionis.example/v1/commerce/exposure?subject_kind=vendor&subject_digest=${"ab".repeat(32)}`,
    });
    expect(await codeOf(ledger.subjectUsage("vendor", "not-a-digest"))).toEqual([
      "EXPOSURE_SUBJECT_INVALID",
      false,
    ]);
    expect(await codeOf(ledger.subjectUsage("vendor&x=1", "ab".repeat(32)))).toEqual([
      "EXPOSURE_SUBJECT_INVALID",
      false,
    ]);
    expect(seen).toHaveLength(1);
  });

  it("reserves, settles and releases on the documented paths", async () => {
    const id = "22222222-2222-4222-8222-222222222222";
    const { ledger, seen } = ledgerAnswering((entry) =>
      entry.url.endsWith("/reservations")
        ? json(200, {
            decision: "PROCEED",
            reason_code: "EXPOSURE_WITHIN_LIMIT",
            reservation_id: id,
            replayed: true,
          })
        : json(200, { service: "decionis", reservation_id: id }),
    );
    expect(await ledger.reserve("vendor.daily:1", request)).toEqual({
      decision: "PROCEED",
      reasonCode: "EXPOSURE_WITHIN_LIMIT",
      reservationId: id,
      replayed: true,
    });
    await ledger.settle("vendor.daily:1", id, 5);
    await ledger.release("vendor.daily:1", id);
    expect(
      seen.map((entry) => [
        entry.method,
        entry.url.replace("https://api.decionis.example", ""),
        entry.body,
      ]),
    ).toEqual([
      ["POST", "/v1/commerce/exposure/vendor.daily%3A1/reservations", JSON.stringify(request)],
      ["POST", `/v1/commerce/exposure/vendor.daily%3A1/reservations/${id}/settle`, '{"amount":5}'],
      ["POST", `/v1/commerce/exposure/vendor.daily%3A1/reservations/${id}/release`, "{}"],
    ]);
  });

  it("names the ledger's own error code, and retries only a server fault", async () => {
    expect(
      await codeOf(
        ledgerAnswering(() => json(409, { error: "EXPOSURE_POLICY_INVALID" })).ledger.limits(),
      ),
    ).toEqual(["EXPOSURE_POLICY_INVALID", false]);
    expect(
      await codeOf(
        ledgerAnswering(() => json(503, { error: "EXPOSURE_UNAVAILABLE" })).ledger.limits(),
      ),
    ).toEqual(["EXPOSURE_UNAVAILABLE", true]);
    expect(
      await codeOf(
        ledgerAnswering(() => new Response("<html>secret</html>", { status: 502 })).ledger.limits(),
      ),
    ).toEqual(["EXPOSURE_HTTP_502", true]);
    expect(
      await codeOf(
        ledgerAnswering(() => json(403, { error: "not a code: Bearer x" })).ledger.limits(),
      ),
    ).toEqual(["EXPOSURE_HTTP_403", false]);
    expect(
      await codeOf(
        ledgerAnswering(() => {
          throw new TypeError("fetch failed");
        }).ledger.limits(),
      ),
    ).toEqual(["EXPOSURE_UNREACHABLE", true]);
  });

  it("refuses an answer that is malformed, oversized, or a refusal carrying a reservation", async () => {
    expect(await codeOf(ledgerAnswering(() => new Response("not json")).ledger.limits())).toEqual([
      "EXPOSURE_ANSWER_MALFORMED",
      false,
    ]);
    expect(
      await codeOf(ledgerAnswering(() => json(200, { limits: [{ key: "x" }] })).ledger.limits()),
    ).toEqual(["EXPOSURE_LIMITS_MALFORMED", false]);
    expect(
      await codeOf(ledgerAnswering(() => new Response("x".repeat(100 * 1024 + 1))).ledger.limits()),
    ).toEqual(["EXPOSURE_ANSWER_TOO_LARGE", false]);
    const refusal = ledgerAnswering(() =>
      json(200, {
        decision: "HOLD",
        reason_code: "EXPOSURE_LIMIT_EXCEEDED",
        reservation_id: "22222222-2222-4222-8222-222222222222",
        replayed: false,
      }),
    );
    expect(await codeOf(refusal.ledger.reserve("k", request))).toEqual([
      "EXPOSURE_ANSWER_MALFORMED",
      false,
    ]);
  });

  it("refuses a limit key it would have to escape out of its path", async () => {
    const { ledger, seen } = ledgerAnswering(() => json(200, {}));
    expect(await codeOf(ledger.reserve("../policies", request))).toEqual([
      "EXPOSURE_LIMIT_KEY_INVALID",
      false,
    ]);
    expect(seen).toHaveLength(0);
  });
});
