import { describe, expect, it } from "vitest";
import type {
  CardAuthorizationRequest,
  CardAuthorizationResult,
} from "../../../src/adapters/cards/CardPurchase.js";
import { ExecutorCardClient } from "../../../src/adapters/stripe/ExecutorCardClient.js";
import {
  StripeBridgeConfigError,
  stripeBridgeSettingsFromEnv,
} from "../../../src/adapters/stripe/StripeBridgeSettings.js";
import {
  STRIPE_AUTHORIZATION_REQUESTS_PATH,
  STRIPE_EVENTS_PATH,
  StripeBridgeServer,
} from "../../../src/http/StripeBridgeServer.js";
import {
  StripeIssuingBridge,
  type ExecutorCardHook,
  type StripeBridgeConfig,
} from "../../../src/adapters/stripe/StripeIssuingBridge.js";
import {
  cardAuthorizationFromStripe,
  stripeAuthorizationOf,
} from "../../../src/adapters/stripe/StripeIssuingEvent.js";
import {
  stripeSignatureHeader,
  verifyStripeSignature,
} from "../../../src/adapters/stripe/StripeSignature.js";

const SECRET = "whsec_fixture_realtime_0001";
const OTHER_SECRET = "whsec_fixture_events_0002";
const NOW_MS = 1_800_000_000_000;
const NOW_S = NOW_MS / 1000;

/** A Stripe Issuing authorization event, with the cardholder's personal data Stripe sends. */
function event(
  type: string,
  overrides: Readonly<Record<string, unknown>> = {},
  livemode = false,
): Buffer {
  const authorization = {
    id: "iauth_fixture_0001",
    object: "issuing.authorization",
    livemode,
    approved: false,
    amount: 0,
    currency: "usd",
    status: "pending",
    card: {
      id: "ic_fixture_card_0042",
      object: "issuing.card",
      last4: "8693",
      cardholder: {
        id: "ich_fixture_holder",
        name: "Jenny Rosen",
        email: "jenny.rosen@example.com",
        phone_number: "+18008675309",
        billing: { address: { line1: "123 Main Street", city: "San Francisco" } },
      },
    },
    cardholder: "ich_fixture_holder",
    merchant_data: {
      category: "computer_software_stores",
      category_code: "5734",
      name: "FIXTURE SOFTWARE",
      network_id: "1234567890",
      city: "SAN FRANCISCO",
      country: "US",
    },
    pending_request: { amount: 4_250, currency: "usd", is_amount_controllable: false },
    request_history: [],
    verification_data: { cvc_check: "match" },
    ...overrides,
  };
  return Buffer.from(
    JSON.stringify({ id: "evt_fixture_0001", type, livemode, data: { object: authorization } }),
  );
}

function signed(body: Buffer, secret = SECRET, at = NOW_S): string {
  return stripeSignatureHeader(body, secret, at);
}

const BASE: StripeBridgeConfig = {
  mode: "enforce",
  livemode: false,
  stripeVersion: "2025-03-31.basil",
  secrets: [SECRET, OTHER_SECRET],
  deadlineMs: 1_500,
  onUndecided: "stand_in",
};

/** A hook that records what it was asked and answers as told. */
class FakeHook implements ExecutorCardHook {
  public readonly asked: CardAuthorizationRequest[] = [];
  public readonly settled: { id: string; result: CardAuthorizationResult }[] = [];
  public constructor(
    public authorizeAnswer: { status: number; body: unknown } | "hang" | "throw" = {
      status: 200,
      body: { decision: "NO_MATCH", code: "POLICY_BLOCK" },
    },
    public settleAnswer: { status: number; body: unknown } | "throw" = { status: 200, body: {} },
  ) {}

  public authorize(request: CardAuthorizationRequest, signal: AbortSignal) {
    this.asked.push(request);
    const answer = this.authorizeAnswer;
    if (answer === "throw") return Promise.reject(new TypeError("fetch failed"));
    if (answer === "hang") {
      return new Promise<{ status: number; body: unknown }>((_, reject) => {
        signal.addEventListener("abort", () => reject(signal.reason as Error));
      });
    }
    return Promise.resolve(answer);
  }

  public settle(id: string, result: CardAuthorizationResult) {
    this.settled.push({ id, result });
    const answer = this.settleAnswer;
    return answer === "throw" ? Promise.reject(new TypeError("down")) : Promise.resolve(answer);
  }
}

function bridge(config: Partial<StripeBridgeConfig> = {}, hook = new FakeHook()) {
  const lines: Record<string, unknown>[] = [];
  const subject = new StripeIssuingBridge({ ...BASE, ...config }, hook, {
    nowMs: () => NOW_MS,
    log: (line) => lines.push({ ...line }),
  });
  return { subject, hook, lines };
}

describe("verifyStripeSignature", () => {
  const body = Buffer.from('{"id":"evt_1"}');

  it("accepts Stripe's signature under any configured secret, so a secret rolls without a gap", () => {
    for (const secret of [SECRET, OTHER_SECRET]) {
      expect(() =>
        verifyStripeSignature({
          body,
          header: signed(body, secret),
          secrets: [SECRET, OTHER_SECRET],
          nowSeconds: NOW_S,
        }),
      ).not.toThrow();
    }
  });

  it("accepts a header carrying several v1 signatures when one matches", () => {
    const real = signed(body).split(",")[1]!;
    const header = `t=${String(NOW_S)},v1=${"0".repeat(64)},${real}`;
    expect(() =>
      verifyStripeSignature({ body, header, secrets: [SECRET], nowSeconds: NOW_S }),
    ).not.toThrow();
  });

  it.each([
    ["a missing header", undefined, "STRIPE_SIGNATURE_MISSING"],
    ["no timestamp", `v1=${"a".repeat(64)}`, "STRIPE_SIGNATURE_MALFORMED"],
    ["no v1", `t=${String(NOW_S)},v0=abc`, "STRIPE_SIGNATURE_MALFORMED"],
    ["another secret", signed(body, "whsec_someone_else"), "STRIPE_SIGNATURE_INVALID"],
    ["a replay six minutes later", signed(body, SECRET, NOW_S - 301), "STRIPE_SIGNATURE_STALE"],
    ["a timestamp from the future", signed(body, SECRET, NOW_S + 301), "STRIPE_SIGNATURE_STALE"],
  ])("refuses %s", (_, header, code) => {
    expect(() =>
      verifyStripeSignature({ body, header, secrets: [SECRET], nowSeconds: NOW_S }),
    ).toThrow(code);
  });

  it("refuses a body changed after signing", () => {
    const header = signed(body);
    expect(() =>
      verifyStripeSignature({
        body: Buffer.from('{"id":"evt_2"}'),
        header,
        secrets: [SECRET],
        nowSeconds: NOW_S,
      }),
    ).toThrow("STRIPE_SIGNATURE_INVALID");
  });

  it("refuses everything when no secret is configured", () => {
    expect(() =>
      verifyStripeSignature({ body, header: signed(body), secrets: [], nowSeconds: NOW_S }),
    ).toThrow("STRIPE_SECRET_NOT_CONFIGURED");
  });
});

describe("the Stripe authorization, as the bridge keeps it", () => {
  it("keeps references, amounts and the merchant category, and none of the cardholder's data", () => {
    const view = stripeAuthorizationOf(event("issuing_authorization.request"));
    const kept = JSON.stringify(view);
    for (const personal of ["Jenny", "jenny.rosen", "8008675309", "Main Street", "8693", "ich_"]) {
      expect(kept).not.toContain(personal);
    }
    expect(cardAuthorizationFromStripe(view, "pending")).toEqual({
      authorization_id: "iauth_fixture_0001",
      card_token_ref: "ic_fixture_card_0042",
      amount_minor: 4_250,
      currency: "USD",
      merchant_id: "1234567890",
      mcc: "5734",
    });
  });

  it.each([
    [
      "an account verification",
      { pending_request: { amount: 0, currency: "usd" } },
      "STRIPE_AMOUNT_ZERO",
    ],
    ["no pending request", { pending_request: null }, "STRIPE_AMOUNT_MISSING"],
    [
      "a merchant with no network id",
      { merchant_data: { category_code: "5734", network_id: null } },
      "STRIPE_MERCHANT_UNIDENTIFIED",
    ],
    [
      "a currency this build cannot count",
      { pending_request: { amount: 100, currency: "xts" } },
      "STRIPE_CURRENCY_UNSUPPORTED",
    ],
    [
      "a card id shaped like a card number",
      { card: "4242424242424242" },
      "STRIPE_CARD_PAN_REFUSED",
    ],
  ])("refuses %s", (_, overrides, code) => {
    const view = stripeAuthorizationOf(event("issuing_authorization.request", overrides));
    expect(() => cardAuthorizationFromStripe(view, "pending")).toThrow(code);
  });

  /** A card whose metadata the company set when it issued the card. */
  const cardWith = (metadata: Readonly<Record<string, string>>) => ({
    card: {
      id: "ic_fixture_card_0042",
      last4: "8693",
      metadata: {
        cost_centre: "fixture-cc-7",
        employee_email: "jenny.rosen@example.com",
        ...metadata,
      },
    },
  });

  it("names the card's holder from the card's metadata, and copies no other metadata", () => {
    const view = stripeAuthorizationOf(
      event(
        "issuing_authorization.request",
        cardWith({ decionis_actor_id: "fixture_usr_jenny", decionis_actor_type: "human" }),
      ),
    );
    expect(cardAuthorizationFromStripe(view, "pending")).toMatchObject({
      actor: { id: "fixture_usr_jenny", type: "human" },
    });
    const kept = JSON.stringify(view);
    expect(kept).not.toContain("cost_centre");
    expect(kept).not.toContain("jenny.rosen");
  });

  it("decides as the deployment's actor when the card names no holder", () => {
    const view = stripeAuthorizationOf(event("issuing_authorization.request", cardWith({})));
    expect(cardAuthorizationFromStripe(view, "pending")).not.toHaveProperty("actor");
  });

  it.each([
    ["half a name", { decionis_actor_id: "fixture_usr_jenny" }, "STRIPE_CARD_ACTOR_INCOMPLETE"],
    ["a type and no id", { decionis_actor_type: "human" }, "STRIPE_CARD_ACTOR_INCOMPLETE"],
    [
      "an id the hook would refuse",
      { decionis_actor_id: "jenny rosen", decionis_actor_type: "human" },
      "STRIPE_CARD_ACTOR_INVALID",
    ],
    [
      "a type the hook would refuse",
      { decionis_actor_id: "fixture_usr_jenny", decionis_actor_type: "1human" },
      "STRIPE_CARD_ACTOR_INVALID",
    ],
  ])("refuses %s rather than deciding it as someone else", (_, metadata, code) => {
    const view = stripeAuthorizationOf(event("issuing_authorization.request", cardWith(metadata)));
    expect(() => cardAuthorizationFromStripe(view, "pending")).toThrow(code);
  });

  it("leaves out a category code that is not four digits", () => {
    const view = stripeAuthorizationOf(
      event("issuing_authorization.request", {
        merchant_data: { category_code: "57x4", network_id: "1234567890" },
      }),
    );
    expect(cardAuthorizationFromStripe(view, "pending")).not.toHaveProperty("mcc");
  });

  it("refuses anything that is not an Issuing authorization", () => {
    expect(() => stripeAuthorizationOf(Buffer.from("not json"))).toThrow("STRIPE_EVENT_INVALID");
    const charge = Buffer.from(
      JSON.stringify({
        id: "evt_1",
        type: "charge.succeeded",
        livemode: false,
        data: { object: { object: "charge" } },
      }),
    );
    expect(() => stripeAuthorizationOf(charge)).toThrow("STRIPE_AUTHORIZATION_INVALID");
  });
});

describe("the real-time endpoint", () => {
  const request = event("issuing_authorization.request");

  it("answers the policy's ALLOW as approved, in Stripe's shape and version", async () => {
    const hook = new FakeHook({
      status: 200,
      body: { decision: "APPROVE", intent_id: "int_1", decision_id: "dec_1", dossier_id: "dos_1" },
    });
    const { subject, lines } = bridge({}, hook);
    const reply = await subject.authorizationRequest(request, signed(request));
    expect(reply.status).toBe(200);
    expect(reply.headers["stripe-version"]).toBe("2025-03-31.basil");
    expect(reply.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(reply.body)).toEqual({
      approved: true,
      metadata: {
        decionis_decision: "APPROVE",
        decionis_intent_id: "int_1",
        decionis_decision_id: "dec_1",
      },
    });
    expect(hook.asked).toEqual([
      {
        authorization_id: "iauth_fixture_0001",
        card_token_ref: "ic_fixture_card_0042",
        amount_minor: 4_250,
        currency: "USD",
        merchant_id: "1234567890",
        mcc: "5734",
      },
    ]);
    expect(lines.at(-1)).toMatchObject({
      event: "STRIPE_AUTHORIZATION_ANSWERED",
      approved: true,
      elapsed_ms: 0,
    });
    expect(JSON.stringify(lines)).not.toContain("Jenny");
  });

  it("declines a BLOCK with the policy's code", async () => {
    const { subject } = bridge();
    const reply = await subject.authorizationRequest(request, signed(request));
    expect(JSON.parse(reply.body)).toEqual({
      approved: false,
      metadata: { decionis_decision: "NO_MATCH", decionis_code: "POLICY_BLOCK" },
    });
  });

  it("declines an escalation, since Stripe cannot pend, and names the intent that awaits approval", async () => {
    const hook = new FakeHook({
      status: 200,
      body: { decision: "PENDING", intent_id: "int_9", decision_id: null },
    });
    const { subject } = bridge({}, hook);
    const reply = await subject.authorizationRequest(request, signed(request));
    expect(JSON.parse(reply.body)).toEqual({
      approved: false,
      metadata: {
        decionis_decision: "PENDING",
        decionis_code: "ESCALATION_PENDING",
        decionis_intent_id: "int_9",
      },
    });
  });

  it("leaves an undecided authorization to Stripe's stand-in by default", async () => {
    const hook = new FakeHook("hang");
    const { subject, lines } = bridge({ deadlineMs: 100 }, hook);
    const reply = await subject.authorizationRequest(request, signed(request));
    expect(reply.status).toBe(503);
    expect(JSON.parse(reply.body)).toEqual({ code: "EXECUTOR_TIMEOUT" });
    expect(lines.at(-1)).toMatchObject({
      event: "STRIPE_AUTHORIZATION_UNDECIDED",
      code: "EXECUTOR_TIMEOUT",
      rule: "stand_in",
    });
  });

  it("declines an undecided authorization when the rule says decline", async () => {
    const { subject } = bridge({ onUndecided: "decline" }, new FakeHook("throw"));
    const reply = await subject.authorizationRequest(request, signed(request));
    expect(reply.status).toBe(200);
    expect(JSON.parse(reply.body)).toEqual({
      approved: false,
      metadata: { decionis_decision: "UNDECIDED", decionis_code: "EXECUTOR_UNAVAILABLE" },
    });
  });

  it("treats an executor refusal as undecided, under the executor's own code", async () => {
    const hook = new FakeHook({ status: 503, body: { code: "CARD_HOLDS_UNAVAILABLE" } });
    const { subject } = bridge({ onUndecided: "decline" }, hook);
    const reply = await subject.authorizationRequest(request, signed(request));
    expect(JSON.parse(reply.body).metadata.decionis_code).toBe("EXECUTOR_CARD_HOLDS_UNAVAILABLE");
  });

  it("never asks the executor about a zero-amount verification", async () => {
    const zero = event("issuing_authorization.request", {
      pending_request: { amount: 0, currency: "usd" },
    });
    const { subject, hook } = bridge({ onUndecided: "decline" });
    const reply = await subject.authorizationRequest(zero, signed(zero));
    expect(JSON.parse(reply.body).metadata.decionis_code).toBe("STRIPE_AMOUNT_ZERO");
    expect(hook.asked).toEqual([]);
  });

  it.each([
    ["an unsigned request", "", request, "STRIPE_SIGNATURE_MISSING"],
    ["a forged request", signed(request, "whsec_attacker"), request, "STRIPE_SIGNATURE_INVALID"],
    [
      "a live event at a test-mode bridge",
      undefined,
      event("issuing_authorization.request", {}, true),
      "STRIPE_LIVEMODE_MISMATCH",
    ],
    [
      "another event type",
      undefined,
      event("issuing_authorization.created"),
      "STRIPE_EVENT_UNEXPECTED",
    ],
  ])(
    "refuses %s before anything is asked, even when the rule is decline",
    async (_, header, body, code) => {
      const { subject, hook } = bridge({ onUndecided: "decline" });
      const reply = await subject.authorizationRequest(body, header ?? signed(body));
      expect(reply.status).toBe(400);
      expect(JSON.parse(reply.body)).toEqual({ code });
      expect(hook.asked).toEqual([]);
    },
  );

  it("is not served in shadow, so shadow never decides a real card", async () => {
    const { subject, hook } = bridge({ mode: "shadow" });
    const reply = await subject.authorizationRequest(request, signed(request));
    expect(reply.status).toBe(404);
    expect(hook.asked).toEqual([]);
  });
});

describe("the events endpoint", () => {
  const created = (overrides: Readonly<Record<string, unknown>> = {}) =>
    event("issuing_authorization.created", {
      approved: true,
      amount: 4_250,
      status: "pending",
      pending_request: null,
      request_history: [
        { amount: 4_250, currency: "usd", approved: true, reason: "webhook_approved" },
      ],
      ...overrides,
    });

  it("settles the claim with what Stripe approved", async () => {
    const { subject, hook } = bridge();
    const body = created();
    const reply = await subject.event(body, signed(body, OTHER_SECRET));
    expect(reply.status).toBe(200);
    expect(hook.settled).toEqual([
      { id: "iauth_fixture_0001", result: { status: "APPROVED", approved_amount_minor: 4_250 } },
    ]);
  });

  it("settles a decline as declined, and says when the decision was Stripe's stand-in", async () => {
    const { subject, hook, lines } = bridge();
    const body = created({
      approved: false,
      amount: 0,
      request_history: [
        { amount: 4_250, currency: "usd", approved: false, reason: "webhook_timeout" },
      ],
    });
    await subject.event(body, signed(body));
    expect(hook.settled[0]!.result).toEqual({ status: "DECLINED" });
    expect(lines[0]).toMatchObject({ event: "STRIPE_STAND_IN_DECIDED", reason: "webhook_timeout" });
  });

  it.each([
    ["nothing was claimed for it", 404, "CARD_AUTHORIZATION_UNKNOWN", 200],
    ["its result is already recorded", 409, "CARD_RESULT_ALREADY_RECORDED", 200],
    ["the executor cannot record it now", 503, "CARD_HOLDS_UNAVAILABLE", 503],
  ])("acknowledges or asks Stripe to retry when %s", async (_, status, code, expected) => {
    const hook = new FakeHook(undefined, { status, body: { code } });
    const { subject } = bridge({}, hook);
    const body = created();
    expect((await subject.event(body, signed(body))).status).toBe(expected);
  });

  it("asks Stripe to retry when the executor is unreachable", async () => {
    const { subject } = bridge({}, new FakeHook(undefined, "throw"));
    const body = created();
    expect((await subject.event(body, signed(body))).status).toBe(503);
  });

  it("acknowledges and ignores other events", async () => {
    const { subject, hook } = bridge();
    const body = event("issuing_authorization.updated");
    const reply = await subject.event(body, signed(body));
    expect(JSON.parse(reply.body)).toEqual({ ignored: true });
    expect(hook.settled).toEqual([]);
  });

  it("refuses an unsigned event", async () => {
    const { subject, hook } = bridge();
    const reply = await subject.event(created(), undefined);
    expect(reply.status).toBe(400);
    expect(hook.settled).toEqual([]);
  });

  describe("in shadow", () => {
    it("has the policy evaluate what Stripe already decided, and records the verdict beside it", async () => {
      const { subject, hook, lines } = bridge({ mode: "shadow" });
      const body = created();
      const reply = await subject.event(body, signed(body));
      expect(JSON.parse(reply.body)).toEqual({ observed: true });
      expect(hook.asked[0]).toMatchObject({
        authorization_id: "iauth_fixture_0001",
        amount_minor: 4_250,
      });
      expect(hook.settled).toEqual([]);
      expect(lines.at(-1)).toMatchObject({
        event: "STRIPE_SHADOW_OBSERVED",
        stripe_approved: true,
        decision: "NO_MATCH",
        code: "POLICY_BLOCK",
      });
    });

    it("settles and warns when the executor it asks is enforcing", async () => {
      const hook = new FakeHook({ status: 200, body: { decision: "APPROVE" } });
      const { subject, lines } = bridge({ mode: "shadow" }, hook);
      const body = created();
      await subject.event(body, signed(body));
      expect(lines.some((line) => line.event === "STRIPE_SHADOW_EXECUTOR_ENFORCING")).toBe(true);
      expect(hook.settled).toHaveLength(1);
    });

    it("skips a zero-amount verification", async () => {
      const { subject, hook } = bridge({ mode: "shadow" });
      const body = created({
        request_history: [
          { amount: 0, currency: "usd", approved: true, reason: "webhook_approved" },
        ],
      });
      const reply = await subject.event(body, signed(body));
      expect(JSON.parse(reply.body)).toEqual({ observed: false });
      expect(hook.asked).toEqual([]);
    });
  });
});

describe("stripeBridgeSettingsFromEnv", () => {
  const files: Record<string, string> = {
    "/s/secrets": `${SECRET}\n${OTHER_SECRET}\n`,
    "/s/token": "operator-token\n",
  };
  const read = (path: string) => {
    const text = files[path];
    if (text === undefined) throw new Error("missing");
    return text;
  };
  const env = {
    STRIPE_BRIDGE_LIVEMODE: "false",
    STRIPE_BRIDGE_STRIPE_VERSION: "2025-03-31.basil",
    STRIPE_BRIDGE_WEBHOOK_SECRETS_FILE: "/s/secrets",
    STRIPE_BRIDGE_EXECUTOR_URL: "https://executor.example",
    STRIPE_BRIDGE_EXECUTOR_TOKEN_FILE: "/s/token",
  };

  it("starts in shadow, leaves undecided authorizations to Stripe, and answers within 1.5 s", () => {
    expect(stripeBridgeSettingsFromEnv(env, read)).toMatchObject({
      mode: "shadow",
      onUndecided: "stand_in",
      deadlineMs: 1_500,
      livemode: false,
      secrets: [SECRET, OTHER_SECRET],
      host: "127.0.0.1",
      port: 8790,
    });
  });

  it.each([
    ["STRIPE_BRIDGE_LIVEMODE", undefined, "STRIPE_BRIDGE_LIVEMODE_REQUIRED"],
    ["STRIPE_BRIDGE_LIVEMODE", "yes", "STRIPE_BRIDGE_LIVEMODE_INVALID"],
    ["STRIPE_BRIDGE_STRIPE_VERSION", "latest", "STRIPE_BRIDGE_STRIPE_VERSION_INVALID"],
    ["STRIPE_BRIDGE_MODE", "observe", "STRIPE_BRIDGE_MODE_INVALID"],
    ["STRIPE_BRIDGE_DEADLINE_MS", "1900", "STRIPE_BRIDGE_DEADLINE_MS_INVALID"],
    ["STRIPE_BRIDGE_DEADLINE_MS", "50", "STRIPE_BRIDGE_DEADLINE_MS_INVALID"],
    ["STRIPE_BRIDGE_ON_UNDECIDED", "approve", "STRIPE_BRIDGE_ON_UNDECIDED_INVALID"],
    ["STRIPE_BRIDGE_EXECUTOR_URL", undefined, "STRIPE_BRIDGE_EXECUTOR_URL_REQUIRED"],
  ])("refuses %s=%s", (name, value, code) => {
    expect(() => stripeBridgeSettingsFromEnv({ ...env, [name]: value }, read)).toThrow(code);
  });

  it("refuses a secrets file holding something that is not a signing secret", () => {
    files["/s/bad"] = "sk_live_not_a_webhook_secret\n";
    expect(() =>
      stripeBridgeSettingsFromEnv({ ...env, STRIPE_BRIDGE_WEBHOOK_SECRETS_FILE: "/s/bad" }, read),
    ).toThrow(StripeBridgeConfigError);
  });
});

describe("ExecutorCardClient", () => {
  it("refuses to send the operator token in clear to another host", () => {
    expect(() => new ExecutorCardClient("http://executor.example", () => "t")).toThrow(
      "EXECUTOR_URL_NOT_HTTPS",
    );
    expect(() => new ExecutorCardClient("http://127.0.0.1:8080", () => "t")).not.toThrow();
  });

  it("posts as the operator, to the hook and to the authorization's result", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetcher = (async (url: URL | string, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify({ decision: "NO_MATCH", code: "X" }), { status: 200 });
    }) as typeof fetch;
    const client = new ExecutorCardClient(
      "https://executor.example",
      () => "operator-token",
      fetcher,
    );
    const signal = new AbortController().signal;
    const answer = await client.authorize(
      {
        authorization_id: "iauth_1",
        card_token_ref: "ic_1",
        amount_minor: 1,
        currency: "USD",
        merchant_id: "m",
      },
      signal,
    );
    await client.settle("iauth_1", { status: "DECLINED" }, signal);
    expect(answer).toEqual({ status: 200, body: { decision: "NO_MATCH", code: "X" } });
    expect(calls.map((call) => call.url)).toEqual([
      "https://executor.example/v1/card-authorizations",
      "https://executor.example/v1/card-authorizations/iauth_1/result",
    ]);
    expect((calls[0]!.init.headers as Record<string, string>).authorization).toBe(
      "Bearer operator-token",
    );
    expect(calls[0]!.init.redirect).toBe("error");
  });
});

describe("StripeBridgeServer", () => {
  it("serves the two Stripe routes over a real listener, raw body and signature intact", async () => {
    const hook = new FakeHook({ status: 200, body: { decision: "APPROVE", intent_id: "int_1" } });
    const subject = new StripeIssuingBridge(BASE, hook, { nowMs: Date.now, log: () => undefined });
    const server = new StripeBridgeServer(subject);
    const { port } = await server.listen(0, "127.0.0.1");
    const at = (path: string): URL => {
      const url = new URL(path, "http://127.0.0.1/");
      url.port = String(port);
      return url;
    };
    try {
      const body = event("issuing_authorization.request");
      const answered = await fetch(at(STRIPE_AUTHORIZATION_REQUESTS_PATH), {
        method: "POST",
        headers: { "stripe-signature": signed(body, SECRET, Math.floor(Date.now() / 1000)) },
        body: new Uint8Array(body),
      });
      expect(answered.status).toBe(200);
      expect(answered.headers.get("stripe-version")).toBe("2025-03-31.basil");
      expect(await answered.json()).toMatchObject({ approved: true });

      const ignored = event("issuing_authorization.updated");
      const events = await fetch(at(STRIPE_EVENTS_PATH), {
        method: "POST",
        headers: { "stripe-signature": signed(ignored, SECRET, Math.floor(Date.now() / 1000)) },
        body: new Uint8Array(ignored),
      });
      expect(await events.json()).toEqual({ ignored: true });

      expect((await fetch(at("/v1/other"), { method: "POST" })).status).toBe(404);
      expect((await fetch(at(STRIPE_EVENTS_PATH))).status).toBe(405);
      expect((await fetch(at("/health"))).status).toBe(200);
      const huge = await fetch(at(STRIPE_EVENTS_PATH), {
        method: "POST",
        body: new Uint8Array(300 * 1024).fill(32),
      }).catch(() => null);
      // The listener stops reading at the bound: either the refusal arrives or the socket closes.
      if (huge !== null) expect(huge.status).toBe(413);
    } finally {
      await server.close();
    }
  });
});
