import { LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { cardHandlers } from "../../src/adapters/cards/CardHandlers.js";
import {
  StripeIssuingBridge,
  type ExecutorCardHook,
  type StripeBridgeConfig,
} from "../../src/adapters/stripe/StripeIssuingBridge.js";
import { stripeSignatureHeader } from "../../src/adapters/stripe/StripeSignature.js";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import type { Principal } from "../../src/identity/PrincipalRegistry.js";
import { HaltSwitch } from "../../src/incident/HaltSwitch.js";
import { InMemoryExecutionJournal } from "../../src/journal/InMemoryExecutionJournal.js";
import { ServiceError } from "../../src/service/ServiceError.js";
import { TrustedExecutorService } from "../../src/service/TrustedExecutorService.js";
import { collectedEvents, loopbackEnvironment, openSecrets } from "../support/Environment.js";

/**
 * Stripe Issuing end to end, short of Stripe and the network: a signed Stripe event goes
 * through the bridge into the real executor's card hook, which the local authority decides.
 */
const TAPPED =
  "eyJhbGciOiJFZERTQSIsInR5cCI6ImRlY2lvbmlzLXByZXNlbmNlLWF0dGVzdGF0aW9uK2p3dCJ9.dGFwcGVk.c2lnbmVk";
const SECRET = "whsec_fixture_flow_0001";

const authority = new LocalAuthority({
  verifyAttestation: (attestation) => attestation === TAPPED,
});

beforeAll(async () => {
  await authority.start();
});

afterAll(async () => {
  await authority.stop();
});

/** The bridge's principal on the executor: an operator holding `cards.authorize` only. */
const BRIDGE: Principal = {
  id: "synthetic-stripe-bridge",
  role: "OPERATOR",
  tenantId: null,
  actor: null,
  allowedActions: new Set(),
  scopes: new Set(["cards.authorize"]),
  credential: { kind: "BEARER", tokenDigest: Buffer.alloc(32) },
  rateLimit: null,
} as unknown as Principal;

const PRESENTING_APP: Principal = {
  ...BRIDGE,
  id: "synthetic-issuer-app-backend",
  scopes: new Set(["escalations.resume"]),
} as unknown as Principal;

function executor(mode: "ENFORCEMENT" | "SHADOW"): TrustedExecutorService {
  const env: Record<string, string> = {
    ...loopbackEnvironment({ authority, providerBaseUrl: "http://127.0.0.1:9" }, mode, "NONE"),
    DOWNSTREAM_SYSTEM: "stripe-issuing",
    DOWNSTREAM_OPERATION: "card_purchase",
    EXECUTOR_ACTOR_ID: "synthetic-card-programme",
    EXECUTOR_CARD_NO_GRANT: "evaluate",
    EXECUTOR_CARD_COMMIT_TENANT_ID: "00000000-0000-4000-8000-000000000002",
    EXECUTOR_CARD_COMMIT_ACTOR_ID: "synthetic-stripe-commit",
  };
  const config = ExecutorConfigLoader.load(env);
  const events = collectedEvents([]);
  return TrustedExecutorService.create(config, openSecrets(env, config, events), cardHandlers(), {
    emit: () => undefined,
    security: events,
    journal: new InMemoryExecutionJournal(),
    halt: new HaltSwitch({ events }),
  });
}

/** The executor's hook in process, answering as its HTTP server would. */
function hookOver(service: TrustedExecutorService): ExecutorCardHook {
  const call = async (work: () => Promise<unknown>) => {
    try {
      return { status: 200, body: await work() };
    } catch (error) {
      if (error instanceof ServiceError) {
        return { status: error.status, body: error.body ?? { code: error.code } };
      }
      throw error;
    }
  };
  return {
    authorize: (request) => call(() => service.authorizeCard(request, BRIDGE)),
    settle: (id, result) => call(() => service.settleCard(id, result, BRIDGE)),
  };
}

function bridgeOver(service: TrustedExecutorService, mode: StripeBridgeConfig["mode"]) {
  const lines: Record<string, unknown>[] = [];
  const bridge = new StripeIssuingBridge(
    {
      mode,
      livemode: false,
      stripeVersion: "2025-03-31.basil",
      secrets: [SECRET],
      deadlineMs: 1_500,
      onUndecided: "stand_in",
    },
    hookOver(service),
    { nowMs: Date.now, log: (line) => lines.push({ ...line }) },
  );
  return { bridge, lines };
}

let sequence = 0;

/** A Stripe Issuing event for one card at one merchant, signed as Stripe signs it. */
function stripe(
  type: "issuing_authorization.request" | "issuing_authorization.created",
  input: {
    readonly id?: string;
    readonly card: string;
    readonly amount: number;
    readonly approved?: boolean;
  },
): { readonly body: Buffer; readonly signature: string } {
  const id = input.id ?? `iauth_fixture_${String(++sequence).padStart(4, "0")}`;
  const decided = type === "issuing_authorization.created";
  const body = Buffer.from(
    JSON.stringify({
      id: `evt_${id}`,
      type,
      livemode: false,
      data: {
        object: {
          id,
          object: "issuing.authorization",
          livemode: false,
          approved: decided ? (input.approved ?? true) : false,
          amount: decided && (input.approved ?? true) ? input.amount : 0,
          currency: "usd",
          card: { id: input.card, cardholder: { name: "Jenny Rosen" } },
          merchant_data: { category_code: "5734", network_id: "1234567890" },
          pending_request: decided ? null : { amount: input.amount, currency: "usd" },
          request_history: decided
            ? [
                {
                  amount: input.amount,
                  currency: "usd",
                  approved: input.approved ?? true,
                  reason: "webhook_approved",
                },
              ]
            : [],
        },
      },
    }),
  );
  return {
    body,
    signature: stripeSignatureHeader(body, SECRET, Math.floor(Date.now() / 1000)),
  };
}

function answer(reply: { readonly body: string }) {
  return JSON.parse(reply.body) as { approved: boolean; metadata: Record<string, string> };
}

describe("Stripe Issuing through the bridge, decided by policy at the executor's hook", () => {
  it("approves a routine purchase in one call and settles it from Stripe's event", async () => {
    const service = executor("ENFORCEMENT");
    const { bridge } = bridgeOver(service, "enforce");
    const asked = stripe("issuing_authorization.request", {
      id: "iauth_fixture_routine",
      card: "ic_fixture_routine",
      amount: 4_250,
    });
    const reply = await bridge.authorizationRequest(asked.body, asked.signature);
    expect(reply.status).toBe(200);
    expect(answer(reply)).toMatchObject({
      approved: true,
      metadata: { decionis_decision: "APPROVE" },
    });
    expect(answer(reply).metadata.decionis_intent_id).toBeTypeOf("string");

    const created = stripe("issuing_authorization.created", {
      id: "iauth_fixture_routine",
      card: "ic_fixture_routine",
      amount: 4_250,
    });
    const settled = await bridge.event(created.body, created.signature);
    expect(JSON.parse(settled.body)).toEqual({ settled: true });
    // Stripe redelivers events; the result is recorded once and the redelivery acknowledged.
    const again = await bridge.event(created.body, created.signature);
    expect(again.status).toBe(200);
    service.close();
  });

  it("declines an escalated purchase, then approves the cardholder's retry once it is approved", async () => {
    const service = executor("ENFORCEMENT");
    const { bridge } = bridgeOver(service, "enforce");
    const first = stripe("issuing_authorization.request", {
      card: "ic_fixture_flagged",
      amount: 50_000,
    });
    const held = await bridge.authorizationRequest(first.body, first.signature);
    expect(answer(held)).toMatchObject({
      approved: false,
      metadata: { decionis_decision: "PENDING", decionis_code: "ESCALATION_PENDING" },
    });

    // The approval, as the issuer app's backend presents it for this intent.
    const pending = await service.authorizeCard(
      {
        authorization_id: JSON.parse(first.body.toString()).data.object.id as string,
        card_token_ref: "ic_fixture_flagged",
        amount_minor: 50_000,
        currency: "USD",
        merchant_id: "1234567890",
        mcc: "5734",
      },
      BRIDGE,
    );
    if (pending.decision !== "PENDING") throw new Error("expected the same pending answer");
    await service.resume(
      {
        mode: "ATTESTATION",
        intent: JSON.parse(JSON.stringify(pending.escalation.intent)) as Record<string, unknown>,
        attestation: TAPPED,
      },
      PRESENTING_APP,
    );

    // Stripe cannot pend, so the cardholder retries: a new authorization, same card and merchant.
    const retry = stripe("issuing_authorization.request", {
      card: "ic_fixture_flagged",
      amount: 50_000,
    });
    const approved = await bridge.authorizationRequest(retry.body, retry.signature);
    expect(answer(approved)).toMatchObject({
      approved: true,
      metadata: { decionis_decision: "APPROVE" },
    });
    service.close();
  });

  it("in shadow, records the policy's verdict on what Stripe already decided, and never answers a card", async () => {
    const service = executor("SHADOW");
    const { bridge, lines } = bridgeOver(service, "shadow");
    const realtime = stripe("issuing_authorization.request", {
      card: "ic_fixture_shadow",
      amount: 4_250,
    });
    expect((await bridge.authorizationRequest(realtime.body, realtime.signature)).status).toBe(404);

    const created = stripe("issuing_authorization.created", {
      card: "ic_fixture_shadow",
      amount: 4_250,
    });
    const observed = await bridge.event(created.body, created.signature);
    expect(JSON.parse(observed.body)).toEqual({ observed: true });
    expect(lines.at(-1)).toMatchObject({
      event: "STRIPE_SHADOW_OBSERVED",
      stripe_approved: true,
      decision: "NO_MATCH",
      code: "SHADOW_OBSERVED",
    });
    service.close();
  });
});
