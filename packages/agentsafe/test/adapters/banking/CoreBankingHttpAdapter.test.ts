import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { DownstreamCredential } from "../../../src/credential/DownstreamCredential.js";
import { MonotonicDeadline } from "../../../src/time/MonotonicClock.js";
import { IndeterminateOutcome } from "../../../src/adapters/EffectAdapter.js";
import type { AdapterExecution } from "../../../src/adapters/EffectAdapter.js";
import { BankingAdapter } from "../../../src/adapters/banking/BankingAdapter.js";
import { CoreBankingHttpAdapter } from "../../../src/adapters/banking/CoreBankingHttpAdapter.js";
import type { BankingAction } from "../../../src/adapters/banking/BankingAction.js";
import { BankingDouble } from "../../support/BankingDouble.js";
import { bankingAction } from "../../support/BankingFixtures.js";

const provider = new BankingDouble();
const SECRET = "Bearer synthetic-downstream-credential-0123456789";

const credential: DownstreamCredential = {
  kind: "STATIC_HEADER",
  headersFor: () => Promise.resolve({ authorization: SECRET }),
};

beforeAll(async () => {
  await provider.start();
});

afterAll(async () => {
  await provider.stop();
});

const prepareOnly = new BankingAdapter({
  id: "synthetic-core-banking",
  version: "0.1.0",
  transport: {
    execute: () => Promise.reject(new Error("prepare only")),
    reconcile: () => Promise.reject(new Error("prepare only")),
  },
});

function transport(options: { readonly byReference?: boolean; readonly byKey?: boolean } = {}) {
  return new CoreBankingHttpAdapter({
    url: provider.executeUrl,
    lookupByReferenceUrl: options.byReference === false ? null : provider.lookupByReferenceUrl,
    lookupByKeyUrl: options.byKey === false ? null : provider.lookupByKeyUrl,
    credential,
    fetch: globalThis.fetch,
    source: "CORE_BANKING_RESPONSE",
  });
}

function execution(action: BankingAction = bankingAction()): AdapterExecution<BankingAction> {
  return {
    action,
    prepared: prepareOnly.prepare(action),
    authorization: {
      decisionId: "synthetic-decision-1",
      dossierId: "synthetic-dossier-1",
      grantId: "synthetic-grant-1",
      intentHash: `sha256:${"a".repeat(64)}`,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    },
    idempotencyKey: "synthetic-req-0001",
    deadline: MonotonicDeadline.after(2_000),
  };
}

async function refusal(work: Promise<unknown>): Promise<IndeterminateOutcome> {
  try {
    await work;
  } catch (error) {
    if (error instanceof IndeterminateOutcome) return error;
    throw error;
  }
  throw new Error("expected an indeterminate outcome");
}

describe("CoreBankingHttpAdapter.execute", () => {
  it("sends the canonical action with the key, the intent hash and both digests", async () => {
    provider.answer({ status: 202, body: { status: "ACCEPTED", reference: "fixture_ref_1" } });
    provider.readBack = null;
    const run = execution();
    const result = await transport().execute(run);
    expect(result).toMatchObject({
      status: "COMMITTED",
      providerStatus: "ACCEPTED",
      providerReference: "fixture_ref_1",
      observationMethod: "DOWNSTREAM_ACK",
      observed: null,
      providerGenerated: true,
    });
    const sent = provider.requests.at(-1);
    expect(sent?.headers["idempotency-key"]).toBe("synthetic-req-0001");
    expect(sent?.headers["x-agent-safe-intent-hash"]).toBe(run.authorization.intentHash);
    expect(sent?.headers["x-beap-intent-digest"]).toBe(run.prepared.intentDigest);
    expect(sent?.headers["x-beap-expected-effect-digest"]).toBe(run.prepared.expectedEffectDigest);
    expect(sent?.headers["authorization"]).toBe(SECRET);
    expect(JSON.parse(sent?.body ?? "{}")).toEqual(bankingAction());
  });

  it("treats every acknowledgement as committed but unobserved", async () => {
    for (const status of ["ACCEPTED", "QUEUED", "PROCESSING", "PENDING", "queued"]) {
      provider.answer({ status: 202, body: { status } });
      const result = await transport().execute(execution());
      expect(result.status, status).toBe("COMMITTED");
      expect(result.observationMethod, status).toBe("DOWNSTREAM_ACK");
      expect(result.observed, status).toBeNull();
    }
  });

  it("reads the effect back after a posted status, and only then observes it", async () => {
    const run = execution();
    provider.answer({ status: 200, body: { status: "POSTED", reference: "fixture_ref_2" } });
    provider.readBack = {
      status: 200,
      body: { status: "POSTED", effect: run.prepared.expectedEffect },
    };
    const before = provider.requests.length;
    const result = await transport().execute(run);
    expect(result.observationMethod).toBe("READ_AFTER_WRITE");
    expect(result.observed).toEqual(run.prepared.expectedEffect);
    const lookup = provider.requests.at(-1);
    expect(lookup?.method).toBe("GET");
    expect(lookup?.path).toContain("by-reference/fixture_ref_2");
    expect(provider.requests.length).toBe(before + 2);
  });

  it("reads back by key when the provider gave no reference", async () => {
    const run = execution();
    provider.answer({ status: 200, body: { status: "SETTLED" } });
    provider.readBack = {
      status: 200,
      body: { status: "SETTLED", effect: run.prepared.expectedEffect },
    };
    await transport().execute(run);
    expect(provider.requests.at(-1)?.path).toContain("by-key/synthetic-req-0001");
  });

  it("stays an unconfirmed commit when the effect cannot be read back", async () => {
    provider.answer({ status: 200, body: { status: "POSTED", reference: "fixture_ref_3" } });
    provider.readBack = null;
    const missing = await transport().execute(execution());
    expect(missing).toMatchObject({ status: "COMMITTED", observationMethod: "DOWNSTREAM_ACK" });
    expect(missing.observed).toBeNull();

    provider.answer({ status: 200, body: { status: "POSTED", reference: "fixture_ref_3" } });
    provider.readBack = { status: 200, body: { status: "POSTED" } };
    const bodyless = await transport().execute(execution());
    expect(bodyless.observed).toBeNull();

    provider.answer({ status: 200, body: { status: "POSTED", reference: "fixture_ref_3" } });
    provider.readBack = { status: 200, body: "not json" };
    expect((await transport().execute(execution())).observed).toBeNull();

    provider.answer({ status: 200, body: { status: "POSTED" } });
    expect(
      (await transport({ byReference: false, byKey: false }).execute(execution())).observed,
    ).toBeNull();
  });

  it("reports a deterministic refusal as effecting nothing", async () => {
    for (const [status, code] of [
      [400, "REJECTED"],
      [404, "DECLINED"],
      [409, "FAILED"],
      [422, "INVALID"],
    ] as const) {
      provider.answer({ status, body: { status: code, reason_code: "LIMIT" } });
      const result = await transport().execute(execution());
      expect(result.status, code).toBe("FAILED");
      expect(result.failureReason, code).toBe("POLICY_STATE_CHANGED");
      expect(result.observed, code).toBeNull();
    }
  });

  it("refuses to conclude anything from a server error, a silence, or a status it cannot read", async () => {
    provider.answer({ status: 500, body: { status: "OOPS" } });
    expect((await refusal(transport().execute(execution()))).reason).toBe("PROVIDER_SERVER_ERROR");

    provider.answer({ status: 200, body: "not json at all" });
    expect((await refusal(transport().execute(execution()))).reason).toBe(
      "PROVIDER_RESPONSE_UNREADABLE",
    );

    provider.answer({ status: 200, body: { status: "MAYBE" } });
    const unknown = await refusal(transport().execute(execution()));
    expect(unknown.reason).toBe("PROVIDER_STATUS_UNKNOWN");
    expect(unknown.providerStatus).toBe("MAYBE");

    provider.answer({ status: 409, body: { status: "MAYBE" } });
    expect((await refusal(transport().execute(execution()))).reason).toBe(
      "PROVIDER_STATUS_UNKNOWN",
    );

    provider.loseNext();
    expect((await refusal(transport().execute(execution()))).reason).toBe("PROVIDER_UNREACHABLE");
  });
});

describe("CoreBankingHttpAdapter.reconcile", () => {
  const context = (reference: string | null = null) => ({
    idempotencyKey: "synthetic-req-0001",
    providerReference: reference,
    intentHash: `sha256:${"a".repeat(64)}`,
    prepared: prepareOnly.prepare(bankingAction()),
  });

  it("completes only on a posted read-back that carries the effect", async () => {
    const prepared = prepareOnly.prepare(bankingAction());
    provider.readBack = {
      status: 200,
      body: { status: "POSTED", effect: prepared.expectedEffect },
    };
    const answer = await transport().reconcile(context());
    expect(answer.status).toBe("COMPLETED");
    expect(answer.status === "COMPLETED" && answer.result.observationMethod).toBe(
      "STATE_RECONCILIATION",
    );
  });

  it("is NOT_EXECUTED for an absent record or a refusal, and never initiates anything", async () => {
    const posts = provider.posts;
    provider.readBack = null;
    expect((await transport().reconcile(context())).status).toBe("NOT_EXECUTED");
    provider.readBack = { status: 200, body: { status: "REJECTED" } };
    expect((await transport().reconcile(context())).status).toBe("NOT_EXECUTED");
    expect(provider.posts).toBe(posts);
  });

  it("is UNKNOWN for anything it cannot read, and when there is nowhere to look", async () => {
    provider.readBack = { status: 200, body: { status: "POSTED" } };
    expect((await transport().reconcile(context())).status).toBe("UNKNOWN");
    provider.readBack = { status: 200, body: "not json" };
    expect((await transport().reconcile(context())).status).toBe("UNKNOWN");
    provider.readBack = { status: 500, body: { status: "OOPS" } };
    expect((await transport().reconcile(context())).status).toBe("UNKNOWN");
    provider.readBack = { status: 200, body: { status: "PROCESSING" } };
    expect((await transport().reconcile(context())).status).toBe("UNKNOWN");
    expect(
      (await transport({ byReference: false, byKey: false }).reconcile(context())).status,
    ).toBe("UNKNOWN");
  });

  it("prefers the provider's own reference over the idempotency key", async () => {
    const prepared = prepareOnly.prepare(bankingAction());
    provider.readBack = {
      status: 200,
      body: { status: "POSTED", effect: prepared.expectedEffect },
    };
    await transport().reconcile(context("fixture ref/4"));
    expect(provider.requests.at(-1)?.path).toContain("by-reference/fixture%20ref%2F4");
  });
});

describe("the response digest", () => {
  it("is taken over the material subset, so two different bodies saying the same agree", () => {
    const one = CoreBankingHttpAdapter.materialDigest({ status: "POSTED", reference: "r1" });
    const same = CoreBankingHttpAdapter.materialDigest({ status: "posted", reference: "r1" });
    expect(one).toBe(same);
    expect(CoreBankingHttpAdapter.materialDigest({ status: "POSTED" })).not.toBe(one);
    expect(
      CoreBankingHttpAdapter.materialDigest({
        status: "POSTED",
        reference: "r1",
        effect: { a: 1 },
      }),
    ).not.toBe(one);
    expect(CoreBankingHttpAdapter.digestOfText("x")).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});
