import { describe, expect, it } from "vitest";
import { CardOutcomeEvidenceProvider } from "../../src/outcomes/CardOutcomeEvidence.js";
import {
  CoreOutcomeEvidenceClient,
  OutcomeEvidenceRefusal,
} from "../../src/outcomes/CoreOutcomeEvidenceClient.js";
import {
  OUTCOME_SUBMISSION_VERSION,
  type OutcomeEvidenceDraft,
  type OutcomeEvidenceSubmission,
} from "../../src/outcomes/OutcomeEvidence.js";
import type { FetchLike } from "../../src/handlers/HandlerRegistration.js";
import {
  ORG_ID,
  PRODUCER_TOKEN,
  at,
  claimed,
  decided,
  settled,
} from "../support/CardOutcomeFacts.js";

const BASE = "https://authority.decionis.example";
const draft = new CardOutcomeEvidenceProvider().map(
  [decided(), claimed(), settled()],
  new Date(Date.parse(at(3_600))),
) as OutcomeEvidenceDraft;
const SUBMISSION: OutcomeEvidenceSubmission = {
  version: OUTCOME_SUBMISSION_VERSION,
  producer: "agentsafe",
  org_id: ORG_ID,
  evidence: [{ ...draft, revision: 1 }],
};

interface Seen {
  readonly url: string;
  readonly init: RequestInit;
}

function answering(status: number, body: unknown, seen: Seen[] = []): FetchLike {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    seen.push({ url: String(input), init: init ?? {} });
    await Promise.resolve();
    return new Response(typeof body === "string" ? body : JSON.stringify(body), { status });
  }) as FetchLike;
}

const client = (fetch: FetchLike, token: () => string = () => PRODUCER_TOKEN) =>
  new CoreOutcomeEvidenceClient({ baseUrl: BASE, token, fetch });

async function refusal(work: Promise<unknown>): Promise<OutcomeEvidenceRefusal> {
  try {
    await work;
  } catch (error) {
    if (error instanceof OutcomeEvidenceRefusal) return error;
    throw error;
  }
  throw new Error("expected a refusal");
}

describe("Core's outcome evidence resource", () => {
  it("posts the submission with the producer token, and reads Core's two counts", async () => {
    const seen: Seen[] = [];
    const answer = await client(answering(200, { accepted: 1, duplicates: 0 }, seen)).submit(
      SUBMISSION,
    );
    expect(answer).toEqual({ accepted: 1, duplicates: 0 });
    expect(seen).toHaveLength(1);
    expect(seen[0]?.url).toBe(`${BASE}/v1/outcomes/evidence`);
    expect(seen[0]?.init).toMatchObject({
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/json", authorization: `Bearer ${PRODUCER_TOKEN}` },
    });
    expect(seen[0]?.init.signal).toBeInstanceOf(AbortSignal);
    expect(JSON.parse(String(seen[0]?.init.body))).toEqual(SUBMISSION);
  });

  it("names the subject of a revision conflict, so the next attempt can state it under the next revision", async () => {
    const subject = "a".repeat(64);
    const conflict = await refusal(
      client(
        answering(409, { error: "evidence_revision_conflict", subject_digest: subject }),
      ).submit(SUBMISSION),
    );
    expect(conflict).toMatchObject({
      code: "OUTCOME_EVIDENCE_REVISION_CONFLICT",
      permanent: false,
      conflict: subject,
    });
    for (const body of [{ error: "evidence_revision_conflict" }, { error: "other" }, "not json"]) {
      expect(await refusal(client(answering(409, body)).submit(SUBMISSION))).toMatchObject({
        code: "OUTCOME_EVIDENCE_CONFLICT",
        permanent: true,
        conflict: null,
      });
    }
  });

  it("treats what the same submission cannot get past as permanent, and anything else as worth retrying", async () => {
    const cases: readonly [number, string, boolean][] = [
      [400, "OUTCOME_EVIDENCE_REFUSED", true],
      [401, "OUTCOME_PRODUCER_REQUIRED", true],
      [403, "OUTCOME_PRODUCER_NOT_ALLOWED", true],
      [404, "OUTCOME_ROUTE_OR_ORGANIZATION_MISSING", true],
      [413, "OUTCOME_EVIDENCE_REFUSED", true],
      [422, "OUTCOME_EVIDENCE_REFUSED", true],
      [429, "OUTCOME_EVIDENCE_UNAVAILABLE", false],
      [500, "OUTCOME_EVIDENCE_UNAVAILABLE", false],
      [503, "OUTCOME_EVIDENCE_UNAVAILABLE", false],
    ];
    for (const [status, code, permanent] of cases) {
      const body = { error: "outcomes_disabled", detail: "from Core" };
      expect(
        await refusal(client(answering(status, body)).submit(SUBMISSION)),
        String(status),
      ).toMatchObject({ code, permanent });
    }
    for (const body of [{ accepted: 1 }, { accepted: -1, duplicates: 0 }, [1, 2], "{"]) {
      expect(await refusal(client(answering(200, body)).submit(SUBMISSION))).toMatchObject({
        code: "OUTCOME_EVIDENCE_RESPONSE_INVALID",
        permanent: false,
      });
    }
    const unreachable = (async () => {
      await Promise.resolve();
      throw new TypeError("connect ECONNREFUSED 127.0.0.1:443");
    }) as FetchLike;
    expect(await refusal(client(unreachable).submit(SUBMISSION))).toMatchObject({
      code: "OUTCOME_EVIDENCE_UNAVAILABLE",
      permanent: false,
    });
  });

  it("gives up on a request that outlives its budget", async () => {
    const stalled = ((_input: string | URL | Request, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      })) as FetchLike;
    const slow = new CoreOutcomeEvidenceClient({
      baseUrl: BASE,
      token: () => PRODUCER_TOKEN,
      fetch: stalled,
      timeoutMs: 20,
    });
    expect(await refusal(slow.submit(SUBMISSION))).toMatchObject({
      code: "OUTCOME_EVIDENCE_UNAVAILABLE",
      permanent: false,
    });
  });

  it("sends nothing without a token Core's producer registry would take", async () => {
    const seen: Seen[] = [];
    const fetch = answering(200, { accepted: 1, duplicates: 0 }, seen);
    expect(await refusal(client(fetch, () => "short").submit(SUBMISSION))).toMatchObject({
      code: "OUTCOME_PRODUCER_TOKEN_INVALID",
      permanent: true,
    });
    expect(
      await refusal(
        client(fetch, () => {
          throw new Error("SECRET_UNKNOWN");
        }).submit(SUBMISSION),
      ),
    ).toMatchObject({ code: "OUTCOME_PRODUCER_TOKEN_UNAVAILABLE", permanent: false });
    expect(seen).toEqual([]);
  });
});
