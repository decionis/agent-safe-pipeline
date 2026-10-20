import type { FetchLike } from "../handlers/HandlerRegistration.js";
import { isOutcomeDigest, type OutcomeEvidenceSubmission } from "./OutcomeEvidence.js";

export const CORE_OUTCOME_EVIDENCE_PATH = "/v1/outcomes/evidence";
/** Submissions carry up to a thousand subjects; Core's answer is two counts. */
export const OUTCOME_SUBMIT_TIMEOUT_MS = 15_000;

/** Core's evidence resource, as the publisher sees it. */
export interface OutcomeEvidenceSink {
  submit(
    submission: OutcomeEvidenceSubmission,
  ): Promise<{ readonly accepted: number; readonly duplicates: number }>;
}

/**
 * A refused submission. A `permanent` refusal is one the same submission cannot get past by
 * being sent again (evidence Core refuses, a producer it does not know or does not allow); any
 * other is retried later. `conflict` names a subject Core already holds at that revision with
 * other content, which the next attempt states under a higher revision.
 */
export class OutcomeEvidenceRefusal extends Error {
  public constructor(
    public readonly code: string,
    public readonly permanent: boolean,
    public readonly conflict: string | null = null,
  ) {
    super(code);
    this.name = "OutcomeEvidenceRefusal";
  }
}

/** Core's refusals a retry of the same submission cannot fix. */
const PERMANENT: Readonly<Record<number, string>> = {
  400: "OUTCOME_EVIDENCE_REFUSED",
  401: "OUTCOME_PRODUCER_REQUIRED",
  403: "OUTCOME_PRODUCER_NOT_ALLOWED",
  404: "OUTCOME_ROUTE_OR_ORGANIZATION_MISSING",
  413: "OUTCOME_EVIDENCE_REFUSED",
  422: "OUTCOME_EVIDENCE_REFUSED",
};
/** What Core's producer registry accepts as a token: printable ASCII, 32 to 512 characters. */
const TOKEN = /^[\x21-\x7e]{32,512}$/;

const count = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

export interface CoreOutcomeEvidenceClientOptions {
  /** The authority's base URL, already normalized: Core serves the meter beside it. */
  readonly baseUrl: string;
  /** The producer token, read at the moment of each request and never held. */
  readonly token: () => string;
  /** The guarded fetch: the authority's origin and trust anchors, and nothing else. */
  readonly fetch: FetchLike;
  readonly timeoutMs?: number;
}

/**
 * `POST {DECIONIS_API_URL}/v1/outcomes/evidence` with AgentSafe's producer token, the credential
 * Core's producer registry names with `outcomes: "agentsafe"`; a customer's own key is never a
 * producer, so the bank's API key cannot feed the meter that measures it. A 503
 * (`outcomes_disabled`, `outcomes_unavailable`), a timeout or an outage is retried later; a 409
 * names the subject Core already holds at that revision. Core's body, the URL and the token
 * never leave this class.
 */
export class CoreOutcomeEvidenceClient implements OutcomeEvidenceSink {
  private readonly url: string;
  private readonly timeoutMs: number;

  public constructor(private readonly options: CoreOutcomeEvidenceClientOptions) {
    this.url = `${options.baseUrl}${CORE_OUTCOME_EVIDENCE_PATH}`;
    this.timeoutMs = options.timeoutMs ?? OUTCOME_SUBMIT_TIMEOUT_MS;
  }

  public async submit(
    submission: OutcomeEvidenceSubmission,
  ): Promise<{ readonly accepted: number; readonly duplicates: number }> {
    let token: string;
    try {
      token = this.options.token();
    } catch {
      throw new OutcomeEvidenceRefusal("OUTCOME_PRODUCER_TOKEN_UNAVAILABLE", false);
    }
    if (!TOKEN.test(token))
      throw new OutcomeEvidenceRefusal("OUTCOME_PRODUCER_TOKEN_INVALID", true);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let status: number;
    let text: string;
    try {
      const response = await this.options.fetch(this.url, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify(submission),
        redirect: "error",
        signal: controller.signal,
      });
      status = response.status;
      text = await response.text();
    } catch {
      throw new OutcomeEvidenceRefusal("OUTCOME_EVIDENCE_UNAVAILABLE", false);
    } finally {
      clearTimeout(timer);
    }
    const answer = CoreOutcomeEvidenceClient.object(text);
    if (status === 409) {
      const subject = answer["subject_digest"];
      if (answer["error"] === "evidence_revision_conflict" && isOutcomeDigest(subject)) {
        throw new OutcomeEvidenceRefusal("OUTCOME_EVIDENCE_REVISION_CONFLICT", false, subject);
      }
      throw new OutcomeEvidenceRefusal("OUTCOME_EVIDENCE_CONFLICT", true);
    }
    const permanent = PERMANENT[status];
    if (permanent !== undefined) throw new OutcomeEvidenceRefusal(permanent, true);
    if (status !== 200) throw new OutcomeEvidenceRefusal("OUTCOME_EVIDENCE_UNAVAILABLE", false);
    const accepted = answer["accepted"];
    const duplicates = answer["duplicates"];
    if (!count(accepted) || !count(duplicates)) {
      throw new OutcomeEvidenceRefusal("OUTCOME_EVIDENCE_RESPONSE_INVALID", false);
    }
    return { accepted, duplicates };
  }

  /** Core's answer as an object, or an empty one when it is not one. */
  private static object(text: string): Record<string, unknown> {
    try {
      const value: unknown = JSON.parse(text);
      return value !== null && typeof value === "object" && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : {};
    } catch {
      return {};
    }
  }
}
