import type {
  ApiAnswer,
  ApiProfile,
  ApiRequest,
  JsonValue,
  TargetPrecondition,
} from "@decionis/agent-safe-pipeline";
import {
  effectRecord,
  expectEffect,
  refusalOutcome,
  type EffectPending,
  type ExpectedEffect,
  type ObservedEffect,
  type RefusalOutcome,
} from "./TargetEffect.js";
import type { Upstream } from "./Upstream.js";

/**
 * What the gateway read of one profiled write's target before the authority
 * was asked: the read its profile names, the precondition the answer stated,
 * and what the grant commits the write's effect to, or why it commits to none.
 */
export interface TargetPlan {
  /** The write's operation in the profile. */
  readonly operation: string;
  readonly read: ApiRequest;
  readonly precondition: TargetPrecondition;
  readonly effect: ExpectedEffect | EffectPending;
}

/** Why a write was refused before the authority was asked: its target stated no usable version. */
export interface TargetRefusal {
  readonly reasonCodes: readonly ["TARGET_STATE_UNREADABLE", string];
}

/** One read of a write's target after a refusal, against the read before the decision. */
export interface RefusalRead {
  readonly outcome: RefusalOutcome;
  readonly version: string | null;
  readonly readAt: string;
}

type Read = { readonly answer: ApiAnswer; readonly at: Date } | { readonly code: string };

export interface TargetReaderOptions {
  readonly profile: ApiProfile;
  readonly upstream: Upstream;
  readonly clock: () => number;
  /** The reason code for a send that threw, as the gateway names a failed forward. */
  readonly failure: (error: unknown) => string;
}

/**
 * The gateway's reads of a write's target, the one read its API profile
 * names, at three moments: before the authority is asked, so the intent
 * binds the version it is decided against; after an `ALLOW` the upstream
 * answered with a `2xx`, so what landed is compared with what was
 * authorised; and after a refusal, so the target is seen to have stayed
 * where it was. Every read is a `GET` the gateway makes as itself
 * (`Upstream.ownHeaders`), bounded like a forward, and nothing it reads is
 * relayed to a caller.
 */
export class TargetReader {
  public constructor(private readonly options: TargetReaderOptions) {}

  /**
   * The plan for a write, or null when its operation names no read. A read
   * that does not answer `2xx`, or whose answer states no usable version, is
   * a refusal: the write is never decided against no version at all.
   */
  public async plan(
    operation: string,
    request: ApiRequest,
    factsOnly: boolean,
  ): Promise<TargetPlan | TargetRefusal | null> {
    const { profile } = this.options;
    const read = profile.stateRead(request);
    if (read === null) return null;
    const answered = await this.read(read);
    if ("code" in answered) return { reasonCodes: ["TARGET_STATE_UNREADABLE", answered.code] };
    const precondition = profile.precondition(operation, answered.answer, answered.at);
    if (precondition === null) {
      return { reasonCodes: ["TARGET_STATE_UNREADABLE", "TARGET_VERSION_UNSTATED"] };
    }
    return {
      operation,
      read,
      precondition,
      effect: expectEffect(this.named(operation), profile.expectedEffect(request), factsOnly),
    };
  }

  /** The read after a write the upstream answered `2xx`, against what the grant committed to. */
  public async effect(plan: TargetPlan, effect: ExpectedEffect): Promise<ObservedEffect> {
    const answered = await this.read(plan.read);
    return effectRecord({
      operation: this.named(plan.operation),
      effect,
      observed:
        "code" in answered
          ? null
          : this.options.profile.observedEffect(plan.operation, answered.answer, effect.expected),
      observedAt: new Date(this.options.clock()).toISOString(),
    });
  }

  /** The read after a refusal: the version now, against the one the decision was asked about. */
  public async refusal(plan: TargetPlan): Promise<RefusalRead> {
    const answered = await this.read(plan.read);
    const after =
      "code" in answered
        ? null
        : this.options.profile.precondition(plan.operation, answered.answer, answered.at);
    return {
      outcome: refusalOutcome(plan.precondition, after),
      version: after?.version ?? null,
      readAt: new Date(this.options.clock()).toISOString(),
    };
  }

  /** An operation as the effect digest names it: `<profile>#<operation>`, as a precondition's source does. */
  private named(operation: string): string {
    return `${this.options.profile.id}#${operation}`;
  }

  /**
   * One `GET` of the target: its headers, which the relay already names in
   * lower case, and its body when it is JSON; or why there is no answer to
   * read, a status past `2xx` included (the transport delivers no `1xx`).
   */
  private async read(read: ApiRequest): Promise<Read> {
    const { upstream } = this.options;
    let status: number;
    let headers: readonly (readonly [string, string])[];
    let body: Buffer;
    try {
      ({ status, headers, body } = await upstream.send(
        "GET",
        read.path,
        TargetReader.search(read.query ?? {}),
        upstream.ownHeaders(),
        Buffer.alloc(0),
        upstream.signal(),
      ));
    } catch (error) {
      return { code: this.options.failure(error) };
    }
    if (status >= 300) return { code: `UPSTREAM_STATUS_${status}` };
    const answer: ApiAnswer = { headers: Object.fromEntries(headers) };
    const at = new Date(this.options.clock());
    try {
      return { answer: { ...answer, body: JSON.parse(body.toString()) as JsonValue }, at };
    } catch {
      // A body that is not JSON states nothing there; its headers still may.
      return { answer, at };
    }
  }

  /**
   * A read's query as a query string, each name and value percent-encoded:
   * the exact values its profile operation names, one string each.
   */
  private static search(query: NonNullable<ApiRequest["query"]>): string {
    const pairs = Object.entries(query).map(
      ([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(String(value))}`,
    );
    return pairs.length === 0 ? "" : `?${pairs.join("&")}`;
  }
}
