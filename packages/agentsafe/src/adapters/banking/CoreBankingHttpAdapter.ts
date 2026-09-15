import { createHash } from "node:crypto";
import { z } from "zod";
import type { JsonObject } from "@decionis/agent-safe-pipeline";
import type { DownstreamCredential } from "../../credential/DownstreamCredential.js";
import type { FetchLike } from "../../handlers/HandlerRegistration.js";
import { jcsDigest, type Sha256 } from "../JcsDigest.js";
import {
  IndeterminateOutcome,
  type AdapterExecution,
  type AdapterReconciliation,
  type ObservationMethod,
  type ProviderReconciliationResult,
  type ProviderResult,
} from "../EffectAdapter.js";
import type { BankingAction } from "./BankingAction.js";
import type { BankingTransport } from "./BankingAdapter.js";

/**
 * The provider's answer, as this adapter requires it. A body that does not
 * fit is not a failure and not a success: it is an outcome nobody can
 * determine, which is what `IndeterminateOutcome` says.
 */
const ResponseSchema = z.object({
  status: z.string().min(1).max(64),
  reference: z.string().min(1).max(500).optional(),
  reason_code: z.string().max(64).optional(),
  effect: z.record(z.string(), z.unknown()).optional(),
});

/** How a provider's status maps onto what this boundary may claim. */
const ACCEPTED = new Set(["ACCEPTED", "QUEUED", "PROCESSING", "PENDING"]);
const POSTED = new Set(["POSTED", "SETTLED", "COMPLETED", "EXECUTED"]);
const REFUSED = new Set(["REJECTED", "DECLINED", "FAILED", "INVALID"]);

export interface CoreBankingHttpOptions {
  readonly url: string;
  /** `{provider_reference}` is substituted; absent when the provider has no lookup. */
  readonly lookupByReferenceUrl: string | null;
  /** `{idempotency_key}` is substituted; absent when the provider has no lookup. */
  readonly lookupByKeyUrl: string | null;
  readonly credential: DownstreamCredential;
  readonly fetch: FetchLike;
  readonly source: string;
}

/**
 * The reference transport for the banking family: one HTTP call per action,
 * with the outcome mapping written out rather than inferred.
 *
 * | The provider says                        | This boundary reports                        |
 * | ---------------------------------------- | -------------------------------------------- |
 * | 2xx, a status meaning it took the request | `COMMITTED`, acknowledged, not yet confirmed |
 * | 2xx, a status meaning it posted           | `COMMITTED`, then read back before confirming |
 * | a deterministic refusal with a body       | `FAILED`, nothing was effected               |
 * | anything else: no body, a timeout, a 5xx  | indeterminate, and reconciliation owns it    |
 *
 * An acknowledgement is never a confirmation, and the absence of an error is
 * never success: only a read-back whose projection matches what was
 * authorised confirms anything.
 */
export class CoreBankingHttpAdapter implements BankingTransport {
  public constructor(private readonly options: CoreBankingHttpOptions) {}

  public async execute(execution: AdapterExecution<BankingAction>): Promise<ProviderResult> {
    const body = JSON.stringify(execution.action);
    const headers = await this.options.credential.headersFor({
      method: "POST",
      url: this.options.url,
      body,
      idempotencyKey: execution.idempotencyKey,
      intentHash: execution.authorization.intentHash,
    });
    let response: Response;
    try {
      response = await this.options.fetch(this.options.url, {
        method: "POST",
        headers: {
          ...headers,
          "content-type": "application/json",
          "idempotency-key": execution.idempotencyKey,
          "x-agent-safe-intent-hash": execution.authorization.intentHash,
          "x-beap-intent-digest": execution.prepared.intentDigest,
          "x-beap-expected-effect-digest": execution.prepared.expectedEffectDigest,
        },
        body,
        signal: execution.deadline.signal(),
      });
    } catch {
      // Past the point of no return with nothing to read: the provider may
      // have acted, and saying otherwise would be a guess.
      throw new IndeterminateOutcome("PROVIDER_UNREACHABLE");
    }
    const text = await response.text();
    if (response.status >= 500)
      throw new IndeterminateOutcome("PROVIDER_SERVER_ERROR", String(response.status));
    let parsed: z.infer<typeof ResponseSchema>;
    try {
      parsed = ResponseSchema.parse(JSON.parse(text));
    } catch {
      throw new IndeterminateOutcome("PROVIDER_RESPONSE_UNREADABLE", String(response.status));
    }
    const status = parsed.status.toUpperCase();
    const responseDigest = CoreBankingHttpAdapter.materialDigest(parsed);
    if (!response.ok) {
      if (!REFUSED.has(status)) {
        throw new IndeterminateOutcome("PROVIDER_STATUS_UNKNOWN", status);
      }
      return {
        status: "FAILED",
        providerStatus: status,
        providerReference: parsed.reference ?? null,
        responseDigest,
        // The provider refused deterministically; the profile's code for a
        // refusal the authority should see is the one it registers.
        failureReason: "POLICY_STATE_CHANGED",
        observed: null,
        observationMethod: "DOWNSTREAM_ACK",
        providerGenerated: true,
        source: this.options.source,
      };
    }
    if (POSTED.has(status)) {
      const observed = await this.readBack(execution, parsed.reference ?? null);
      return {
        status: "COMMITTED",
        providerStatus: status,
        providerReference: parsed.reference ?? null,
        responseDigest,
        failureReason: null,
        observed: observed.effect,
        observationMethod: observed.method,
        providerGenerated: true,
        source: this.options.source,
      };
    }
    if (ACCEPTED.has(status)) {
      return {
        status: "COMMITTED",
        providerStatus: status,
        providerReference: parsed.reference ?? null,
        responseDigest,
        failureReason: null,
        // An acknowledgement carries no effect to observe, and none is invented.
        observed: null,
        observationMethod: "DOWNSTREAM_ACK",
        providerGenerated: true,
        source: this.options.source,
      };
    }
    throw new IndeterminateOutcome("PROVIDER_STATUS_UNKNOWN", status);
  }

  public async reconcile(context: AdapterReconciliation): Promise<ProviderReconciliationResult> {
    const url = this.lookupUrl(context.idempotencyKey, context.providerReference);
    if (url === null) return { status: "UNKNOWN" };
    let response: Response;
    try {
      response = await this.options.fetch(url, {
        method: "GET",
        headers: await this.options.credential.headersFor({
          method: "GET",
          url,
          body: null,
          idempotencyKey: context.idempotencyKey,
          intentHash: context.intentHash,
        }),
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      return { status: "UNKNOWN" };
    }
    if (response.status === 404) return { status: "NOT_EXECUTED" };
    const text = await response.text();
    if (!response.ok) return { status: "UNKNOWN" };
    let parsed: z.infer<typeof ResponseSchema>;
    try {
      parsed = ResponseSchema.parse(JSON.parse(text));
    } catch {
      return { status: "UNKNOWN" };
    }
    const status = parsed.status.toUpperCase();
    if (REFUSED.has(status)) return { status: "NOT_EXECUTED" };
    if (!POSTED.has(status) || parsed.effect === undefined) return { status: "UNKNOWN" };
    return {
      status: "COMPLETED",
      result: {
        status: "COMMITTED",
        providerStatus: status,
        providerReference: parsed.reference ?? null,
        responseDigest: CoreBankingHttpAdapter.materialDigest(parsed),
        failureReason: null,
        observed: parsed.effect as JsonObject,
        observationMethod: "STATE_RECONCILIATION",
        providerGenerated: true,
        source: this.options.source,
      },
    };
  }

  /** Reads the effect back, by reference when the provider gave one, else by key. */
  private async readBack(
    execution: AdapterExecution<BankingAction>,
    reference: string | null,
  ): Promise<{ readonly effect: JsonObject | null; readonly method: ObservationMethod }> {
    const url = this.lookupUrl(execution.idempotencyKey, reference);
    if (url === null) return { effect: null, method: "DOWNSTREAM_ACK" };
    try {
      const response = await this.options.fetch(url, {
        method: "GET",
        headers: await this.options.credential.headersFor({
          method: "GET",
          url,
          body: null,
          idempotencyKey: execution.idempotencyKey,
          intentHash: execution.authorization.intentHash,
        }),
        signal: execution.deadline.signal(),
      });
      if (!response.ok) return { effect: null, method: "DOWNSTREAM_ACK" };
      const parsed = ResponseSchema.parse(JSON.parse(await response.text()));
      if (parsed.effect === undefined) return { effect: null, method: "DOWNSTREAM_ACK" };
      return { effect: parsed.effect as JsonObject, method: "READ_AFTER_WRITE" };
    } catch {
      // The effect happened; this process could not read it back. That is an
      // unconfirmed commit, not an indeterminate one.
      return { effect: null, method: "DOWNSTREAM_ACK" };
    }
  }

  private lookupUrl(idempotencyKey: string, reference: string | null): string | null {
    if (reference !== null && this.options.lookupByReferenceUrl !== null) {
      return this.options.lookupByReferenceUrl.replace(
        "{provider_reference}",
        encodeURIComponent(reference),
      );
    }
    if (this.options.lookupByKeyUrl !== null) {
      return this.options.lookupByKeyUrl.replace(
        "{idempotency_key}",
        encodeURIComponent(idempotencyKey),
      );
    }
    return null;
  }

  /**
   * The digest of the material subset of the answer: the fields that say
   * what happened, and nothing else. A provider body is never hashed whole,
   * because it may carry anything, including things this process must not
   * retain.
   */
  public static materialDigest(response: {
    readonly status: string;
    readonly reference?: string | undefined;
    readonly reason_code?: string | undefined;
    readonly effect?: Record<string, unknown> | undefined;
  }): Sha256 {
    const material: JsonObject = {
      status: response.status.toUpperCase(),
      reference: response.reference ?? null,
      reason_code: response.reason_code ?? null,
      effect: (response.effect ?? null) as JsonObject | null,
    };
    return jcsDigest(material);
  }

  /** For a caller that holds a body it did not parse; the same subset rule. */
  public static digestOfText(text: string): Sha256 {
    return `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;
  }
}
