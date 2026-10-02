import { createHash } from "node:crypto";
import { z } from "zod";
import type { LocalGrants } from "../../execution/LocalAuthorizationVerifier.js";
import type { ReplayStore } from "../../execution/ReplayStore.js";
import type { CapturedIntent } from "../../intent/ExecutionIntent.js";
import { DecionisGate } from "../DecionisGate.js";
import {
  FailClosedDecision,
  type DecisionAuthority,
  type DecisionEvaluationMode,
  type DecisionEvaluationOptions,
  type DecisionEvidence,
  type DecisionVerdict,
  type GateDecision,
} from "../DecisionAuthority.js";
import { immutableGateDecision } from "../ImmutableGateDecision.js";
import type { EdgeBundleManager, LoadedBundle } from "./EdgeBundleManager.js";
import type { EdgeModule } from "./EdgeModule.js";

/** What happens when no local decision can be made: ask Decionis, or refuse. */
export type EdgeUnavailablePolicy = "hosted" | "block";

/**
 * One line of local evidence. A decision line names the bundle it was made
 * on and the digest of the evaluation; it carries the identifiers and the
 * verdict the hosted record carries, and no parameter, amount, or value from
 * the intent. These lines are what a deployment's edge usage is counted from.
 */
export type EdgeDecisionRecord =
  | {
      readonly event: "EDGE_DECISION";
      readonly mode: DecisionEvaluationMode;
      readonly intent_id: string;
      readonly intent_hash: string;
      readonly decision_id: string;
      readonly verdict: DecisionVerdict;
      readonly reason_codes: readonly string[];
      readonly policy_version: string;
      readonly bundle_id: string;
      readonly kid: string;
      readonly jti: string;
      readonly evaluation_digest: string;
      /** True when the verdict sends the intent on to Decionis (an `ESCALATE` in enforcement). */
      readonly delegated: boolean;
    }
  | {
      readonly event: "EDGE_UNAVAILABLE";
      readonly mode: DecisionEvaluationMode;
      readonly intent_id: string;
      readonly intent_hash: string;
      readonly reason: string;
      /** The module's own refusal code, when it gave one. */
      readonly module_code: string | null;
      readonly fallback: "HOSTED" | "BLOCK";
    };

export interface EdgeDecisionAuthorityOptions {
  readonly module: EdgeModule;
  readonly bundles: EdgeBundleManager;
  /**
   * The hosted authority: Decionis through `enforce-and-bind`. An `ESCALATE`
   * goes to it, so Presence and attestation flows run as they always have,
   * and so does an intent the edge cannot decide when `onUnavailable` is
   * `hosted`.
   */
  readonly hosted: DecisionAuthority;
  /** Where an enforcement `ALLOW` is held for the executor to consume once. */
  readonly grants: LocalGrants;
  /**
   * The single-use store the local verifier claims intents in. When given,
   * an enforcement decision about an intent that has already run (on this
   * replica or, with a shared store, on any) is refused before it is made.
   */
  readonly replay?: ReplayStore;
  readonly mode?: DecisionEvaluationMode;
  /** `hosted` (the default) or `block`. Neither ever allows without a valid bundle. */
  readonly onUnavailable?: EdgeUnavailablePolicy;
  readonly clock?: () => number;
  /** The executor's evidence stream. A decision that cannot be recorded is not made. */
  readonly record?: (record: EdgeDecisionRecord) => void;
}

const sha256 = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const identifier = z.string().min(1).max(200);

/** The `decide` result (module ABI 3). Fields beyond these are not read. */
const DecideResultSchema = z.object({
  verdict: z.enum(["ALLOW", "ESCALATE", "BLOCK"]),
  reason_codes: z.array(identifier).max(50),
  policy_version: identifier,
  bundle: z.object({
    bundle_id: identifier,
    policy_version: identifier,
    kid: identifier,
    jti: identifier,
  }),
  authority_requirement: z.record(z.string(), z.unknown()).nullable(),
  evaluation_digest: sha256,
});

type DecideResult = z.infer<typeof DecideResultSchema>;

/**
 * A `DecisionAuthority` that decides inside the deployment, with the Decionis
 * edge evaluator: the same verdict hosted `enforce-and-bind` gives for the
 * same binding and bundle, with no network call on the way.
 *
 * - `ALLOW` in enforcement becomes a local authorization, held in
 *   `LocalGrants` and consumed once by `LocalAuthorizationVerifier`; there is
 *   no Decionis grant on this path and nothing to claim.
 * - `BLOCK` is a refusal, as it is hosted.
 * - `ESCALATE` in enforcement hands the same intent, with the same escalation
 *   options, to the hosted authority: the human-approval paths are hosted.
 * - Approval evidence is only ever evaluated hosted.
 * - No usable bundle, a module fault, or a result this host cannot read
 *   follows `onUnavailable`: the hosted authority, or a fail-closed `BLOCK`.
 *
 * This class is the open host. The evaluator is a separately licensed
 * module this package does not contain; without it the executor runs on the
 * hosted authority alone, exactly as it does without this class.
 */
export class EdgeDecisionAuthority implements DecisionAuthority {
  public readonly evaluationMode: DecisionEvaluationMode;
  private readonly onUnavailable: EdgeUnavailablePolicy;
  private readonly clock: () => number;

  public constructor(private readonly options: EdgeDecisionAuthorityOptions) {
    const mode = options.mode ?? "ENFORCEMENT";
    if (mode !== "ENFORCEMENT" && mode !== "SHADOW") throw new Error("EDGE_MODE_INVALID");
    const hostedMode = options.hosted.evaluationMode;
    if (hostedMode !== undefined && hostedMode !== mode) throw new Error("EDGE_MODE_MISMATCH");
    const onUnavailable = options.onUnavailable ?? "hosted";
    if (onUnavailable !== "hosted" && onUnavailable !== "block") {
      throw new Error("EDGE_ON_UNAVAILABLE_INVALID");
    }
    this.evaluationMode = mode;
    this.onUnavailable = onUnavailable;
    this.clock = options.clock ?? Date.now;
  }

  public async evaluate(
    captured: CapturedIntent,
    evidence?: DecisionEvidence,
    options: DecisionEvaluationOptions = {},
  ): Promise<GateDecision> {
    if (evidence !== undefined)
      return await this.options.hosted.evaluate(captured, evidence, options);
    const replayed = await this.replayed(captured);
    if (replayed !== null) return FailClosedDecision.create(captured.intentHash, replayed);
    const now = this.clock();
    const bundle = this.options.bundles.current(now);
    if (bundle === null) {
      return await this.unavailable(captured, "EDGE_BUNDLE_UNAVAILABLE", null, options);
    }
    let envelope;
    try {
      envelope = this.options.module.decide(bundle.handle, {
        binding: DecionisGate.binding(captured),
        mode: this.evaluationMode,
        now: new Date(now).toISOString(),
      });
    } catch {
      return await this.unavailable(captured, "EDGE_MODULE_FAULTED", null, options);
    }
    if (!envelope.ok) {
      return await this.unavailable(captured, "EDGE_MODULE_REFUSED", envelope.code, options);
    }
    const parsed = DecideResultSchema.safeParse(envelope.result);
    if (!parsed.success || !EdgeDecisionAuthority.sameBundle(parsed.data, bundle)) {
      return await this.unavailable(captured, "EDGE_RESULT_INVALID", null, options);
    }
    const result = parsed.data;
    const delegated = result.verdict === "ESCALATE" && this.evaluationMode === "ENFORCEMENT";
    const decisionId = EdgeDecisionAuthority.decisionId(captured, result);
    try {
      this.options.record?.({
        event: "EDGE_DECISION",
        mode: this.evaluationMode,
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
        decision_id: decisionId,
        verdict: result.verdict,
        reason_codes: [...result.reason_codes],
        policy_version: result.policy_version,
        bundle_id: result.bundle.bundle_id,
        kid: result.bundle.kid,
        jti: result.bundle.jti,
        evaluation_digest: result.evaluation_digest,
        delegated,
      });
    } catch {
      return FailClosedDecision.create(captured.intentHash, "EDGE_RECORD_UNAVAILABLE");
    }
    if (delegated) return await this.options.hosted.evaluate(captured, undefined, options);
    return this.local(captured, result, decisionId, bundle, now);
  }

  private local(
    captured: CapturedIntent,
    result: DecideResult,
    decisionId: string,
    bundle: LoadedBundle,
    now: number,
  ): GateDecision {
    const dossierId = `edge:${result.evaluation_digest}`;
    let authorization: GateDecision["authorization"] = null;
    if (result.verdict === "ALLOW" && this.evaluationMode === "ENFORCEMENT") {
      // The authorization lives no longer than the intent or the bundle.
      const expiresAtMs = Math.min(Date.parse(captured.intent.expiresAt), bundle.expiresAtMs);
      if (!(expiresAtMs > now)) {
        return FailClosedDecision.create(captured.intentHash, "INTENT_EXPIRED");
      }
      const expiresAt = new Date(expiresAtMs).toISOString();
      const token = this.options.grants.issue({
        intentId: captured.intent.intentId,
        intentHash: captured.intentHash,
        decisionId,
        dossierId,
        expiresAt,
      });
      authorization = { token, expiresAt };
    }
    return immutableGateDecision({
      verdict: result.verdict,
      decisionId,
      dossierId,
      intentHash: captured.intentHash,
      reasonCodes: result.reason_codes,
      authorization,
      failClosed: false,
    });
  }

  private async unavailable(
    captured: CapturedIntent,
    reason: string,
    moduleCode: string | null,
    options: DecisionEvaluationOptions,
  ): Promise<GateDecision> {
    const fallback = this.onUnavailable === "hosted" ? "HOSTED" : "BLOCK";
    try {
      this.options.record?.({
        event: "EDGE_UNAVAILABLE",
        mode: this.evaluationMode,
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
        reason,
        module_code:
          moduleCode !== null && /^[a-z][a-z0-9_]{0,62}$/.test(moduleCode) ? moduleCode : null,
        fallback,
      });
    } catch {
      return FailClosedDecision.create(captured.intentHash, "EDGE_RECORD_UNAVAILABLE");
    }
    if (fallback === "HOSTED")
      return await this.options.hosted.evaluate(captured, undefined, options);
    return FailClosedDecision.create(captured.intentHash, reason);
  }

  /**
   * Why an enforcement decision must not be made: the intent has already
   * been claimed, or the store that would say so cannot be asked. Neither is
   * a decision, so neither is recorded or counted.
   */
  private async replayed(captured: CapturedIntent): Promise<string | null> {
    const store = this.options.replay;
    if (this.evaluationMode !== "ENFORCEMENT" || store?.consumed === undefined) return null;
    try {
      return (await store.consumed(captured.intent.intentId)) ? "INTENT_ALREADY_CONSUMED" : null;
    } catch {
      return "EDGE_REPLAY_STORE_UNAVAILABLE";
    }
  }

  /** The module must have decided on the bundle this host gave it. */
  private static sameBundle(result: DecideResult, bundle: LoadedBundle): boolean {
    return (
      result.bundle.bundle_id === bundle.bundleId &&
      result.bundle.policy_version === bundle.policyVersion &&
      result.bundle.kid === bundle.kid
    );
  }

  /** Unique per intent and evaluation, and derivable from the record that names it. */
  private static decisionId(captured: CapturedIntent, result: DecideResult): string {
    const digest = createHash("sha256")
      .update(`${captured.intentHash}\n${result.evaluation_digest}\n${result.bundle.jti}`, "utf8")
      .digest("hex");
    return `edge:${digest.slice(0, 40)}`;
  }
}
