/**
 * The profile's reason codes this executor can produce on its own, mirrored
 * from the `reason-codes` registry with the category the registry gives
 * them. The authority owns the evaluation and authority-set codes; these are
 * the ones an execution boundary observes and reports, so only they are
 * mirrored. A test asserts each one exists in the registry under the
 * category claimed here, so a drift in the profile fails rather than passing
 * quietly.
 */
export const EXECUTION_REASON_CODES = [
  "INTENT_DIGEST_MISMATCH",
  "GRANT_EXPIRED",
  "GRANT_ALREADY_CONSUMED",
  "AUTHORIZATION_INVALID",
  "CLAIM_REJECTED",
  "CLAIM_LEASE_EXPIRED",
  "POLICY_STATE_CHANGED",
  "AMOUNT_SCALE_INVALID",
] as const;

export const EFFECT_REASON_CODES = [
  "EFFECT_MISMATCH",
  "INDETERMINATE_OUTCOME",
  "RECONCILIATION_REQUIRED",
  "EVIDENCE_INCOMPLETE",
] as const;

export type ExecutionReasonCode = (typeof EXECUTION_REASON_CODES)[number];
export type EffectReasonCode = (typeof EFFECT_REASON_CODES)[number];
export type BankingReasonCode = ExecutionReasonCode | EffectReasonCode;

/** The category each mirrored code carries in the profile's registry. */
export const REASON_CODE_CATEGORIES: ReadonlyMap<BankingReasonCode, "execution" | "effect"> =
  new Map([
    ...EXECUTION_REASON_CODES.map(
      (code) => [code, "execution"] as const satisfies readonly [BankingReasonCode, "execution"],
    ),
    ...EFFECT_REASON_CODES.map(
      (code) => [code, "effect"] as const satisfies readonly [BankingReasonCode, "effect"],
    ),
  ]);

/** Whether a code is one this executor may put on an effect record. */
export function isBankingReasonCode(code: string): code is BankingReasonCode {
  return REASON_CODE_CATEGORIES.has(code as BankingReasonCode);
}
