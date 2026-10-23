/**
 * Local testing entry: loopback doubles for Decionis and Presence plus the
 * development fixture primitives. Import from
 * `@decionis/agent-safe-pipeline/testing`. Nothing here is production
 * authority; the fixture authority refuses to construct under
 * `NODE_ENV=production`, and the local servers bind only to loopback.
 */
export {
  FixtureAuthorizationVerifier,
  FixtureDecisionAuthority,
  createFixtureAuthorityPair,
  type FixtureAuthorityPair,
  type FixtureCommitRecord,
  type FixtureVerdictResolver,
  type UnsafeFixtureAuthorityOptions,
} from "../decision/FixtureDecisionAuthority.js";
export { InMemoryReplayStore } from "../execution/ReplayStore.js";
export {
  LocalPresence,
  LOCAL_PRESENCE_API_KEY,
  readBody,
  type LocalAuthenticator,
  type LocalCeremonyResponse,
  type LocalPresenceOptions,
  type LocalPresenceRequestRecord,
  type LocalReceipt,
  type LocalReceiptBinding,
  type LocalReceiptVerification,
  type LocalVerificationRecord,
  type LocalVerificationStatus,
} from "./LocalPresence.js";
export {
  AUTONOMOUS_LIMIT_MINOR,
  CLAIM_ATTESTATION_TYPE,
  EFFECT_RECEIPT_TYPE,
  HUMAN_LIMIT_MINOR,
  LocalAuthority,
  LOCAL_AUTHORITY_API_KEY,
  LOCAL_AUTHORITY_ISSUER,
  LOCAL_AUTHORITY_JWKS_PATH,
  hashBinding,
  stableStringify,
  type LocalAllowanceDraw,
  type LocalAllowanceUsage,
  type LocalAuthorityOptions,
  type LocalClaimAttestationClaims,
  type LocalEffectReceiptCode,
  type LocalEffectReceiptRecord,
  type LocalProviderKey,
  PROVIDER_KEY_PURPOSES,
  type LocalAuthorityPolicy,
  type LocalAuthorityPolicyInput,
  type LocalProviderKeyPurpose,
  type LocalAuthorityRequestRecord,
  type LocalGrantRecord,
  type LocalManagedEscalationRecord,
  type LocalMaterialSignal,
  type LocalRouteOverride,
} from "./LocalAuthority.js";
export { LocalPlans } from "./LocalPlans.js";
export {
  LocalAssumptionBreaches,
  type LocalAssumptionBreach,
  type LocalAssumptionBreachCitation,
  type LocalAssumptionBreachScope,
  type LocalAssumptionBreachTrigger,
} from "./LocalAssumptionBreaches.js";
export {
  SIGNED_SIGNAL_MAX_LIFETIME_SECONDS,
  SIGNED_SIGNAL_REFUSAL_CODES,
  SIGNED_SIGNAL_TYPE,
  mintSignedSignal,
  signedSignalFacts,
  verifySignedSignal,
  verifySignedSignals,
  type SignedSignalClaims,
  type SignedSignalCoverage,
  type SignedSignalFacts,
  type SignedSignalIntentView,
  type SignedSignalKey,
  type SignedSignalRefusalCode,
  type SignedSignalVerification,
  type VerifiedSignedSignal,
} from "./SignedSignals.js";
