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
  type LocalAuthorityOptions,
  type LocalClaimAttestationClaims,
  type LocalEffectReceiptCode,
  type LocalEffectReceiptRecord,
  type LocalProviderKey,
  type LocalAuthorityPolicy,
  type LocalAuthorityRequestRecord,
  type LocalGrantRecord,
  type LocalManagedEscalationRecord,
  type LocalRouteOverride,
} from "./LocalAuthority.js";
