import type { VerifiedAuthorization } from "@decionis/agent-safe-pipeline";
import type { DownstreamGrant } from "./DownstreamCredential.js";

/**
 * The grant a dispatch executes under, as a credential binds it into the
 * request: the grant's identity, the decision's, and the authority's
 * attestation of the claim when the authority gave one. One place, so every
 * handler forwards the same three things and none forwards a fourth.
 */
export function grantOf(authorization: VerifiedAuthorization): DownstreamGrant {
  return {
    id: authorization.grantId,
    decisionId: authorization.decisionId,
    ...(authorization.claimAttestation === undefined
      ? {}
      : { claimAttestation: authorization.claimAttestation }),
  };
}
