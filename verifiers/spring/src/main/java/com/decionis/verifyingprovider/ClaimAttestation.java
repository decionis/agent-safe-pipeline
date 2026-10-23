package com.decionis.verifyingprovider;

import java.util.Optional;

/**
 * The part of the attestation the provider reads; the authority's schema has more. The dossier,
 * the claim-token digest and the attestation's own id are what a receipt ({@link EffectReceipt},
 * VP-3) is built from. {@code expectedStateVersion} is the target's version the grant was decided
 * against, when the attestation names one: the precondition of the write, compared as a strong
 * {@code If-Match} is.
 */
public record ClaimAttestation(
    String iss,
    String sub,
    String decisionId,
    String dossierId,
    String intentHash,
    String executionPayloadDigest,
    String executionPayloadCanonicalizationProfile,
    String claimTokenDigest,
    String jti,
    double exp,
    Optional<String> expectedStateVersion) {

  /** An attestation that names no version of the target. */
  public ClaimAttestation(
      String iss,
      String sub,
      String decisionId,
      String dossierId,
      String intentHash,
      String executionPayloadDigest,
      String executionPayloadCanonicalizationProfile,
      String claimTokenDigest,
      String jti,
      double exp) {
    this(iss, sub, decisionId, dossierId, intentHash, executionPayloadDigest,
        executionPayloadCanonicalizationProfile, claimTokenDigest, jti, exp, Optional.empty());
  }
}
