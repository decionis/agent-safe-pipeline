package com.decionis.verifyingprovider;

/**
 * The part of the attestation the provider reads; the authority's schema has more. The dossier,
 * the claim-token digest and the attestation's own id are what a receipt ({@link EffectReceipt},
 * VP-3) is built from.
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
    double exp) {}
