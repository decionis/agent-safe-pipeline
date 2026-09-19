package com.decionis.verifyingprovider;

/** The part of the attestation the provider reads; the authority's schema has more. */
public record ClaimAttestation(
    String iss,
    String sub,
    String decisionId,
    String intentHash,
    String executionPayloadDigest,
    String executionPayloadCanonicalizationProfile,
    long exp) {}
