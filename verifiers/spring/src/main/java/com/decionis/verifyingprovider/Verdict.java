package com.decionis.verifyingprovider;

/**
 * The outcome of the procedure for one request. {@code attestation} is set on
 * an accepted dispatch, and null for a read a non-effecting provider verified
 * at VP-1 alone; a refusal carries the code the response body names. The one
 * refusal that carries the attestation too is {@link #TARGET_STATE_CHANGED}:
 * the provider's own refusal of a genuine, now spent, attestation, which a
 * provider at VP-3 signs as a receipt built from those claims.
 */
public record Verdict(boolean accepted, String reasonCode, ClaimAttestation attestation) {

  public static final String SIGNATURE_INVALID_OR_INCOMPLETE = "SIGNATURE_INVALID_OR_INCOMPLETE";
  public static final String ATTESTATION_INVALID = "ATTESTATION_INVALID";
  public static final String ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST =
      "ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST";
  public static final String GRANT_REPLAYED = "GRANT_REPLAYED";
  public static final String TARGET_STATE_CHANGED = "TARGET_STATE_CHANGED";

  static Verdict refuse(String reasonCode) {
    return new Verdict(false, reasonCode, null);
  }

  /** The refusal body the profile names; the status is the provider's, 409 in the references. */
  public String refusalBody() {
    return "{\"status\":\"REJECTED\",\"reason_code\":\"" + reasonCode + "\"}";
  }
}
