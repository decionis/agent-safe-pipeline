package com.decionis.verifyingprovider;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Pattern;
import org.erdtman.jcs.JsonCanonicalizer;

/**
 * The effect receipt: the provider's half of the evidence (the Verifying Provider Profile, VP-3).
 *
 * <p>The attestation let this provider refuse what the authority never claimed. The receipt closes
 * the other direction: after effecting, or refusing, the claimed request, the provider signs a
 * compact JWS under its own key naming the grant it acted under, the claim it answered and what
 * it did, and returns it in {@link #HEADER}. The executor forwards it unread at finalization; the
 * authority verifies it against the public key the organisation registered for this provider and
 * records it with the commit evidence.
 *
 * <p>Every field the receipt binds comes from the attestation the provider has already verified:
 * {@code sub} is the grant, {@code decision_id} and {@code dossier_id} are the decision's, and
 * {@code claim_token_digest} is copied from the attestation of this very claim. The header and
 * the payload are serialised in RFC 8785 canonical form, so every implementation of the profile
 * signs the same bytes for the same receipt, and the conformance vectors say so.
 *
 * @param kid the {@code kid} the organisation registered the key under at the authority
 * @param issuer the {@code iss} registered with the key
 * @param audience the authority the receipt is for: its issuer, {@code https://decionis.com} for
 *     the hosted one
 * @param attestation the claims of the attestation this provider verified, as {@link
 *     VerifyingProvider#verify} returned them
 * @param idempotencyKey the idempotency key of the request effected, when the provider records it
 * @param effect what the provider did
 * @param issuedAt {@code iat}, as an epoch second
 * @param jti unique per receipt
 */
public record EffectReceipt(
    String kid,
    String issuer,
    String audience,
    ClaimAttestation attestation,
    Optional<String> idempotencyKey,
    Effect effect,
    long issuedAt,
    String jti) {

  /** The protected header {@code typ} of an effect receipt. */
  public static final String TYPE = "decionis-effect-receipt+jwt";

  /** The response header the receipt travels in. */
  public static final String HEADER = "x-agent-safe-effect-receipt";

  private static final ObjectMapper JSON = new ObjectMapper();
  private static final Pattern SHA256 = Pattern.compile("^sha256:[0-9a-f]{64}$");

  /** What the provider did with the claimed request. A signed refusal is evidence too. */
  public enum Status {
    EFFECTED,
    REFUSED,
    INDETERMINATE
  }

  /**
   * The effect the receipt reports.
   *
   * @param status what the provider did
   * @param reference the provider's own reference for the effect: a ledger entry, an order id
   * @param digest the digest of the effect in the grant's terms ({@code expected_effect_digest});
   *     equality is what confirms the effect at the authority
   * @param effectedAt when the effect took place, RFC 3339
   */
  public record Effect(
      Status status, Optional<String> reference, Optional<String> digest, String effectedAt) {}

  /** Why a receipt could not be built; a provider never signs one it could not stand behind. */
  public static final class ReceiptException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    ReceiptException(String code) {
      super(code);
    }
  }

  /** The payload of the receipt, before it is signed; what the authority reads. */
  public ObjectNode claims() {
    if (effect.digest().isPresent() && !SHA256.matcher(effect.digest().get()).matches()) {
      throw new ReceiptException("EFFECT_DIGEST_MALFORMED");
    }
    try {
      OffsetDateTime.parse(effect.effectedAt());
    } catch (DateTimeParseException e) {
      throw new ReceiptException("EFFECTED_AT_MALFORMED");
    }
    if (issuedAt < 0) {
      throw new ReceiptException("ISSUED_AT_MALFORMED");
    }
    if (attestation == null) {
      throw new ReceiptException("ATTESTATION_MISSING");
    }
    require(kid, "KID_EMPTY");
    require(issuer, "ISSUER_EMPTY");
    require(audience, "AUDIENCE_EMPTY");
    require(jti, "JTI_EMPTY");
    ObjectNode effectNode = JSON.createObjectNode();
    effectNode.put("status", effect.status().name());
    effect.reference().ifPresent(reference -> effectNode.put("reference", reference));
    effect.digest().ifPresent(digest -> effectNode.put("digest", digest));
    effectNode.put("effected_at", effect.effectedAt());
    ObjectNode claims = JSON.createObjectNode();
    claims.put("iss", issuer);
    claims.put("aud", audience);
    claims.put("sub", attestation.sub());
    claims.put("decision_id", attestation.decisionId());
    claims.put("dossier_id", attestation.dossierId());
    claims.put("claim_token_digest", attestation.claimTokenDigest());
    claims.put("attestation_jti", attestation.jti());
    claims.put("intent_hash", attestation.intentHash());
    idempotencyKey.ifPresent(key -> claims.put("idempotency_key", key));
    claims.set("effect", effectNode);
    claims.put("iat", issuedAt);
    claims.put("jti", jti);
    return claims;
  }

  /** The {@code header.payload} the signature covers: both segments RFC 8785 canonical, base64url. */
  public String signingInput() {
    ObjectNode header = JSON.createObjectNode();
    header.put("alg", "EdDSA");
    header.put("kid", kid);
    header.put("typ", TYPE);
    return segment(header) + "." + segment(claims());
  }

  /**
   * The receipt: a compact EdDSA JWS the provider returns in {@link #HEADER}.
   *
   * @param key the provider's Ed25519 private key, which never leaves the provider
   * @return the compact JWS
   */
  public String sign(PrivateKey key) {
    if (!"Ed25519".equalsIgnoreCase(key.getAlgorithm()) && !"EdDSA".equalsIgnoreCase(key.getAlgorithm())) {
      throw new ReceiptException("KEY_NOT_ED25519");
    }
    String signingInput = signingInput();
    try {
      Signature signer = Signature.getInstance("Ed25519");
      signer.initSign(key);
      signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
      return signingInput + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
    } catch (java.security.GeneralSecurityException e) {
      throw new ReceiptException("KEY_NOT_ED25519");
    }
  }

  private static String segment(ObjectNode value) {
    try {
      byte[] canonical = new JsonCanonicalizer(JSON.writeValueAsString(value)).getEncodedUTF8();
      return Base64.getUrlEncoder().withoutPadding().encodeToString(canonical);
    } catch (java.io.IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void require(String value, String code) {
    if (value == null || value.isEmpty()) {
      throw new ReceiptException(code);
    }
  }
}
