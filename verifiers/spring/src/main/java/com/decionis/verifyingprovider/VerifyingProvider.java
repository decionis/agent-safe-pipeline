package com.decionis.verifyingprovider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * An independent implementation of the Verifying Provider Profile
 * (docs/authority/verifying-provider.md in the agent-safe-pipeline repository),
 * VP-1 and VP-2, written against the profile's text and held to its vectors.
 * It shares no code with the executor; that is the point of a second
 * implementation.
 */
public final class VerifyingProvider {
  public static final String ATTESTATION_TYPE = "decionis-claim-attestation+jwt";
  public static final String JCS_PROFILE = "RFC8785/JCS";
  private static final String LABEL = "agentsafe";

  static final List<String> BASE_COMPONENTS =
      List.of("@method", "@path", "content-digest", "idempotency-key", "x-agent-safe-intent-hash");
  static final List<String> GRANT_COMPONENTS =
      List.of("x-agent-safe-grant-id", "x-agent-safe-decision-id", "x-agent-safe-claim-attestation");
  static final List<String> KNOWN_COMPONENTS;

  static {
    List<String> known = new ArrayList<>(BASE_COMPONENTS);
    known.addAll(GRANT_COMPONENTS);
    KNOWN_COMPONENTS = List.copyOf(known);
  }

  private static final Pattern CREATED = Pattern.compile(";created=(\\d{1,12})(?:;|$)");
  private static final Pattern KEY_ID = Pattern.compile(";keyid=\"([^\"]*)\"(?:;|$)");
  private static final Pattern ALG = Pattern.compile(";alg=\"([a-z0-9-]+)\"(?:;|$)");
  private static final Pattern SIGNATURE = Pattern.compile("^agentsafe=:(.*):$");
  private static final ObjectMapper JSON = new ObjectMapper();

  private final ProviderOptions options;

  public VerifyingProvider(ProviderOptions options) {
    this.options = options;
  }

  /** The RFC 9530 value the executor sends for a body, the empty body included. */
  public static String contentDigest(byte[] body) {
    try {
      byte[] sum = MessageDigest.getInstance("SHA-256").digest(body == null ? new byte[0] : body);
      return "sha-256=:" + Base64.getEncoder().encodeToString(sum) + ":";
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** The whole procedure for one received request. */
  public Verdict verify(ProviderRequest request) {
    long nowSeconds = options.clock().instant().getEpochSecond();
    if (!signatureHolds(request, nowSeconds)) {
      return Verdict.refuse(Verdict.SIGNATURE_INVALID_OR_INCOMPLETE);
    }
    if (!options.effects()) {
      return new Verdict(true, null, null);
    }
    ClaimAttestation attestation;
    try {
      attestation = attestationOf(request.headers().get("x-agent-safe-claim-attestation"));
    } catch (Exception e) {
      return Verdict.refuse(Verdict.ATTESTATION_INVALID);
    }
    try {
      described(attestation, request, nowSeconds);
    } catch (Exception e) {
      return Verdict.refuse(Verdict.ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST);
    }
    // The record is kept to the end of the second `exp` falls in, never shorter than `exp`.
    Instant expiresAt = Instant.ofEpochSecond((long) Math.ceil(attestation.exp()));
    if (!options.replay().record(attestation.sub(), expiresAt)) {
      return Verdict.refuse(Verdict.GRANT_REPLAYED);
    }
    return new Verdict(true, null, attestation);
  }

  // Steps 0 to 5.
  private boolean signatureHolds(ProviderRequest request, long nowSeconds) {
    Map<String, String> headers = request.headers();
    String input = headers.get("signature-input");
    if (input == null || !input.startsWith(LABEL + "=")) {
      return false;
    }
    String parameters = input.substring(LABEL.length() + 1);
    Matcher encoded = SIGNATURE.matcher(headers.getOrDefault("signature", ""));
    if (!encoded.matches()) {
      return false;
    }
    if (!contentDigest(request.body()).equals(headers.get("content-digest"))) {
      return false;
    }
    List<String> covered = coveredComponents(parameters);
    if (covered == null) {
      return false;
    }
    for (String component : options.effects() ? KNOWN_COMPONENTS : BASE_COMPONENTS) {
      if (!covered.contains(component)) {
        return false;
      }
    }
    String createdText = group(CREATED, parameters);
    if (createdText == null) {
      return false;
    }
    long created = Long.parseLong(createdText);
    long window = options.clockWindow().getSeconds();
    if (created < nowSeconds - window || created > nowSeconds + window) {
      return false;
    }
    String keyId = group(KEY_ID, parameters);
    String algorithm = group(ALG, parameters);
    Optional<ExecutorKey> key = options.executorKeys().stream()
        .filter(candidate -> candidate.keyId().equals(keyId) && candidate.algorithm().equals(algorithm))
        .findFirst();
    if (key.isEmpty()) {
      return false;
    }
    byte[] base = signatureBase(request, covered, parameters);
    if (base == null) {
      return false;
    }
    byte[] signature;
    try {
      signature = Base64.getDecoder().decode(encoded.group(1));
    } catch (IllegalArgumentException e) {
      return false;
    }
    try {
      switch (key.get().algorithm()) {
        case "ed25519" -> {
          Signature verifier = Signature.getInstance("Ed25519");
          verifier.initVerify(key.get().publicKey());
          verifier.update(base);
          return verifier.verify(signature);
        }
        case "hmac-sha256" -> {
          Mac mac = Mac.getInstance("HmacSHA256");
          mac.init(new SecretKeySpec(key.get().secret(), "HmacSHA256"));
          return MessageDigest.isEqual(mac.doFinal(base), signature);
        }
        default -> {
          return false;
        }
      }
    } catch (Exception e) {
      return false;
    }
  }

  /** The covered components a signature-input names, or null when the list is not one, names an unknown one, or one twice. */
  static List<String> coveredComponents(String parameters) {
    if (!parameters.startsWith("(")) {
      return null;
    }
    int end = parameters.indexOf(')');
    if (end < 0) {
      return null;
    }
    String inner = parameters.substring(1, end);
    if (inner.isEmpty()) {
      return List.of();
    }
    List<String> names = new ArrayList<>();
    Set<String> seen = new HashSet<>();
    for (String quoted : inner.split(" ", -1)) {
      if (quoted.length() < 3 || quoted.charAt(0) != '"' || quoted.charAt(quoted.length() - 1) != '"') {
        return null;
      }
      String name = quoted.substring(1, quoted.length() - 1);
      if (!KNOWN_COMPONENTS.contains(name) || !seen.add(name)) {
        return null;
      }
      names.add(name);
    }
    return names;
  }

  /** The base, exactly as both sides build it. */
  static byte[] signatureBase(ProviderRequest request, List<String> covered, String parameters) {
    List<String> lines = new ArrayList<>();
    for (String component : covered) {
      String value;
      switch (component) {
        case "@method" -> value = request.method().toUpperCase(java.util.Locale.ROOT);
        case "@path" -> value = request.path();
        case "content-digest" -> value = contentDigest(request.body());
        default -> {
          value = request.headers().get(component);
          if (value == null) {
            return null;
          }
        }
      }
      lines.add("\"" + component + "\": " + value);
    }
    lines.add("\"@signature-params\": " + parameters);
    return String.join("\n", lines).getBytes(StandardCharsets.UTF_8);
  }

  // Step 6: the attestation by form, key, signature, issuer and the shape of its claims; the
  // claims when it is the authority's.
  private ClaimAttestation attestationOf(String compact) throws Exception {
    String[] parts = compact == null ? new String[0] : compact.split("\\.", -1);
    if (parts.length != 3) {
      throw new IllegalArgumentException("form");
    }
    Base64.Decoder base64url = Base64.getUrlDecoder();
    JsonNode header = JSON.readTree(base64url.decode(parts[0]));
    if (!"EdDSA".equals(header.path("alg").asText(null))
        || !ATTESTATION_TYPE.equals(header.path("typ").asText(null))) {
      throw new IllegalArgumentException("header");
    }
    PublicKey key = options.authorityJwks().find(header.path("kid").asText(""))
        .orElseThrow(() -> new IllegalArgumentException("kid"));
    Signature verifier = Signature.getInstance("Ed25519");
    verifier.initVerify(key);
    verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
    if (!verifier.verify(base64url.decode(parts[2]))) {
      throw new IllegalArgumentException("signature");
    }
    JsonNode claims = JSON.readTree(base64url.decode(parts[1]));
    // The claims a provider compares, and the ones a receipt is built from, must be there in the
    // right type: an attestation without them is not one.
    JsonNode binding = claims.path("binding");
    JsonNode exp = claims.path("exp");
    if (!exp.isNumber()) {
      throw new IllegalArgumentException("exp");
    }
    ClaimAttestation attestation = new ClaimAttestation(
        text(claims, "iss"),
        text(claims, "sub"),
        text(claims, "decision_id"),
        text(claims, "dossier_id"),
        text(binding, "intent_hash"),
        text(binding, "execution_payload_digest"),
        text(binding, "execution_payload_canonicalization_profile"),
        text(claims, "claim_token_digest"),
        text(claims, "jti"),
        exp.asDouble());
    if (!options.authorityIssuer().equals(attestation.iss())) {
      throw new IllegalArgumentException("issuer");
    }
    return attestation;
  }

  // Step 7: whether the attestation describes this request.
  private static void described(ClaimAttestation attestation, ProviderRequest request, long nowSeconds)
      throws Exception {
    if (request.body() == null) {
      throw new IllegalArgumentException("no body");
    }
    String digest = CanonicalDigest.of(request.body());
    Map<String, String> headers = request.headers();
    if (!attestation.sub().equals(headers.get("x-agent-safe-grant-id"))
        || !attestation.decisionId().equals(headers.get("x-agent-safe-decision-id"))
        || !attestation.intentHash().equals(headers.get("x-agent-safe-intent-hash"))
        || !JCS_PROFILE.equals(attestation.executionPayloadCanonicalizationProfile())
        || !attestation.executionPayloadDigest().equals(digest)
        || !(attestation.exp() > nowSeconds)) {
      throw new IllegalArgumentException("describes another request");
    }
  }

  private static String text(JsonNode node, String field) {
    JsonNode value = node.path(field);
    if (!value.isTextual()) {
      throw new IllegalArgumentException(field);
    }
    return value.textValue();
  }

  private static String group(Pattern pattern, String text) {
    Matcher matcher = pattern.matcher(text);
    return matcher.find() ? matcher.group(1) : null;
  }
}
