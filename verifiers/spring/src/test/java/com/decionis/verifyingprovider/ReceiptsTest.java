package com.decionis.verifyingprovider;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.expectThrows;
import static org.testng.Assert.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/** The receipt vectors (VP-3): this module signs exactly the bytes every implementation agrees on. */
public class ReceiptsTest {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final KeyPair PROVIDER = generate();

  private static KeyPair generate() {
    try {
      return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static Path receiptsDirectory() {
    return VectorsTest.vectorsDirectory().resolveSibling("receipts");
  }

  static ClaimAttestation attestationOf(JsonNode node) {
    JsonNode binding = node.path("binding");
    return new ClaimAttestation(
        node.path("iss").asText(),
        node.path("sub").asText(),
        node.path("decision_id").asText(),
        node.path("dossier_id").asText(),
        binding.path("intent_hash").asText(),
        binding.path("execution_payload_digest").asText(),
        binding.path("execution_payload_canonicalization_profile").asText(),
        node.path("claim_token_digest").asText(),
        node.path("jti").asText(),
        node.path("exp").asDouble());
  }

  static Optional<String> optional(JsonNode node, String field) {
    return node.hasNonNull(field) ? Optional.of(node.path(field).asText()) : Optional.empty();
  }

  static EffectReceipt receiptOf(JsonNode input) {
    JsonNode effect = input.path("effect");
    return new EffectReceipt(
        input.path("kid").asText(),
        input.path("issuer").asText(),
        input.path("audience").asText(),
        attestationOf(input.path("attestation")),
        optional(input, "idempotency_key"),
        new EffectReceipt.Effect(
            EffectReceipt.Status.valueOf(effect.path("status").asText()),
            optional(effect, "reference"),
            optional(effect, "digest"),
            effect.path("effected_at").asText()),
        input.path("iat").asLong(),
        input.path("jti").asText());
  }

  @DataProvider(name = "receipts")
  public Object[][] receipts() throws IOException {
    List<Path> files;
    try (Stream<Path> listing = Files.list(receiptsDirectory())) {
      files = listing.filter(path -> path.toString().endsWith(".json")).sorted().toList();
    }
    assertTrue(files.size() >= 4, "found " + files.size() + " receipt vectors");
    return files.stream().map(file -> new Object[] {file}).toArray(Object[][]::new);
  }

  @Test(dataProvider = "receipts")
  public void everyReceiptVectorIsSignedOverTheBytesItNames(Path file) throws Exception {
    JsonNode vector = JSON.readTree(Files.readString(file));
    String name = vector.path("vector").asText();
    assertEquals(vector.path("level").asText(), "VP-3", name);
    EffectReceipt receipt = receiptOf(vector.path("input"));
    JsonNode expect = vector.path("expect");
    // Jackson tells an int node from a long node; the canonical text does not.
    assertEquals(canonical(receipt.claims()), canonical(expect.path("claims")), name);
    String signingInput = receipt.signingInput();
    assertEquals(signingInput, expect.path("signing_input").asText(), name);
    String token = receipt.sign(PROVIDER.getPrivate());
    String[] parts = token.split("\\.", -1);
    assertEquals(parts.length, 3, name);
    assertEquals(parts[0] + "." + parts[1], signingInput, name);
    Base64.Decoder base64url = Base64.getUrlDecoder();
    assertEquals(canonical(JSON.readTree(base64url.decode(parts[0]))),
        canonical(expect.path("protected_header")), name);
    assertTrue(verifies(PROVIDER.getPublic(), signingInput, parts[2]), name + ": own signature");
    // The vector's own token verifies under the public half it carries.
    String[] vectorParts = expect.path("token").asText().split("\\.", -1);
    assertEquals(vectorParts[0] + "." + vectorParts[1], signingInput, name);
    byte[] x = base64url.decode(expect.path("provider_jwk").path("x").asText());
    assertTrue(verifies(ed25519(x), vectorParts[0] + "." + vectorParts[1], vectorParts[2]),
        name + ": the vector's signature");
  }

  @Test
  public void aReceiptIsNotBuiltFromWhatItCannotStandBehind() {
    ClaimAttestation attestation =
        new ClaimAttestation("i", "g", "d", "s", "h", "p", "RFC8785/JCS", "c", "a", 1);
    EffectReceipt good = new EffectReceipt("k", "i", "a", attestation, Optional.empty(),
        new EffectReceipt.Effect(EffectReceipt.Status.EFFECTED, Optional.empty(), Optional.empty(),
            "2026-09-19T12:00:01Z"),
        1_789_819_202L, "r");
    good.sign(PROVIDER.getPrivate());
    record Case(String code, EffectReceipt receipt) {}
    for (Case c : List.of(
        new Case("EFFECT_DIGEST_MALFORMED", with(good, new EffectReceipt.Effect(
            EffectReceipt.Status.EFFECTED, Optional.empty(), Optional.of("sha256:zz"),
            good.effect().effectedAt()))),
        new Case("EFFECTED_AT_MALFORMED", with(good, new EffectReceipt.Effect(
            EffectReceipt.Status.EFFECTED, Optional.empty(), Optional.empty(), "yesterday"))),
        new Case("ISSUED_AT_MALFORMED", new EffectReceipt(good.kid(), good.issuer(), good.audience(),
            attestation, Optional.empty(), good.effect(), -1, good.jti())),
        new Case("KID_EMPTY", new EffectReceipt("", good.issuer(), good.audience(), attestation,
            Optional.empty(), good.effect(), good.issuedAt(), good.jti())),
        new Case("ISSUER_EMPTY", new EffectReceipt(good.kid(), "", good.audience(), attestation,
            Optional.empty(), good.effect(), good.issuedAt(), good.jti())),
        new Case("AUDIENCE_EMPTY", new EffectReceipt(good.kid(), good.issuer(), "", attestation,
            Optional.empty(), good.effect(), good.issuedAt(), good.jti())),
        new Case("JTI_EMPTY", new EffectReceipt(good.kid(), good.issuer(), good.audience(),
            attestation, Optional.empty(), good.effect(), good.issuedAt(), "")))) {
      EffectReceipt.ReceiptException refused = expectThrows(EffectReceipt.ReceiptException.class,
          () -> c.receipt().sign(PROVIDER.getPrivate()));
      assertEquals(refused.getMessage(), c.code());
    }
  }

  private static EffectReceipt with(EffectReceipt receipt, EffectReceipt.Effect effect) {
    return new EffectReceipt(receipt.kid(), receipt.issuer(), receipt.audience(),
        receipt.attestation(), receipt.idempotencyKey(), effect, receipt.issuedAt(), receipt.jti());
  }

  private static String canonical(JsonNode node) throws IOException {
    return new org.erdtman.jcs.JsonCanonicalizer(JSON.writeValueAsString(node)).getEncodedString();
  }

  private static boolean verifies(PublicKey key, String signingInput, String signature)
      throws Exception {
    Signature verifier = Signature.getInstance("Ed25519");
    verifier.initVerify(key);
    verifier.update(signingInput.getBytes(StandardCharsets.US_ASCII));
    return verifier.verify(Base64.getUrlDecoder().decode(signature));
  }

  /** An Ed25519 public key from its 32 raw bytes: the SPKI prefix, then the point. */
  private static PublicKey ed25519(byte[] x) throws Exception {
    byte[] prefix = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
    byte[] spki = new byte[prefix.length + x.length];
    System.arraycopy(prefix, 0, spki, 0, prefix.length);
    System.arraycopy(x, 0, spki, prefix.length, x.length);
    return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
  }
}
