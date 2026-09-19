package com.decionis.verifyingprovider;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * A key the provider issued to, or registered for, the executor, by the keyid a
 * signature names. Exactly one of {@code publicKey} (for {@code ed25519}) and
 * {@code secret} (for {@code hmac-sha256}) is set.
 */
public record ExecutorKey(String keyId, String algorithm, PublicKey publicKey, byte[] secret) {

  public ExecutorKey {
    Objects.requireNonNull(keyId, "keyId");
    Objects.requireNonNull(algorithm, "algorithm");
  }

  /** An Ed25519 key from its SPKI PEM, as the vectors and a key file carry it. */
  public static ExecutorKey ed25519(String keyId, String publicKeyPem) {
    String base64 = publicKeyPem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replaceAll("\\s", "");
    try {
      PublicKey key = KeyFactory.getInstance("Ed25519")
          .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64)));
      return new ExecutorKey(keyId, "ed25519", key, null);
    } catch (Exception e) {
      throw new IllegalArgumentException(keyId + ": not an Ed25519 public key", e);
    }
  }

  /** A shared HMAC secret, as UTF-8 text. */
  public static ExecutorKey hmac(String keyId, String sharedMaterialUtf8) {
    return new ExecutorKey(keyId, "hmac-sha256", null,
        sharedMaterialUtf8.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }
}
