package com.decionis.verifyingprovider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/** The authority's execution-grant key set, as served: OKP Ed25519 keys by kid. */
public final class Jwks {
  private static final ObjectMapper JSON = new ObjectMapper();

  /** One key: its kid and the Ed25519 public key its x encodes. */
  public record Key(String kid, PublicKey publicKey) {}

  private final List<Key> keys;

  public Jwks(List<Key> keys) {
    this.keys = List.copyOf(keys);
  }

  /** Parses the JWKS document; entries that are not OKP Ed25519 keys are left out. */
  public static Jwks parse(String json) {
    try {
      JsonNode root = JSON.readTree(json);
      List<Key> keys = new ArrayList<>();
      for (JsonNode entry : root.path("keys")) {
        if (!"OKP".equals(entry.path("kty").asText()) || !"Ed25519".equals(entry.path("crv").asText())) {
          continue;
        }
        String kid = entry.path("kid").asText(null);
        String x = entry.path("x").asText(null);
        if (kid == null || x == null) {
          continue;
        }
        keys.add(new Key(kid, publicKeyFromX(Base64.getUrlDecoder().decode(x))));
      }
      return new Jwks(keys);
    } catch (Exception e) {
      throw new IllegalArgumentException("not a JWKS", e);
    }
  }

  public Optional<PublicKey> find(String kid) {
    return keys.stream().filter(key -> key.kid().equals(kid)).map(Key::publicKey).findFirst();
  }

  /**
   * RFC 8032 encodes a point as the little-endian y with the top bit carrying the
   * least significant bit of x; the JDK wants the two apart.
   */
  static PublicKey publicKeyFromX(byte[] encoded) throws Exception {
    if (encoded.length != 32) {
      throw new IllegalArgumentException("an Ed25519 x is 32 bytes");
    }
    byte[] bigEndian = new byte[32];
    for (int index = 0; index < 32; index++) {
      bigEndian[index] = encoded[31 - index];
    }
    boolean xOdd = (bigEndian[0] & 0x80) != 0;
    bigEndian[0] &= 0x7F;
    BigInteger y = new BigInteger(1, bigEndian);
    return KeyFactory.getInstance("Ed25519")
        .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(xOdd, y)));
  }
}
