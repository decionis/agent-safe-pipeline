package com.decionis.verifyingprovider;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Map;
import org.erdtman.jcs.JsonCanonicalizer;

/**
 * "sha256:" and the hex SHA-256 over the RFC 8785 canonical form of a JSON
 * object, or a refusal when the text is not one that is I-JSON: not valid
 * UTF-8, not an object, a name repeated within one object, or a lone
 * surrogate, each of which another parser would read differently.
 */
public final class CanonicalDigest {
  private static final ObjectMapper STRICT =
      new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

  private CanonicalDigest() {}

  /** Thrown when the body has no canonical form a provider may digest. */
  public static final class NotIJson extends Exception {
    NotIJson(String message, Throwable cause) {
      super(message, cause);
    }

    NotIJson(String message) {
      super(message);
    }
  }

  public static String of(byte[] body) throws NotIJson {
    String text;
    try {
      text = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(body)).toString();
    } catch (CharacterCodingException e) {
      throw new NotIJson("not UTF-8", e);
    }
    JsonNode tree;
    try {
      tree = STRICT.readTree(text);
    } catch (Exception e) {
      throw new NotIJson("not JSON, or a repeated name", e);
    }
    if (tree == null || !tree.isObject()) {
      throw new NotIJson("not a JSON object");
    }
    if (hasLoneSurrogate(tree)) {
      throw new NotIJson("lone surrogate");
    }
    try {
      byte[] canonical = new JsonCanonicalizer(text).getEncodedUTF8();
      byte[] sum = MessageDigest.getInstance("SHA-256").digest(canonical);
      return "sha256:" + HexFormat.of().formatHex(sum);
    } catch (Exception e) {
      throw new NotIJson("no canonical form", e);
    }
  }

  /** A string with a surrogate that is not half of a pair, in a name or a value. */
  static boolean hasLoneSurrogate(JsonNode node) {
    if (node.isTextual()) {
      return !wellFormed(node.textValue());
    }
    if (node.isObject()) {
      for (Iterator<Map.Entry<String, JsonNode>> fields = node.fields(); fields.hasNext(); ) {
        Map.Entry<String, JsonNode> field = fields.next();
        if (!wellFormed(field.getKey()) || hasLoneSurrogate(field.getValue())) {
          return true;
        }
      }
      return false;
    }
    if (node.isArray()) {
      for (JsonNode element : node) {
        if (hasLoneSurrogate(element)) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean wellFormed(String text) {
    for (int index = 0; index < text.length(); index++) {
      char unit = text.charAt(index);
      if (Character.isHighSurrogate(unit)) {
        if (index + 1 >= text.length() || !Character.isLowSurrogate(text.charAt(index + 1))) {
          return false;
        }
        index++;
      } else if (Character.isLowSurrogate(unit)) {
        return false;
      }
    }
    return true;
  }
}
