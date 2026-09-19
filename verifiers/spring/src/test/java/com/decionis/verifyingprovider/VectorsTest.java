package com.decionis.verifyingprovider;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class VectorsTest {
  private static final ObjectMapper JSON = new ObjectMapper();

  /** The vectors live at the repository root; walk up to them from this module. */
  static Path vectorsDirectory() {
    Path directory = Path.of("").toAbsolutePath();
    while (directory != null) {
      Path candidate = directory.resolve("conformance/provider/vectors");
      if (Files.isDirectory(candidate)) {
        return candidate;
      }
      directory = directory.getParent();
    }
    throw new IllegalStateException("conformance/provider/vectors not found above this module");
  }

  static ExecutorKey executorKey(JsonNode key) {
    return switch (key.path("alg").asText()) {
      case "ed25519" -> ExecutorKey.ed25519(key.path("keyid").asText(), key.path("public_pem").asText());
      case "hmac-sha256" ->
          ExecutorKey.hmac(key.path("keyid").asText(), key.path("shared_material_utf8").asText());
      default -> throw new IllegalArgumentException(key.path("alg").asText());
    };
  }

  @DataProvider(name = "vectors")
  public Object[][] vectors() throws IOException {
    List<Path> files;
    try (Stream<Path> listing = Files.list(vectorsDirectory())) {
      files = listing.filter(path -> path.toString().endsWith(".json")).sorted().toList();
    }
    assertTrue(files.size() >= 20, "found " + files.size() + " vectors");
    return files.stream().map(file -> new Object[] {file}).toArray(Object[][]::new);
  }

  @Test(dataProvider = "vectors")
  public void everyVectorReachesTheOutcomesItNames(Path file) throws IOException {
    JsonNode vector = JSON.readTree(Files.readString(file));
    assertEquals(vector.path("profile").asText(), "agent-safe.verifying-provider/1");
    assertEquals(vector.path("version").asText(), "0.1");
    JsonNode provider = vector.path("provider");
    Instant now = Instant.parse(provider.path("now").asText());
    Clock clock = Clock.fixed(now, ZoneOffset.UTC);
    List<ExecutorKey> keys = new ArrayList<>();
    for (JsonNode key : vector.path("executor_keys")) {
      keys.add(executorKey(key));
    }
    ProviderOptions options = new ProviderOptions(
        provider.path("effects").asBoolean(),
        keys,
        Jwks.parse(vector.path("authority_jwks").toString()),
        provider.path("authority_issuer").asText(),
        Duration.ofSeconds(provider.path("clock_window_seconds").asLong()),
        new MemoryReplayStore(clock),
        clock);
    VerifyingProvider verifying = new VerifyingProvider(options);
    int index = 0;
    for (JsonNode request : vector.path("requests")) {
      Map<String, String> headers = new HashMap<>();
      request.path("headers").fields()
          .forEachRemaining(entry -> headers.put(entry.getKey(), entry.getValue().asText()));
      byte[] body = request.path("body").isNull()
          ? null
          : request.path("body").asText().getBytes(StandardCharsets.UTF_8);
      Verdict verdict = verifying.verify(new ProviderRequest(
          request.path("method").asText(), request.path("path").asText(), body, headers));
      JsonNode expect = request.path("expect");
      String where = file.getFileName() + " request " + index;
      if ("ACCEPT".equals(expect.path("outcome").asText())) {
        assertTrue(verdict.accepted(), where + ": " + verdict.reasonCode());
        assertNull(verdict.reasonCode(), where);
        if (provider.path("effects").asBoolean()) {
          assertNotNull(verdict.attestation(), where + ": an accepted dispatch carries its attestation");
        }
      } else {
        assertFalse(verdict.accepted(), where);
        assertEquals(verdict.reasonCode(), expect.path("reason_code").asText(), where);
        assertNull(verdict.attestation(), where);
      }
      index++;
    }
  }

  @Test
  public void canonicalDigestRefusesWhatOtherParsersReadDifferently() {
    for (String body : List.of(
        "{\"a\":1,\"a\":2}",
        "{\"x\":{\"a\":1,\"b\":2,\"a\":3}}",
        "{\"x\":[1,{\"a\":1,\"a\":2}]}",
        "{\"\\u0061\":1,\"a\":2}",
        "{\"a\":\"\\udc00\"}",
        "{\"a\":\"\\ud83d\"}",
        "{\"a\":\"\\ud83d\\ud83d\"}",
        "{\"a\":\"\\udc00\\ud83d\"}",
        "{\"a\":\"\\ud83dx\"}",
        "{\"\\udc00\":1}",
        "not json",
        "5",
        "\"a\"",
        "[1]",
        "")) {
      assertRefused(body.getBytes(StandardCharsets.UTF_8), body);
    }
    assertRefused(new byte[] {(byte) 0xff}, "0xff");
    for (String body : List.of(
        "{\"a\":1,\"b\":{\"a\":2},\"c\":[{\"a\":3},{\"a\":4}],\"d\":[],\"e\":{}}",
        "{\"a\":\"\\ud83d\\ude80\",\"b\":\"\\\\ud83d\",\"c\":\"\\\\\\\\uDC00\"}",
        "{\"a\":\"\\\"\",\"a2\":\"\\\\\"}")) {
      try {
        CanonicalDigest.of(body.getBytes(StandardCharsets.UTF_8));
      } catch (CanonicalDigest.NotIJson e) {
        fail(body + ": " + e.getMessage(), e);
      }
    }
  }

  private static void assertRefused(byte[] body, String label) {
    try {
      CanonicalDigest.of(body);
      fail(label + ": expected a refusal");
    } catch (CanonicalDigest.NotIJson expected) {
      // the refusal
    }
  }

  @Test
  public void canonicalDigestIsOverTheCanonicalForm() throws Exception {
    String spaced = CanonicalDigest.of(
        "{\n  \"b\": 1,\n  \"a\": [1.50, 1e21, -0]\n}".getBytes(StandardCharsets.UTF_8));
    String compact = CanonicalDigest.of("{\"a\":[1.5,1e+21,0],\"b\":1}".getBytes(StandardCharsets.UTF_8));
    assertEquals(spaced, compact);
  }

  @Test
  public void memoryReplayStoreForgetsAGrantOnceItsAttestationExpired() {
    Instant[] now = {Instant.ofEpochSecond(1_789_819_200L)};
    Clock clock = new Clock() {
      @Override public ZoneId getZone() { return ZoneOffset.UTC; }
      @Override public Clock withZone(ZoneId zone) { return this; }
      @Override public Instant instant() { return now[0]; }
    };
    MemoryReplayStore store = new MemoryReplayStore(clock);
    assertTrue(store.record("g", now[0].plusSeconds(1)));
    assertFalse(store.record("g", now[0].plusSeconds(1)));
    now[0] = now[0].plusMillis(999);
    assertFalse(store.record("g", now[0].plusSeconds(5)));
    now[0] = now[0].plusMillis(1);
    assertTrue(store.record("g", now[0].plusSeconds(5)));
  }
}
