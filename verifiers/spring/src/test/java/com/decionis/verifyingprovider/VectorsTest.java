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
import java.util.Optional;
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

  static JsonNode vector(Path file) throws IOException {
    return JSON.readTree(Files.readString(file));
  }

  /** A provider configured as the vector says, with a replay store of its own. */
  static VerifyingProvider providerFor(JsonNode vector) {
    JsonNode provider = vector.path("provider");
    Instant now = Instant.parse(provider.path("now").asText());
    Clock clock = Clock.fixed(now, ZoneOffset.UTC);
    List<ExecutorKey> keys = new ArrayList<>();
    for (JsonNode key : vector.path("executor_keys")) {
      keys.add(executorKey(key));
    }
    return new VerifyingProvider(new ProviderOptions(
        provider.path("effects").asBoolean(),
        keys,
        Jwks.parse(vector.path("authority_jwks").toString()),
        provider.path("authority_issuer").asText(),
        Duration.ofSeconds(provider.path("clock_window_seconds").asLong()),
        new MemoryReplayStore(clock),
        clock));
  }

  static ProviderRequest requestOf(JsonNode request) {
    Map<String, String> headers = new HashMap<>();
    request.path("headers").fields()
        .forEachRemaining(entry -> headers.put(entry.getKey(), entry.getValue().asText()));
    byte[] body = request.path("body").isNull()
        ? null
        : request.path("body").asText().getBytes(StandardCharsets.UTF_8);
    return new ProviderRequest(
        request.path("method").asText(), request.path("path").asText(), body, headers);
  }

  /** The vector's own read of the target, for step 9: none given, a version, or gone (null). */
  static Optional<ProviderTarget> targetOf(JsonNode request) {
    if (!request.has("target_version")) {
      return Optional.empty();
    }
    JsonNode version = request.path("target_version");
    return Optional.of(version.isNull() ? ProviderTarget.gone() : ProviderTarget.at(version.textValue()));
  }

  /** The version the attestation names, handed back on an acceptance or a step 9 refusal. */
  static Optional<String> expectedStateVersion(JsonNode expect) {
    return expect.has("expected_state_version")
        ? Optional.of(expect.path("expected_state_version").textValue())
        : Optional.empty();
  }

  @Test(dataProvider = "vectors")
  public void everyVectorReachesTheOutcomesItNames(Path file) throws IOException {
    JsonNode vector = vector(file);
    assertEquals(vector.path("profile").asText(), "agent-safe.verifying-provider/1");
    assertEquals(vector.path("version").asText(), "0.1");
    boolean effects = vector.path("provider").path("effects").asBoolean();
    VerifyingProvider verifying = providerFor(vector);
    int index = 0;
    for (JsonNode request : vector.path("requests")) {
      ProviderRequest received = requestOf(request);
      Optional<ProviderTarget> target = targetOf(request);
      Verdict verdict = target.isPresent()
          ? verifying.verify(received, target.get())
          : verifying.verify(received);
      JsonNode expect = request.path("expect");
      String where = file.getFileName() + " request " + index;
      if ("ACCEPT".equals(expect.path("outcome").asText())) {
        assertTrue(verdict.accepted(), where + ": " + verdict.reasonCode());
        assertNull(verdict.reasonCode(), where);
        if (effects) {
          assertNotNull(verdict.attestation(), where + ": an accepted dispatch carries its attestation");
          assertEquals(verdict.attestation().expectedStateVersion(), expectedStateVersion(expect), where);
        }
      } else if (Verdict.TARGET_STATE_CHANGED.equals(expect.path("reason_code").asText())) {
        assertFalse(verdict.accepted(), where);
        assertEquals(verdict.reasonCode(), Verdict.TARGET_STATE_CHANGED, where);
        assertNotNull(verdict.attestation(), where + ": a step 9 refusal carries its attestation");
        assertEquals(verdict.attestation().expectedStateVersion(), expectedStateVersion(expect), where);
      } else {
        assertFalse(verdict.accepted(), where);
        assertEquals(verdict.reasonCode(), expect.path("reason_code").asText(), where);
        assertNull(verdict.attestation(), where);
      }
      index++;
    }
  }

  /** A vector's first request, as received; the step 9 cases vary only the target. */
  private static ProviderRequest firstRequestOf(JsonNode vector) {
    return requestOf(vector.path("requests").path(0));
  }

  @Test
  public void stepNineAcceptsTheVersionTheGrantWasDecidedOnOrNoReadOfTheTarget() throws IOException {
    JsonNode vector = vector(vectorsDirectory().resolve("state-version-unchanged-accepts.json"));
    ProviderRequest request = firstRequestOf(vector);
    Verdict read = providerFor(vector).verify(request, ProviderTarget.at("\"17\""));
    assertTrue(read.accepted(), read.reasonCode());
    assertEquals(read.attestation().expectedStateVersion(), Optional.of("\"17\""));
    Verdict unread = providerFor(vector).verify(request);
    assertTrue(unread.accepted(), unread.reasonCode());
    assertEquals(unread.attestation(), read.attestation());
  }

  @Test
  public void stepNineRefusesAnyOtherVersionAfterRecordingThePresentation() throws IOException {
    JsonNode vector = vector(vectorsDirectory().resolve("state-version-unchanged-accepts.json"));
    ProviderRequest request = firstRequestOf(vector);
    ClaimAttestation claimed = providerFor(vector).verify(request).attestation();
    for (ProviderTarget target : List.of(ProviderTarget.at("\"18\""), ProviderTarget.at("W/\"17\""),
        ProviderTarget.at("17"), ProviderTarget.gone())) {
      VerifyingProvider verifying = providerFor(vector);
      Verdict refused = verifying.verify(request, target);
      assertEquals(refused, new Verdict(false, Verdict.TARGET_STATE_CHANGED, claimed), target.toString());
      assertEquals(refused.refusalBody(),
          "{\"status\":\"REJECTED\",\"reason_code\":\"TARGET_STATE_CHANGED\"}");
      assertEquals(verifying.verify(request, ProviderTarget.at("\"17\"")),
          new Verdict(false, Verdict.GRANT_REPLAYED, null), target + ": the refusal recorded the grant");
    }
  }

  @Test
  public void stepNineIgnoresTheTargetWhenTheAttestationNamesNoVersion() throws IOException {
    JsonNode vector = vector(vectorsDirectory().resolve("state-version-not-named-ignores-target.json"));
    ProviderRequest request = firstRequestOf(vector);
    for (ProviderTarget target : List.of(ProviderTarget.at("\"8\""), ProviderTarget.gone())) {
      Verdict verdict = providerFor(vector).verify(request, target);
      assertTrue(verdict.accepted(), target + ": " + verdict.reasonCode());
      assertEquals(verdict.attestation().expectedStateVersion(), Optional.empty(), target.toString());
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
