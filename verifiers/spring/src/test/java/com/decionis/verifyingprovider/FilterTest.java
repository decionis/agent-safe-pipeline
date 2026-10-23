package com.decionis.verifyingprovider;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.testng.annotations.Test;

public class FilterTest {

  /** A request as the container hands it to the filter: the vector's method, path, headers and body. */
  private static HttpServletRequest servletRequest(JsonNode request) {
    Map<String, String> headers = new HashMap<>();
    request.path("headers").properties()
        .forEach(entry -> headers.put(entry.getKey(), entry.getValue().asText()));
    byte[] body = request.path("body").isNull()
        ? new byte[0]
        : request.path("body").asText().getBytes(StandardCharsets.UTF_8);
    ByteArrayInputStream bytes = new ByteArrayInputStream(body);
    ServletInputStream stream = new ServletInputStream() {
      @Override public int read() { return bytes.read(); }
      @Override public boolean isFinished() { return bytes.available() == 0; }
      @Override public boolean isReady() { return true; }
      @Override public void setReadListener(ReadListener listener) {}
    };
    Map<String, Object> attributes = new HashMap<>();
    return (HttpServletRequest) Proxy.newProxyInstance(
        FilterTest.class.getClassLoader(), new Class<?>[] {HttpServletRequest.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "getMethod" -> request.path("method").asText();
          case "getRequestURI" -> request.path("path").asText();
          case "getHeaderNames" -> Collections.enumeration(headers.keySet());
          case "getHeaders" -> Collections.enumeration(List.of(headers.get((String) args[0])));
          case "getInputStream" -> stream;
          case "getAttribute" -> attributes.get((String) args[0]);
          case "setAttribute" -> args[1] == null
              ? attributes.remove((String) args[0])
              : attributes.put((String) args[0], args[1]);
          default -> throw new UnsupportedOperationException(method.getName());
        });
  }

  /** A response that keeps the status and body the filter refuses with. */
  private static HttpServletResponse servletResponse(int[] status, StringWriter body) {
    PrintWriter writer = new PrintWriter(body, true);
    return (HttpServletResponse) Proxy.newProxyInstance(
        FilterTest.class.getClassLoader(), new Class<?>[] {HttpServletResponse.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "setStatus" -> {
            status[0] = (int) args[0];
            yield null;
          }
          case "setContentType" -> null;
          case "getWriter" -> writer;
          default -> throw new UnsupportedOperationException(method.getName());
        });
  }

  @Test
  public void theFilterHandsTheVerifiedAttestationToTheApplication() throws Exception {
    JsonNode vector = VectorsTest.vector(
        VectorsTest.vectorsDirectory().resolve("state-version-left-to-the-write.json"));
    JsonNode request = vector.path("requests").path(0);
    VerifyingProviderFilter filter = new VerifyingProviderFilter(VectorsTest.providerFor(vector));
    // The system of record behind the hop: it reads the body it was handed, and the attestation.
    List<Object> reached = new ArrayList<>();
    FilterChain application = (servletRequest, servletResponse) -> {
      reached.add(servletRequest.getAttribute(VerifyingProviderFilter.ATTESTATION_ATTRIBUTE));
      reached.add(new String(servletRequest.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
    };
    int[] status = {200};
    StringWriter body = new StringWriter();
    filter.doFilter(servletRequest(request), servletResponse(status, body), application);
    assertEquals(status[0], 200, body.toString());
    assertEquals(reached.size(), 2);
    assertTrue(reached.get(0) instanceof ClaimAttestation, String.valueOf(reached.get(0)));
    assertEquals(((ClaimAttestation) reached.get(0)).expectedStateVersion(), Optional.of("\"17\""));
    assertEquals(reached.get(1), request.path("body").asText());

    HttpServletRequest again = servletRequest(request);
    filter.doFilter(again, servletResponse(status, body), application);
    assertEquals(status[0], 409);
    assertEquals(body.toString(), "{\"status\":\"REJECTED\",\"reason_code\":\"GRANT_REPLAYED\"}");
    assertEquals(reached.size(), 2, "a refusal reaches nothing behind the filter");
    assertNull(again.getAttribute(VerifyingProviderFilter.ATTESTATION_ATTRIBUTE));
  }
}
