package com.decionis.verifyingprovider;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A servlet filter that runs the profile in front of the handlers behind it:
 * register it in a Spring application (a {@code FilterRegistrationBean}, or
 * {@code @Component}) ahead of anything that reads the body. It buffers the
 * body up to a bound, verifies, and either refuses with the profile's status
 * and body or hands the request on with the body intact. The hop this runs
 * in is a verifying provider only when the system of record admits nothing
 * but that hop (the profile's section 1).
 */
public final class VerifyingProviderFilter implements Filter {
  static final List<String> COVERED = List.of(
      "content-digest", "idempotency-key", "x-agent-safe-intent-hash",
      "x-agent-safe-grant-id", "x-agent-safe-decision-id", "x-agent-safe-claim-attestation",
      "signature", "signature-input");

  private final VerifyingProvider provider;
  private final long maxBodyBytes;

  public VerifyingProviderFilter(VerifyingProvider provider, long maxBodyBytes) {
    this.provider = provider;
    this.maxBodyBytes = maxBodyBytes;
  }

  public VerifyingProviderFilter(VerifyingProvider provider) {
    this(provider, 1L << 20);
  }

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;
    byte[] body = request.getInputStream().readNBytes((int) Math.min(maxBodyBytes + 1, Integer.MAX_VALUE));
    if (body.length > maxBodyBytes) {
      refuse(response, 413, "BODY_BEYOND_BOUND");
      return;
    }
    Map<String, String> headers = new HashMap<>();
    for (Enumeration<String> names = request.getHeaderNames(); names.hasMoreElements(); ) {
      String name = names.nextElement();
      String lower = name.toLowerCase(Locale.ROOT);
      List<String> values = Collections.list(request.getHeaders(name));
      if (values.size() > 1 && COVERED.contains(lower)) {
        refuse(response, 409, Verdict.SIGNATURE_INVALID_OR_INCOMPLETE);
        return;
      }
      headers.put(lower, values.isEmpty() ? "" : values.get(0).trim());
    }
    ProviderRequest received = new ProviderRequest(
        request.getMethod(), request.getRequestURI(), body.length == 0 ? null : body, headers);
    Verdict verdict = provider.verify(received);
    if (!verdict.accepted()) {
      refuse(response, 409, verdict.reasonCode());
      return;
    }
    chain.doFilter(new Replayable(request, body), response);
  }

  private static void refuse(HttpServletResponse response, int status, String code) throws IOException {
    response.setStatus(status);
    response.setContentType("application/json");
    response.getWriter().write("{\"status\":\"REJECTED\",\"reason_code\":\"" + code + "\"}");
  }

  /** The request with its body served again to the handlers behind the filter. */
  private static final class Replayable extends HttpServletRequestWrapper {
    private final byte[] body;

    Replayable(HttpServletRequest request, byte[] body) {
      super(request);
      this.body = body;
    }

    @Override
    public ServletInputStream getInputStream() {
      ByteArrayInputStream bytes = new ByteArrayInputStream(body);
      return new ServletInputStream() {
        @Override
        public int read() {
          return bytes.read();
        }

        @Override
        public boolean isFinished() {
          return bytes.available() == 0;
        }

        @Override
        public boolean isReady() {
          return true;
        }

        @Override
        public void setReadListener(ReadListener listener) {}
      };
    }

    @Override
    public BufferedReader getReader() {
      return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }
  }
}
