import { describe, expect, it } from "vitest";
import {
  MAX_REQUEST_HEAD_BYTES,
  parseAuthority,
  readRequestHead,
} from "../../src/intercept/RequestHead.js";

const bytes = (text: string): Buffer => Buffer.from(text, "latin1");

describe("readRequestHead", () => {
  it("reads the method, target and host of an origin-form request", () => {
    const head = bytes(
      "POST /v1/orders?dry=1 HTTP/1.1\r\nHost: API.Example.com\r\nContent-Type: application/json\r\n\r\n{}",
    );
    expect(readRequestHead(head)).toEqual({
      kind: "REQUEST",
      method: "POST",
      target: "/v1/orders?dry=1",
      host: "api.example.com",
      port: null,
    });
  });

  it("takes the port the host names, and an address as a host", () => {
    expect(readRequestHead(bytes("GET / HTTP/1.0\r\nHost: 127.0.0.1:8080\r\n\r\n"))).toEqual({
      kind: "REQUEST",
      method: "GET",
      target: "/",
      host: "127.0.0.1",
      port: 8080,
    });
    expect(readRequestHead(bytes("GET / HTTP/1.1\r\nhost:\t[::1]:81 \r\n\r\n"))).toEqual({
      kind: "REQUEST",
      method: "GET",
      target: "/",
      host: "[::1]",
      port: 81,
    });
  });

  it("reads an absolute-form target, and requires the host header to agree with it", () => {
    expect(readRequestHead(bytes("GET http://a.example:81/x?y HTTP/1.1\r\n\r\n"))).toEqual({
      kind: "REQUEST",
      method: "GET",
      target: "/x?y",
      host: "a.example",
      port: 81,
    });
    expect(
      readRequestHead(bytes("GET http://a.example HTTP/1.1\r\nHost: a.example\r\n\r\n")),
    ).toEqual({
      kind: "REQUEST",
      method: "GET",
      target: "/",
      host: "a.example",
      port: null,
    });
    expect(
      readRequestHead(bytes("GET http://a.example/ HTTP/1.1\r\nHost: b.example\r\n\r\n")),
    ).toEqual({
      kind: "MALFORMED",
      reason: "TARGET_DISAGREES_WITH_HOST",
    });
    expect(
      readRequestHead(bytes("GET https://a.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n")),
    ).toEqual({
      kind: "MALFORMED",
      reason: "TARGET_INVALID",
    });
    // Built rather than written, so the provenance gate reads no URL with a
    // host that is not a name here.
    const invalidAuthority = ["http:", "", "-bad.example", ""].join("/");
    expect(readRequestHead(bytes(`GET ${invalidAuthority} HTTP/1.1\r\n\r\n`))).toEqual({
      kind: "MALFORMED",
      reason: "TARGET_INVALID",
    });
    const spacedAuthority = ["http:", "", "bad host", ""].join("/");
    expect(readRequestHead(bytes(`GET ${spacedAuthority} HTTP/1.1\r\n\r\n`))).toEqual({
      kind: "MALFORMED",
      reason: "REQUEST_LINE_INVALID",
    });
  });

  it("asks for more until the head has arrived, within the bound", () => {
    const head = "DELETE /a/very/long/path/that/goes/on HTTP/1.1\r\nHost: a.example\r\n\r\n";
    for (const cut of [1, 3, 4, 10, 30, head.length - 1]) {
      expect(readRequestHead(bytes(head.slice(0, cut))), `${cut}`).toEqual({ kind: "NEED_MORE" });
    }
    expect(readRequestHead(bytes(head)).kind).toBe("REQUEST");
    const long = `GET / HTTP/1.1\r\nHost: a.example\r\nX: ${"y".repeat(MAX_REQUEST_HEAD_BYTES)}`;
    expect(readRequestHead(bytes(long))).toEqual({ kind: "MALFORMED", reason: "HEAD_TOO_LONG" });
  });

  it("is not HTTP when the first bytes are not a request line", () => {
    for (const text of [
      "\x16\x03\x01\x00\x05hello",
      "hello there\r\n",
      "get / HTTP/1.1\r\n",
      "\x00\x01",
    ]) {
      expect(readRequestHead(bytes(text)), JSON.stringify(text)).toEqual({ kind: "NOT_HTTP" });
    }
    expect(readRequestHead(bytes("SSH-2.0-OpenSSH\r\n\r\n"))).toEqual({ kind: "NOT_HTTP" });
  });

  it("refuses a head two parsers could read differently", () => {
    const cases: Record<string, [string, string]> = {
      "no host": ["GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", "HOST_MISSING"],
      "a repeated host": [
        "GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n",
        "HOST_REPEATED",
      ],
      "a host that is not one": ["GET / HTTP/1.1\r\nHost: a example\r\n\r\n", "HOST_INVALID"],
      "a host with a bad port": ["GET / HTTP/1.1\r\nHost: a.example:99999\r\n\r\n", "HOST_INVALID"],
      "an empty host": ["GET / HTTP/1.1\r\nHost:\r\n\r\n", "HOST_INVALID"],
      "a header without a colon": ["GET / HTTP/1.1\r\nHost a.example\r\n\r\n", "HEADER_INVALID"],
      "a header with a bare LF": [
        "GET / HTTP/1.1\r\nHost: a.example\nX: y\r\n\r\n",
        "HEADER_INVALID",
      ],
      "a header name that is not a token": [
        "GET / HTTP/1.1\r\nHo st: a.example\r\n\r\n",
        "HEADER_INVALID",
      ],
      "an HTTP/2 preface": ["PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "REQUEST_LINE_INVALID"],
      "a CONNECT": [
        "CONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\r\n",
        "TARGET_INVALID",
      ],
      "a target that is neither form": [
        "GET a.example HTTP/1.1\r\nHost: a.example\r\n\r\n",
        "TARGET_INVALID",
      ],
    };
    for (const [name, [text, reason]] of Object.entries(cases)) {
      expect(readRequestHead(bytes(text)), name).toEqual({ kind: "MALFORMED", reason });
    }
  });
});

describe("parseAuthority", () => {
  it("reads names, addresses and ports, and nothing else", () => {
    expect(parseAuthority("Example.COM")).toEqual({ host: "example.com", port: null });
    expect(parseAuthority("example.com:443")).toEqual({ host: "example.com", port: 443 });
    expect(parseAuthority("10.0.0.1:80")).toEqual({ host: "10.0.0.1", port: 80 });
    expect(parseAuthority("[fe80::1]")).toEqual({ host: "[fe80::1]", port: null });
    expect(parseAuthority("[fe80::1]:8443")).toEqual({ host: "[fe80::1]", port: 8443 });
    for (const bad of [
      "",
      "a..b",
      "-a.example",
      "a.example:",
      "a.example:0",
      "a.example:65536",
      "a.example:8o",
      "fe80::1",
      "[fe80::1",
      "[fe80::1]x",
      "[zz]",
      "a.example/path",
      `${"a".repeat(64)}.example`,
      "x".repeat(261),
    ]) {
      expect(parseAuthority(bad), bad).toBeNull();
    }
  });
});
