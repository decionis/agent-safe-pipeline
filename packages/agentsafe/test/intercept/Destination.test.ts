import { describe, expect, it } from "vitest";
import { MAX_PEEK_BYTES, readDestination } from "../../src/intercept/Destination.js";
import { InterceptLedger } from "../../src/intercept/InterceptLedger.js";

/** A minimal ClientHello record naming `host`, or none when null. */
function hello(host: string | null): Buffer {
  const name = host === null ? null : Buffer.from(host, "latin1");
  const sni =
    name === null
      ? Buffer.alloc(0)
      : Buffer.concat([
          Buffer.from([0x00, 0x00]),
          Buffer.from([(name.length + 5) >> 8, (name.length + 5) & 0xff]),
          Buffer.from([(name.length + 3) >> 8, (name.length + 3) & 0xff]),
          Buffer.from([0x00, name.length >> 8, name.length & 0xff]),
          name,
        ]);
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    Buffer.alloc(32, 1),
    Buffer.from([0x00]),
    Buffer.from([0x00, 0x02, 0x13, 0x01]),
    Buffer.from([0x01, 0x00]),
    Buffer.from([sni.length >> 8, sni.length & 0xff]),
    sni,
  ]);
  const handshake = Buffer.concat([
    Buffer.from([0x01, 0x00, body.length >> 8, body.length & 0xff]),
    body,
  ]);
  return Buffer.concat([
    Buffer.from([0x16, 0x03, 0x01, handshake.length >> 8, handshake.length & 0xff]),
    handshake,
  ]);
}

describe("readDestination", () => {
  it("places TLS by its server name on the port the listener stood for", () => {
    expect(readDestination(hello("api.example"), 443)).toEqual({
      kind: "DESTINATION",
      protocol: "TLS",
      host: "api.example",
      port: 443,
      alpn: [],
    });
  });

  it("places HTTP by its host, the host's own port winning over the listener's", () => {
    expect(readDestination(Buffer.from("PUT /x HTTP/1.1\r\nHost: a.example\r\n\r\n"), 80)).toEqual({
      kind: "DESTINATION",
      protocol: "HTTP",
      host: "a.example",
      port: 80,
      method: "PUT",
      target: "/x",
    });
    expect(
      readDestination(Buffer.from("GET / HTTP/1.1\r\nHost: a.example:8080\r\n\r\n"), 80),
    ).toMatchObject({ port: 8080 });
  });

  it("asks for more while either reading is incomplete, and refuses at the bound", () => {
    expect(readDestination(hello("api.example").subarray(0, 9), 443)).toEqual({
      kind: "NEED_MORE",
    });
    expect(readDestination(Buffer.from("POST /x HTTP/1.1\r\nHo"), 80)).toEqual({
      kind: "NEED_MORE",
    });
    const tlsFlood = Buffer.concat([
      Buffer.from([0x16, 0x03, 0x01, 0x40, 0x00]),
      Buffer.alloc(MAX_PEEK_BYTES),
    ]);
    expect(readDestination(tlsFlood.subarray(0, 5 + 100), 443)).toEqual({ kind: "NEED_MORE" });
    // A record length no TLS record can have is not TLS at all, and not HTTP either.
    const bogus = Buffer.concat([Buffer.from([0x16, 0x03, 0x01, 0xff, 0xff]), Buffer.alloc(64)]);
    expect(readDestination(bogus, 443)).toEqual({
      kind: "REFUSED",
      reason: "DESTINATION_UNKNOWN",
      protocol: null,
    });
    // A hello that announces the most bytes allowed and never finishes them is
    // refused once the peek bound is reached, not read on.
    const record = (length: number): Buffer =>
      Buffer.concat([
        Buffer.from([0x16, 0x03, 0x01, length >> 8, length & 0xff]),
        Buffer.alloc(length),
      ]);
    const first = record(16_384);
    first.set([0x01, 0x00, 0xff, 0xfc], 5);
    const partial = Buffer.concat([
      Buffer.from([0x16, 0x03, 0x01, 0x40, 0x00]),
      Buffer.alloc(16_379),
    ]);
    const unfinished = Buffer.concat([first, record(16_384), record(16_384), partial]);
    expect(unfinished.length).toBeGreaterThanOrEqual(MAX_PEEK_BYTES);
    expect(readDestination(unfinished.subarray(0, 40_000), 443)).toEqual({ kind: "NEED_MORE" });
    expect(readDestination(unfinished.subarray(0, MAX_PEEK_BYTES - 1), 443)).toEqual({
      kind: "NEED_MORE",
    });
    expect(readDestination(unfinished.subarray(0, MAX_PEEK_BYTES), 443)).toEqual({
      kind: "REFUSED",
      reason: "MALFORMED",
      protocol: "TLS",
    });
    expect(readDestination(unfinished, 443)).toEqual({
      kind: "REFUSED",
      reason: "MALFORMED",
      protocol: "TLS",
    });
    const httpFlood = Buffer.from(`GET / HTTP/1.1\r\nX: ${"y".repeat(MAX_PEEK_BYTES)}`);
    expect(readDestination(httpFlood, 80)).toEqual({
      kind: "REFUSED",
      reason: "MALFORMED",
      protocol: "HTTP",
      detail: "HEAD_TOO_LONG",
    });
  });

  it("refuses what names no destination", () => {
    expect(readDestination(hello(null), 443)).toEqual({
      kind: "REFUSED",
      reason: "DESTINATION_UNKNOWN",
      protocol: "TLS",
    });
    expect(readDestination(Buffer.from("SSH-2.0-x\r\n\r\n"), 22)).toEqual({
      kind: "REFUSED",
      reason: "DESTINATION_UNKNOWN",
      protocol: null,
    });
    expect(readDestination(Buffer.from("GET / HTTP/1.1\r\n\r\n"), 80)).toEqual({
      kind: "REFUSED",
      reason: "MALFORMED",
      protocol: "HTTP",
      detail: "HOST_MISSING",
    });
    const broken = hello("api.example");
    broken[5] = 0x02;
    expect(readDestination(broken, 443)).toEqual({
      kind: "REFUSED",
      reason: "MALFORMED",
      protocol: "TLS",
    });
  });
});

describe("InterceptLedger", () => {
  it("counts destinations, methods, bytes and refusals, and reports them sorted", () => {
    const ledger = new InterceptLedger();
    const a = ledger.record("b.example", 443, "TLS", null, "2026-09-20T10:00:00.000Z");
    ledger.placed();
    ledger.bytes(a, 100, 2_000);
    const b = ledger.record("a.example", 80, "HTTP", "POST", "2026-09-20T10:00:01.000Z");
    ledger.placed();
    ledger.bytes(b, 300, 50);
    ledger.record("a.example", 80, "HTTP", "GET", "2026-09-20T10:00:02.000Z");
    ledger.refuse("UPSTREAM_UNREACHABLE", "2026-09-20T10:00:03.000Z", false);
    ledger.refuse("DESTINATION_UNKNOWN", "2026-09-20T10:00:04.000Z", true);
    ledger.refuse("DESTINATION_UNKNOWN", "2026-09-20T10:00:05.000Z", true);
    ledger.bytes("nobody:1", 1, 1);
    expect(ledger.summary()).toEqual({
      since: "2026-09-20T10:00:00.000Z",
      until: "2026-09-20T10:00:05.000Z",
      connections: 5,
      placed: 2,
      refused: { DESTINATION_UNKNOWN: 2, UPSTREAM_UNREACHABLE: 1 },
      destinations: {
        "a.example:80": {
          protocol: "HTTP",
          connections: 2,
          bytes_to_destination: 300,
          bytes_from_destination: 50,
          methods: { POST: 1, GET: 1 },
        },
        "b.example:443": {
          protocol: "TLS",
          connections: 1,
          bytes_to_destination: 100,
          bytes_from_destination: 2_000,
          methods: {},
        },
      },
    });
    const report = ledger.report("2026-09-20T10:01:00.000Z");
    expect(report.event).toBe("INTERCEPT_REPORT");
    expect(report.at).toBe("2026-09-20T10:01:00.000Z");
    expect(report.intercept.placed).toBe(2);
    expect(report.next).toContain("agentsafe proxy --upstream");
  });

  it("keeps a thousand destinations apart and the rest under one name", () => {
    const ledger = new InterceptLedger();
    for (let index = 0; index < 1_000; index += 1) {
      ledger.record(`h${index}.example`, 443, "TLS", null, "2026-09-20T10:00:00.000Z");
    }
    expect(ledger.record("more.example", 443, "TLS", null, "2026-09-20T10:00:00.000Z")).toBe(
      "other",
    );
    expect(ledger.record("h7.example", 443, "TLS", null, "2026-09-20T10:00:00.000Z")).toBe(
      "h7.example:443",
    );
    const summary = ledger.summary();
    expect(Object.keys(summary.destinations)).toHaveLength(1_001);
    expect(summary.destinations["other"]?.connections).toBe(1);
    expect(summary.destinations["h7.example:443"]?.connections).toBe(2);
    const empty = new InterceptLedger().summary();
    expect(empty).toEqual({
      since: null,
      until: null,
      connections: 0,
      placed: 0,
      refused: {},
      destinations: {},
    });
  });
});
