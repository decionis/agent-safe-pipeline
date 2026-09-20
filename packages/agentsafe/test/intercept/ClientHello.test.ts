import { once } from "node:events";
import { createServer, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { describe, expect, it } from "vitest";
import { MAX_CLIENT_HELLO_BYTES, readClientHello } from "../../src/intercept/ClientHello.js";
import { TestCertificateAuthority } from "../support/TestCertificateAuthority.js";

function u16(value: number): Buffer {
  return Buffer.from([(value >> 8) & 0xff, value & 0xff]);
}

function u24(value: number): Buffer {
  return Buffer.from([(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]);
}

function serverNameExtension(names: readonly { type?: number; name: string }[]): Buffer {
  const entries = Buffer.concat(
    names.map(({ type = 0, name }) => {
      const bytes = Buffer.from(name, "latin1");
      return Buffer.concat([Buffer.from([type]), u16(bytes.length), bytes]);
    }),
  );
  const list = Buffer.concat([u16(entries.length), entries]);
  return Buffer.concat([u16(0x0000), u16(list.length), list]);
}

function alpnExtension(protocols: readonly string[]): Buffer {
  const entries = Buffer.concat(
    protocols.map((protocol) => {
      const bytes = Buffer.from(protocol, "latin1");
      return Buffer.concat([Buffer.from([bytes.length]), bytes]);
    }),
  );
  const list = Buffer.concat([u16(entries.length), entries]);
  return Buffer.concat([u16(0x0010), u16(list.length), list]);
}

function extension(type: number, body: Buffer): Buffer {
  return Buffer.concat([u16(type), u16(body.length), body]);
}

/** A ClientHello handshake message (no record header) with the given extensions. */
function clientHello(
  extensions: readonly Buffer[] | null,
  options: { type?: number } = {},
): Buffer {
  const body = Buffer.concat([
    u16(0x0303),
    Buffer.alloc(32, 7),
    Buffer.from([0]), // session id
    u16(2),
    Buffer.from([0x13, 0x01]), // one cipher suite
    Buffer.from([1, 0]), // one compression method: null
    ...(extensions === null ? [] : [u16(Buffer.concat(extensions).length), ...extensions]),
  ]);
  return Buffer.concat([Buffer.from([options.type ?? 0x01]), u24(body.length), body]);
}

/** Handshake bytes wrapped in one or more TLS records. */
function records(handshake: Buffer, fragmentAt: number[] = []): Buffer {
  const parts: Buffer[] = [];
  let offset = 0;
  for (const cut of [...fragmentAt, handshake.length]) {
    const fragment = handshake.subarray(offset, cut);
    parts.push(Buffer.from([0x16, 0x03, 0x01]), u16(fragment.length), fragment);
    offset = cut;
  }
  return Buffer.concat(parts);
}

describe("readClientHello", () => {
  it("reads the server name and the ALPN protocols from a hand-built hello", () => {
    const bytes = records(
      clientHello([
        serverNameExtension([{ name: "API.Example.COM" }]),
        alpnExtension(["h2", "http/1.1"]),
      ]),
    );
    expect(readClientHello(bytes)).toEqual({
      kind: "CLIENT_HELLO",
      serverName: "api.example.com",
      alpn: ["h2", "http/1.1"],
    });
  });

  it("reads what Node's own TLS client sends", async () => {
    const server = createServer();
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const port = (server.address() as { port: number }).port;
    const captured = new Promise<Buffer>((resolve) => {
      server.once("connection", (socket: Socket) => {
        socket.once("data", (chunk: Buffer) => {
          resolve(chunk);
          socket.destroy();
        });
      });
    });
    // The server never answers the hello, so no certificate is ever checked;
    // the client still trusts only the test's own authority.
    const client = tlsConnect({
      host: "127.0.0.1",
      port,
      servername: "upstream.example",
      ALPNProtocols: ["http/1.1"],
      ca: [new TestCertificateAuthority().certificate],
    });
    client.on("error", () => undefined);
    const first = await captured;
    client.destroy();
    server.close();
    const reading = readClientHello(first);
    expect(reading).toEqual({
      kind: "CLIENT_HELLO",
      serverName: "upstream.example",
      alpn: ["http/1.1"],
    });
  });

  it("asks for more while the hello is incomplete, across records too", () => {
    const handshake = clientHello([serverNameExtension([{ name: "a.example" }])]);
    const whole = records(handshake, [10, 40]);
    // Cuts inside a record header, inside a body, and at every boundary.
    for (const cut of [0, 3, 5, 12, 15, 17, 20, 44, whole.length - 1]) {
      expect(readClientHello(whole.subarray(0, cut)), `${cut}`).toEqual({ kind: "NEED_MORE" });
    }
    expect(readClientHello(whole)).toEqual({
      kind: "CLIENT_HELLO",
      serverName: "a.example",
      alpn: [],
    });
    // The handshake header alone in the first record, the rest in the second.
    expect(readClientHello(records(handshake, [4]))).toEqual({
      kind: "CLIENT_HELLO",
      serverName: "a.example",
      alpn: [],
    });
    expect(readClientHello(records(handshake, [4]).subarray(0, 9))).toEqual({ kind: "NEED_MORE" });
  });

  it("accepts a record as large as TLS allows and refuses one larger", () => {
    const largest = Buffer.concat([
      Buffer.from([0x16, 0x03, 0x01, 0x40, 0x00]),
      Buffer.alloc(16_384),
    ]);
    largest.set([0x01, 0x00, 0xff, 0x00], 5);
    expect(readClientHello(largest)).toEqual({ kind: "NEED_MORE" });
    const larger = Buffer.concat([
      Buffer.from([0x16, 0x03, 0x01, 0x40, 0x01]),
      Buffer.alloc(16_385),
    ]);
    expect(readClientHello(larger)).toEqual({ kind: "NOT_TLS" });
  });

  it("reads only the hello when a later record carries more after it", () => {
    const handshake = clientHello([serverNameExtension([{ name: "a.example" }])]);
    const trailing = Buffer.concat([handshake, Buffer.from([0x0b, 0, 0, 0, 1, 2, 3])]);
    expect(readClientHello(records(trailing, [10, 30]))).toEqual({
      kind: "CLIENT_HELLO",
      serverName: "a.example",
      alpn: [],
    });
  });

  it("refuses a hello whose fields run past its bytes", () => {
    const body = (fields: Buffer): Buffer =>
      records(Buffer.concat([Buffer.from([0x01]), u24(fields.length), fields]));
    const prefix = Buffer.concat([u16(0x0303), Buffer.alloc(32, 7)]);
    const suites = Buffer.concat([Buffer.from([0]), u16(2), Buffer.from([0x13, 0x01])]);
    const cases: Record<string, Buffer> = {
      "a session id longer than the hello": body(
        Buffer.concat([prefix, Buffer.from([32]), Buffer.alloc(10)]),
      ),
      "a cipher suite length cut in half": body(
        Buffer.concat([prefix, Buffer.from([0]), Buffer.from([0x00])]),
      ),
      "no compression byte": body(Buffer.concat([prefix, suites])),
      "an extension longer than the hello": body(
        Buffer.concat([
          prefix,
          suites,
          Buffer.from([1, 0]),
          u16(8),
          u16(0x0000),
          u16(20),
          Buffer.alloc(4),
        ]),
      ),
      "a server name that claims more bytes than follow, which would otherwise read as a valid shorter one":
        body(
          Buffer.concat([
            prefix,
            suites,
            Buffer.from([1, 0]),
            u16(18),
            u16(0x0000),
            u16(14),
            u16(12),
            Buffer.from([0x00]),
            u16(20),
            Buffer.from("a.example", "latin1"),
          ]),
        ),
      "a server name longer than its extension": body(
        Buffer.concat([
          prefix,
          suites,
          Buffer.from([1, 0]),
          u16(9),
          u16(0x0000),
          u16(5),
          u16(3),
          Buffer.from([0x00]),
          u16(40),
        ]),
      ),
    };
    for (const [name, bytes] of Object.entries(cases)) {
      expect(readClientHello(bytes), name).toEqual({ kind: "MALFORMED" });
    }
  });

  it("refuses a server name longer than a host name may be, and reads one at the limit", () => {
    expect(readClientHello(records(clientHello([serverNameExtension([{ name: "a.b" }])])))).toEqual(
      {
        kind: "CLIENT_HELLO",
        serverName: "a.b",
        alpn: [],
      },
    );
    const label = "a".repeat(63);
    const longest = [label, label, label, "a".repeat(61)].join(".");
    expect(longest).toHaveLength(253);
    expect(
      readClientHello(records(clientHello([serverNameExtension([{ name: longest }])]))),
    ).toEqual({ kind: "CLIENT_HELLO", serverName: longest, alpn: [] });
    const tooLong = [label, label, label, "a".repeat(62)].join(".");
    expect(
      readClientHello(records(clientHello([serverNameExtension([{ name: tooLong }])]))),
    ).toEqual({ kind: "MALFORMED" });
    const longLabel = `${"a".repeat(64)}.example`;
    expect(
      readClientHello(records(clientHello([serverNameExtension([{ name: longLabel }])]))),
    ).toEqual({ kind: "MALFORMED" });
  });

  it("refuses an ALPN protocol name outside printable ASCII wherever the byte sits", () => {
    for (const protocol of ["h2", "h2", "h 2", "h2"]) {
      expect(
        readClientHello(records(clientHello([alpnExtension([protocol])]))),
        JSON.stringify(protocol),
      ).toEqual({ kind: "MALFORMED" });
    }
    expect(readClientHello(records(clientHello([alpnExtension(["!", "~"])])))).toEqual({
      kind: "CLIENT_HELLO",
      serverName: null,
      alpn: ["!", "~"],
    });
  });

  it("reads only the hello when the record carries more after it", () => {
    const handshake = clientHello([serverNameExtension([{ name: "a.example" }])]);
    const trailing = Buffer.concat([handshake, Buffer.from([0x0b, 0, 0, 0])]);
    expect(readClientHello(records(trailing))).toEqual({
      kind: "CLIENT_HELLO",
      serverName: "a.example",
      alpn: [],
    });
  });

  it("says a hello without a server name has none, and a hello without extensions too", () => {
    expect(readClientHello(records(clientHello([alpnExtension(["h2"])])))).toEqual({
      kind: "CLIENT_HELLO",
      serverName: null,
      alpn: ["h2"],
    });
    expect(readClientHello(records(clientHello(null)))).toEqual({
      kind: "CLIENT_HELLO",
      serverName: null,
      alpn: [],
    });
  });

  it("is not TLS when the first record is not a handshake record", () => {
    expect(readClientHello(Buffer.from("GET / HTTP/1.1\r\n"))).toEqual({ kind: "NOT_TLS" });
    expect(readClientHello(Buffer.from([0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]))).toEqual({
      kind: "NOT_TLS",
    });
    expect(readClientHello(Buffer.from([0x16, 0x02, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5]))).toEqual({
      kind: "NOT_TLS",
    });
    expect(readClientHello(Buffer.from([0x16, 0x03, 0x01, 0x00, 0x00]))).toEqual({
      kind: "NOT_TLS",
    });
  });

  it("refuses a hello it cannot read as the RFC lays it out", () => {
    const cases: Record<string, Buffer> = {
      "not a ClientHello": records(clientHello([], { type: 0x02 })),
      "a length beyond any hello": (() => {
        const bytes = records(clientHello([serverNameExtension([{ name: "a.example" }])]));
        bytes[6] = 0x7f;
        return bytes;
      })(),
      "a length shorter than the hello": (() => {
        const hello = clientHello([serverNameExtension([{ name: "a.example" }])]);
        hello[3] = (hello[3] ?? 0) - 4;
        return records(hello);
      })(),
      "a repeated server_name extension": records(
        clientHello([
          serverNameExtension([{ name: "a.example" }]),
          serverNameExtension([{ name: "b.example" }]),
        ]),
      ),
      "two host names in one extension": records(
        clientHello([serverNameExtension([{ name: "a.example" }, { name: "b.example" }])]),
      ),
      "a host name that is not one": records(
        clientHello([serverNameExtension([{ name: "not a host" }])]),
      ),
      "an address where a name belongs": records(
        clientHello([serverNameExtension([{ name: "-bad.example" }])]),
      ),
      "a server_name list length that disagrees": records(
        clientHello([extension(0x0000, Buffer.from([0x00, 0x09, 0x00, 0x00, 0x01, 0x61]))]),
      ),
      "a repeated ALPN extension": records(
        clientHello([alpnExtension(["h2"]), alpnExtension(["h2"])]),
      ),
      "an ALPN list length that disagrees": records(
        clientHello([extension(0x0010, Buffer.from([0x00, 0x09, 0x02, 0x68, 0x32]))]),
      ),
      "a server name with a byte outside printable ASCII": records(
        clientHello([serverNameExtension([{ name: "a\u0001.example" }])]),
      ),
      "an empty ALPN protocol": records(
        clientHello([extension(0x0010, Buffer.from([0x00, 0x01, 0x00]))]),
      ),
      "an extensions length that disagrees": (() => {
        const hello = clientHello([alpnExtension(["h2"])]);
        const offset = 4 + 2 + 32 + 1 + 2 + 2 + 2;
        hello[offset + 1] = (hello[offset + 1] ?? 0) + 1;
        return records(hello);
      })(),
      "a non-handshake record inside an unfinished hello": (() => {
        const handshake = clientHello([serverNameExtension([{ name: "a.example" }])]);
        const first = records(handshake.subarray(0, 20));
        return Buffer.concat([first, Buffer.from([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])]);
      })(),
    };
    for (const [name, bytes] of Object.entries(cases)) {
      expect(readClientHello(bytes), name).toEqual({ kind: "MALFORMED" });
    }
  });

  it("ignores a server_name entry of another name type", () => {
    const bytes = records(
      clientHello([serverNameExtension([{ type: 1, name: "ignored" }, { name: "a.example" }])]),
    );
    expect(readClientHello(bytes)).toEqual({
      kind: "CLIENT_HELLO",
      serverName: "a.example",
      alpn: [],
    });
    const onlyOther = records(clientHello([serverNameExtension([{ type: 1, name: "ignored" }])]));
    expect(readClientHello(onlyOther)).toEqual({ kind: "MALFORMED" });
  });

  it("refuses a hello beyond the bound instead of reading on", () => {
    const filler = extension(0xff01, Buffer.alloc(16_000, 1));
    const hello = clientHello([filler, filler, filler, filler, filler]);
    expect(hello.length).toBeGreaterThan(MAX_CLIENT_HELLO_BYTES);
    const cuts = Array.from(
      { length: Math.ceil(hello.length / 16_000) - 1 },
      (_, i) => (i + 1) * 16_000,
    );
    expect(readClientHello(records(hello, cuts))).toEqual({ kind: "MALFORMED" });
  });
});
