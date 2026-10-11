import { once } from "node:events";
import { connect, createServer, type AddressInfo, type Socket } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { readConnectResponse, readLine, requireControl } from "../../src/tcp/TcpWire.js";

const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((close) => close()));
});

async function pair(): Promise<{ client: Socket; peer: Socket }> {
  const server = createServer({ allowHalfOpen: true });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const accepted = once(server, "connection");
  const client = connect({
    host: "127.0.0.1",
    port: (server.address() as AddressInfo).port,
    allowHalfOpen: true,
  });
  client.on("error", () => undefined);
  const [peer] = (await accepted) as [Socket];
  peer.on("error", () => undefined);
  cleanups.push(async () => {
    client.destroy();
    peer.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  return { client, peer };
}

describe("TCP relay framing", () => {
  it("preserves coalesced CONNECT, attach and binary tails, including a split header", async () => {
    const { client, peer } = await pair();
    const response = readConnectResponse(client, 16384, 1000);
    peer.write("HTTP/1.1 200 Connection Established\r\n");
    const raw = Buffer.from([0, 255, 13, 10, 127]);
    peer.write(Buffer.concat([Buffer.from('\r\n{"type":"attach"}\n'), raw]));
    const headers = await response;
    expect(headers.status).toBe(200);
    const control = await readLine(client, 1024, 1000, headers.tail);
    requireControl(control.line, "attach");
    expect(control.tail).toEqual(raw);
    expect(client.isPaused()).toBe(true);
  });

  it("bounds incomplete lines and deadlines and rejects malformed controls and HTTP framing", async () => {
    const { client, peer } = await pair();
    const oversized = readLine(client, 8, 1000);
    peer.write("12345678");
    await expect(oversized).rejects.toMatchObject({ code: "TCP_FRAME_TOO_LARGE" });
    await expect(readLine(client, 8, 10)).rejects.toMatchObject({ code: "TCP_PROTOCOL_TIMEOUT" });
    for (const line of ['{"type":"ready"}', '{"type":"attach","target":"other"}', "not-json"]) {
      expect(() => requireControl(line, "attach")).toThrow("TCP_CONTROL_INVALID");
    }
    const invalid = readConnectResponse(client, 16384, 1000);
    peer.write("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx");
    await expect(invalid).rejects.toMatchObject({ code: "TCP_RESPONSE_INVALID" });
  });

  it("cancels a pending read and refuses invalid UTF-8 without echoing bytes", async () => {
    const { client, peer } = await pair();
    const abort = new AbortController();
    const pending = readLine(client, 1024, 1000, Buffer.alloc(0), abort.signal);
    abort.abort();
    await expect(pending).rejects.toMatchObject({ code: "TCP_STOPPED" });
    const invalid = readLine(client, 1024, 1000);
    peer.write(Buffer.from([255, 10]));
    await expect(invalid).rejects.toMatchObject({ code: "TCP_CONTROL_INVALID" });
  });
});
