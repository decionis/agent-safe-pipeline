import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { RecordingTarget } from "../../src/http/RecordingTarget.js";

describe("the recording target", () => {
  let target: RecordingTarget;

  beforeEach(() => {
    target = new RecordingTarget();
  });

  afterEach(async () => {
    await target.stop();
  });

  it("answers by method, records what arrived and keeps no header values", async () => {
    await target.start();
    await target.start();
    expect(target.baseUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    const read = await fetch(`${target.baseUrl}/accounts/42?verbose=1`);
    expect(read.status).toBe(200);
    const write = await fetch(`${target.baseUrl}/payments`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-agent-safe-decision": "ALLOW" },
      body: '{"amount":25}',
    });
    expect(write.status).toBe(201);
    expect(await write.json()).toEqual({
      received: { method: "POST", path: "/payments", body_bytes: 13 },
    });
    const remove = await fetch(`${target.baseUrl}/customers/42`, { method: "DELETE" });
    expect(remove.status).toBe(204);
    expect(target.received.map((request) => [request.method, request.path])).toEqual([
      ["GET", "/accounts/42"],
      ["POST", "/payments"],
      ["DELETE", "/customers/42"],
    ]);
    expect(target.received[1]?.headerNames).toContain("x-agent-safe-decision");
    expect(JSON.stringify(target.received)).not.toContain("ALLOW");
    expect(target.received[1]?.bodyBytes).toBe(13);
  });

  it("drops a body past its bound instead of keeping it", async () => {
    await target.start();
    await expect(
      fetch(`${target.baseUrl}/payments`, {
        method: "POST",
        body: Buffer.alloc(1024 * 1024 + 1, 65),
      }),
    ).rejects.toThrow();
    expect(target.received).toEqual([]);
  });

  it("stops idempotently", async () => {
    await target.stop();
    await target.start();
    await target.stop();
    await target.stop();
    await expect(fetch(`${target.baseUrl}/`)).rejects.toThrow();
  });
});
