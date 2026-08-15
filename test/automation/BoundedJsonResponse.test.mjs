import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  defaultMaxJsonResponseBytes,
  readBoundedJsonResponse,
} from "../../scripts/BoundedJsonResponse.mjs";

describe("readBoundedJsonResponse", () => {
  it("parses a bounded JSON response", async () => {
    const response = new globalThis.Response(JSON.stringify({ status: "ok" }));

    assert.deepEqual(await readBoundedJsonResponse(response), { status: "ok" });
  });

  it("rejects and cancels a streamed response above the byte limit", async () => {
    let cancelled = false;
    const body = new globalThis.ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(defaultMaxJsonResponseBytes));
        controller.enqueue(new Uint8Array(1));
      },
      cancel() {
        cancelled = true;
      },
    });

    await assert.rejects(
      readBoundedJsonResponse(new globalThis.Response(body)),
      /GITHUB_API_RESPONSE_TOO_LARGE/,
    );
    assert.equal(cancelled, true);
  });

  it("returns stable errors for malformed JSON and encoding", async () => {
    await assert.rejects(
      readBoundedJsonResponse(new globalThis.Response("{")),
      /GITHUB_API_RESPONSE_INVALID/,
    );
    await assert.rejects(
      readBoundedJsonResponse(new globalThis.Response(new Uint8Array([255]))),
      /GITHUB_API_RESPONSE_INVALID/,
    );
  });

  it("rejects an invalid configured limit", async () => {
    await assert.rejects(
      readBoundedJsonResponse(new globalThis.Response("{}"), { maxBytes: 0 }),
      /GITHUB_API_RESPONSE_LIMIT_INVALID/,
    );
  });
});
