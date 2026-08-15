import { describe, expect, it } from "vitest";
import { InMemoryReplayStore } from "../../src/execution/ReplayStore.js";

describe("InMemoryReplayStore", () => {
  it("allows exactly one concurrent claim for an unexpired grant", async () => {
    const store = new InMemoryReplayStore();
    const expiresAt = new Date(Date.now() + 60_000);

    const claims = await Promise.all(
      Array.from({ length: 100 }, async () => store.claim("grant-1", expiresAt)),
    );

    expect(claims.filter(Boolean)).toHaveLength(1);
  });

  it("rejects invalid or expired claims without making them replayable", async () => {
    const store = new InMemoryReplayStore();

    await expect(store.claim("expired", new Date(Date.now() - 1))).resolves.toBe(false);
    await expect(store.claim("expired", new Date(Date.now() - 1))).resolves.toBe(false);
    await expect(store.claim("", new Date(Date.now() + 60_000))).resolves.toBe(false);
    await expect(store.claim("grant-2", new Date(Number.NaN))).resolves.toBe(false);
  });

  it("fails closed when its bounded capacity is exhausted", async () => {
    expect(() => new InMemoryReplayStore(0)).toThrow("REPLAY_STORE_CAPACITY_INVALID");
    const store = new InMemoryReplayStore(1);
    const expiresAt = new Date(Date.now() + 60_000);

    await expect(store.claim("grant-1", expiresAt)).resolves.toBe(true);
    await expect(store.claim("grant-2", expiresAt)).rejects.toThrow(
      "REPLAY_STORE_CAPACITY_EXCEEDED",
    );
  });
});
