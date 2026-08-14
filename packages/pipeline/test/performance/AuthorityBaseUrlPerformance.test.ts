import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import { AuthorityBaseUrl } from "../../src/http/AuthorityBaseUrl.js";

describe("AuthorityBaseUrl performance", () => {
  it("normalizes an adversarial slash run within the performance budget", () => {
    const baseUrl = `https://authority.example/${"/".repeat(100_000)}sentinel`;
    const startedAt = performance.now();

    const normalized = AuthorityBaseUrl.normalize(baseUrl);

    expect(normalized).toBe(baseUrl);
    expect(performance.now() - startedAt).toBeLessThan(1_000);
  });
});
