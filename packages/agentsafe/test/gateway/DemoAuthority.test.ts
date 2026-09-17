import { describe, expect, it } from "vitest";
import { amountMinorOf, demoPolicy, startDemoAuthority } from "../../src/gateway/DemoAuthority.js";

const request = (
  parameters: Record<string, unknown>,
  context: Record<string, unknown> = { body_embedded: true, body_bytes: 10 },
) => ({
  action: { type: "http.post", parameters },
  context,
});

describe("the demo policy", () => {
  it("reads an amount in major or minor units, and nothing that is not one", () => {
    expect(amountMinorOf({ amount: 12.34 })).toBe(1234);
    expect(amountMinorOf({ amount: "12.3" })).toBe(1230);
    expect(amountMinorOf({ amount: "100" })).toBe(10_000);
    expect(amountMinorOf({ amountMinor: 55 })).toBe(55);
    expect(amountMinorOf({ amount_minor: 56 })).toBe(56);
    expect(amountMinorOf({ amountMinor: -1, amount: 1 })).toBe(100);
    expect(amountMinorOf({ amount: "1,000" })).toBeNull();
    expect(amountMinorOf({ amount: 1e21 })).toBeNull();
    expect(amountMinorOf({ amount: true })).toBeNull();
    expect(amountMinorOf({})).toBeNull();
    expect(amountMinorOf(undefined)).toBeNull();
    expect(amountMinorOf(null)).toBeNull();
    expect(amountMinorOf([1])).toBeNull();
    expect(amountMinorOf("5")).toBeNull();
  });

  it("allows within the autonomous ceiling, escalates above it, blocks above the human ceiling", () => {
    expect(demoPolicy(request({ method: "POST", body: { amount: 100 } }))).toBe("ALLOW");
    expect(demoPolicy(request({ method: "POST", body: { amount: 100.01 } }))).toBe("ESCALATE");
    expect(demoPolicy(request({ method: "POST", body: { amountMinor: 100_000 } }))).toBe(
      "ESCALATE",
    );
    expect(demoPolicy(request({ method: "POST", body: { amountMinor: 100_001 } }))).toBe("BLOCK");
    expect(demoPolicy(request({ method: "POST", body: { note: "no amount" } }))).toBe("ALLOW");
    expect(demoPolicy(request({ method: "POST" }))).toBe("ALLOW");
  });

  it("escalates a DELETE, and a body it could not see", () => {
    expect(demoPolicy(request({ method: "DELETE" }))).toBe("ESCALATE");
    expect(demoPolicy(request({ method: "POST" }, { body_embedded: false, body_bytes: 12 }))).toBe(
      "ESCALATE",
    );
    expect(demoPolicy(request({ method: "POST" }, { body_embedded: false, body_bytes: 0 }))).toBe(
      "ALLOW",
    );
  });

  it("starts the loopback double with the demo key and stops it", async () => {
    const handle = await startDemoAuthority();
    expect(handle.baseUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect(handle.apiKey).toBe("test-key");
    await handle.stop();
  });
});
