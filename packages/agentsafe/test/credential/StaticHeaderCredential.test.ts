import { describe, expect, it } from "vitest";
import type { DownstreamCredential } from "../../src/credential/DownstreamCredential.js";
import { StaticHeaderCredential } from "../../src/credential/StaticHeaderCredential.js";
import { SecretHandle } from "../../src/secrets/SecretHandle.js";

describe("StaticHeaderCredential", () => {
  it("puts the current handle's value in the configured header and follows rotation", async () => {
    let current = SecretHandle.fromString("DOWNSTREAM_CREDENTIAL", "Bearer synthetic-one");
    const credential: DownstreamCredential = new StaticHeaderCredential(
      "authorization",
      () => current,
    );
    const request = {
      method: "POST" as const,
      url: "https://payouts.provider.example/v1/payouts",
      body: "{}",
      idempotencyKey: "payout-1-v1",
      intentHash: `sha256:${"0".repeat(64)}`,
    };
    expect(credential.kind).toBe("STATIC_HEADER");
    expect(await credential.headersFor(request)).toEqual({ authorization: "Bearer synthetic-one" });
    current = SecretHandle.fromString("DOWNSTREAM_CREDENTIAL", "Bearer synthetic-two");
    expect(await credential.headersFor(request)).toEqual({ authorization: "Bearer synthetic-two" });
  });
});
