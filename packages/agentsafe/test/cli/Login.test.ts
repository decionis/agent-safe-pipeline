import { describe, expect, it } from "vitest";
import { readCredentials } from "../../src/cli/Credentials.js";
import { runLogin, runLogout } from "../../src/cli/Login.js";
import { DEFAULT_AUTHORITY_ENDPOINT } from "../../src/gateway/GatewayConfig.js";
import { fakeProcess } from "../support/GatewayHarness.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";
const KEY = "synthetic-decionis-key-aaaaaaaa";

describe("agentsafe login and logout", () => {
  it("stores a key read from input, never from an argument, with the organization and endpoint", async () => {
    const io = fakeProcess({ lines: [KEY, TENANT_ID] });
    await runLogin(io, []);
    expect(io.exits).toEqual([0]);
    expect(readCredentials(io)).toEqual({ apiKey: KEY, tenantId: TENANT_ID, endpoint: null });
    expect(io.out.join("")).toContain("mode 0600");
    expect(io.out.join("")).toContain(DEFAULT_AUTHORITY_ENDPOINT);
    const flagged = fakeProcess({ lines: [KEY] });
    await runLogin(flagged, [
      "--tenant",
      TENANT_ID,
      "--endpoint",
      "https://api.decionis.example",
      "--key-stdin",
    ]);
    expect(readCredentials(flagged)).toEqual({
      apiKey: KEY,
      tenantId: TENANT_ID,
      endpoint: "https://api.decionis.example",
    });
    const blank = fakeProcess({ lines: [KEY, ""] });
    await runLogin(blank, []);
    expect(readCredentials(blank)?.tenantId).toBeNull();
    expect(blank.out.join("")).toContain("export DECIONIS_TENANT_ID");
  });

  it("refuses what is not a key, an organization or an endpoint, and refuses in production", async () => {
    const short = fakeProcess({ lines: ["abc"] });
    await runLogin(short, []);
    expect(short.exits).toEqual([1]);
    expect(readCredentials(short)).toBeNull();
    const org = fakeProcess({ lines: [KEY, "org-1"] });
    await runLogin(org, []);
    expect(org.exits).toEqual([1]);
    const endpoint = fakeProcess({ lines: [KEY] });
    await runLogin(endpoint, [
      "--tenant",
      TENANT_ID,
      "--endpoint",
      "http://api.decionis.example/path",
    ]);
    expect(endpoint.exits).toEqual([1]);
    const production = fakeProcess({ env: { NODE_ENV: "production" }, lines: [KEY] });
    await runLogin(production, []);
    expect(production.exits).toEqual([1]);
    expect(production.err.join("")).toContain("DECIONIS_API_KEY_FILE");
    const bad = fakeProcess();
    await runLogin(bad, ["--nope"]);
    expect(bad.exits).toEqual([2]);
  });

  it("removes the stored login, and says when there was none", async () => {
    const io = fakeProcess({ lines: [KEY, TENANT_ID] });
    await runLogin(io, []);
    runLogout(io);
    expect(io.out.at(-1)).toContain("Removed");
    expect(readCredentials(io)).toBeNull();
    runLogout(io);
    expect(io.out.at(-1)).toContain("No login stored");
    expect(io.exits).toEqual([0, 0, 0]);
  });
});
