import { ProvisionError, type ProvisionOptions } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { credentialsPath, readCredentials } from "../../src/cli/Credentials.js";
import { runLogin, runLogout, type LoginDependencies } from "../../src/cli/Login.js";
import { DEFAULT_AUTHORITY_ENDPOINT } from "../../src/gateway/GatewayConfig.js";
import { fakeProcess } from "../support/GatewayHarness.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";
const KEY = "synthetic-decionis-key-aaaaaaaa";
const WORKSPACE_ID = "7f0c3a5e-0000-4000-8000-00000000000a";

/** A provisioning call that answers as the authority does, and remembers what it was asked. */
function minting(answer: "workspace" | ProvisionError = "workspace"): {
  asked: ProvisionOptions[];
  dependencies: LoginDependencies;
} {
  const asked: ProvisionOptions[] = [];
  return {
    asked,
    dependencies: {
      provision: (options) => {
        asked.push(options);
        if (answer !== "workspace") return Promise.reject(answer);
        return Promise.resolve({
          orgId: WORKSPACE_ID,
          rawKey: "synthetic-provisional-key-bbbbbbbb",
          provisional: true,
          limits: { governed_decisions_per_month: 50 },
          claim: { note: "Claim this workspace at https://decionis.example/claim/synthetic" },
        });
      },
    },
  };
}

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

  it("mints a free provisional workspace with --provision and stores it as the login", async () => {
    const io = fakeProcess({ env: { AGENTSAFE_SURFACE: "homebrew" } });
    const { asked, dependencies } = minting();
    await runLogin(io, ["--provision"], dependencies);
    expect(io.exits).toEqual([0]);
    // The call carries what every hosted call carries, and nothing about the machine.
    expect(asked).toHaveLength(1);
    expect(asked[0]).toMatchObject({
      baseUrl: DEFAULT_AUTHORITY_ENDPOINT,
      allowInsecureLoopback: false,
      source: {
        example: expect.stringMatching(/^agentsafe-login@\d/) as string,
        surface: "homebrew",
      },
      agentName: "agentsafe login",
    });
    expect(readCredentials(io)).toEqual({
      apiKey: "synthetic-provisional-key-bbbbbbbb",
      tenantId: WORKSPACE_ID,
      endpoint: null,
      provisional: true,
    });
    const text = io.out.join("");
    expect(text).toContain(
      `Provisioned a free Decionis workspace ${WORKSPACE_ID} (provisional, no account; 50 governed decisions a month).`,
    );
    expect(text).toContain(`Stored its key at ${credentialsPath(io)} (mode 0600).`);
    expect(text).toContain("It decides in shadow");
    expect(text).toContain("Enforcement needs a key from your\norganization: agentsafe login.");
    expect(text).toContain(
      "Claim it: Claim this workspace at https://decionis.example/claim/synthetic",
    );
    expect(text).toContain("Next: agentsafe doctor");
    // Asked again, the stored workspace is the answer, and nothing is minted.
    await runLogin(io, ["--provision"], dependencies);
    expect(io.exits).toEqual([0, 0]);
    expect(asked).toHaveLength(1);
    expect(io.out.at(-1)).toContain(`A provisional workspace is already stored`);
    expect(io.out.at(-1)).toContain(WORKSPACE_ID);
    // An endpoint of one's own is kept with the workspace, and no surface is
    // sent when the process has none it can name.
    const own = fakeProcess({ env: { AGENTSAFE_SURFACE: "somewhere-unnamed" } });
    const elsewhere = minting();
    await runLogin(
      own,
      ["--provision", "--endpoint", "https://api.decionis.example"],
      elsewhere.dependencies,
    );
    expect(elsewhere.asked[0]).toMatchObject({ baseUrl: "https://api.decionis.example" });
    expect(elsewhere.asked[0]?.source).not.toHaveProperty("surface");
    expect(readCredentials(own)).toMatchObject({
      endpoint: "https://api.decionis.example",
      provisional: true,
    });
  });

  it("refuses to provision over a login, with a key or an organization, in production, or when the authority declines", async () => {
    const stored = fakeProcess({ lines: [KEY, TENANT_ID] });
    await runLogin(stored, []);
    const { asked, dependencies } = minting();
    await runLogin(stored, ["--provision"], dependencies);
    expect(stored.exits).toEqual([0, 1]);
    expect(stored.err.at(-1)).toContain("A login is stored at");
    expect(stored.err.at(-1)).toContain("agentsafe logout");
    expect(asked).toEqual([]);
    expect(readCredentials(stored)?.apiKey).toBe(KEY);

    const withTenant = fakeProcess();
    await runLogin(withTenant, ["--provision", "--tenant", TENANT_ID], dependencies);
    expect(withTenant.exits).toEqual([2]);
    expect(withTenant.err.join("")).toContain("takes no key and no organization");
    const withKey = fakeProcess();
    await runLogin(withKey, ["--provision", "--key-stdin"], dependencies);
    expect(withKey.exits).toEqual([2]);
    const badEndpoint = fakeProcess();
    await runLogin(
      badEndpoint,
      ["--provision", "--endpoint", "http://api.decionis.example"],
      dependencies,
    );
    expect(badEndpoint.exits).toEqual([1]);
    expect(asked).toEqual([]);

    const production = fakeProcess({ env: { NODE_ENV: "production" } });
    await runLogin(production, ["--provision"], dependencies);
    expect(production.exits).toEqual([1]);
    expect(production.err.join("")).toContain("DECIONIS_API_KEY_FILE");
    expect(asked).toEqual([]);

    for (const [error, expected] of [
      [
        new ProvisionError("PROVISION_LIMIT_REACHED", 429, 3_600),
        "Decionis is minting no more free workspaces right now (PROVISION_LIMIT_REACHED). Try again in 3600 s.",
      ],
      [
        new ProvisionError("PROVISION_UNAVAILABLE", 503),
        "Decionis could not be reached, or answered 503 (PROVISION_UNAVAILABLE).",
      ],
      [
        new ProvisionError("PROVISION_UNAVAILABLE", null),
        "Decionis could not be reached, or answered nothing (PROVISION_UNAVAILABLE).",
      ],
      [
        new ProvisionError("PROVISION_TIMED_OUT", null),
        "Decionis did not answer in time (PROVISION_TIMED_OUT).",
      ],
      [
        new ProvisionError("PROVISION_REFUSED", 400),
        "Decionis refused to mint a workspace (PROVISION_REFUSED, 400).",
      ],
      [
        new ProvisionError("PROVISION_RESPONSE_INVALID", 200),
        "Decionis answered with something other than a workspace (PROVISION_RESPONSE_INVALID).",
      ],
    ] as const) {
      const io = fakeProcess();
      await runLogin(io, ["--provision"], minting(error).dependencies);
      expect(io.exits, error.code).toEqual([1]);
      expect(io.err.join(""), error.code).toContain(expected);
      expect(readCredentials(io)).toBeNull();
    }
    const other = fakeProcess();
    await runLogin(other, ["--provision"], {
      provision: () => Promise.reject(new Error("socket hang up")),
    });
    expect(other.exits).toEqual([1]);
    expect(other.err.join("")).toContain(
      "Decionis could not be asked for a workspace; nothing was stored.",
    );
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
