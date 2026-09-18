import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  credentialsDirectory,
  credentialsPath,
  readStoredCredentials,
  writeStoredCredentials,
  type CredentialFiles,
} from "../../src/http/StoredCredentials.js";

const ORG = "00000000-0000-4000-8000-000000000004";

function memoryFiles(
  initial: Record<string, string> = {},
): CredentialFiles & { stored: Map<string, string> } {
  const stored = new Map(Object.entries(initial));
  return {
    stored,
    read: (path) => stored.get(path) ?? null,
    write: (path, text) => {
      stored.set(path, text);
    },
    mkdir: () => undefined,
  };
}

describe("the stored credential", () => {
  const scratch: string[] = [];

  afterEach(() => {
    for (const dir of scratch.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  it("lives under AGENTSAFE_HOME, else XDG, else the home directory", () => {
    expect(credentialsDirectory({ env: { AGENTSAFE_HOME: "/explicit" }, home: "/h" })).toBe(
      "/explicit",
    );
    expect(credentialsDirectory({ env: { XDG_CONFIG_HOME: "/xdg" }, home: "/h" })).toBe(
      join("/xdg", "agentsafe"),
    );
    expect(credentialsPath({ env: { AGENTSAFE_HOME: " " }, home: "/h" })).toBe(
      join("/h", ".config", "agentsafe", "credentials.json"),
    );
    expect(credentialsDirectory({ env: {} })).toMatch(/agentsafe$/);
  });

  it("round-trips a login and a provisioned workspace through an injected file seam", () => {
    const files = memoryFiles();
    const options = { env: { AGENTSAFE_HOME: "/a" }, files };
    expect(readStoredCredentials(options)).toBeNull();
    const path = writeStoredCredentials(options, { apiKey: "k", tenantId: ORG, endpoint: null });
    expect(path).toBe(join("/a", "credentials.json"));
    expect(readStoredCredentials(options)).toEqual({ apiKey: "k", tenantId: ORG, endpoint: null });
    writeStoredCredentials(options, {
      apiKey: "k2",
      tenantId: ORG,
      endpoint: "https://authority.example",
      provisional: true,
    });
    expect(readStoredCredentials(options)).toEqual({
      apiKey: "k2",
      tenantId: ORG,
      endpoint: "https://authority.example",
      provisional: true,
    });
  });

  it("returns null for what it cannot read as a credential, and in production", () => {
    const path = join("/a", "credentials.json");
    for (const text of [
      "",
      "{",
      "[]",
      JSON.stringify({ version: 2, decionis: {} }),
      JSON.stringify({
        version: 1,
        decionis: { apiKey: "k", tenantId: ["not", "a", "uuid"].join("-"), endpoint: null },
      }),
      JSON.stringify({
        version: 1,
        decionis: { apiKey: "k", tenantId: null, endpoint: null, extra: 1 },
      }),
      "x".repeat(17 * 1024),
    ]) {
      expect(
        readStoredCredentials({
          env: { AGENTSAFE_HOME: "/a" },
          files: memoryFiles({ [path]: text }),
        }),
      ).toBeNull();
    }
    const good = JSON.stringify({
      version: 1,
      decionis: { apiKey: "k", tenantId: null, endpoint: null },
    });
    expect(
      readStoredCredentials({
        env: { AGENTSAFE_HOME: "/a", NODE_ENV: "production" },
        files: memoryFiles({ [path]: good }),
      }),
    ).toBeNull();
    expect(
      readStoredCredentials({
        env: { AGENTSAFE_HOME: "/a" },
        files: memoryFiles({ [path]: good }),
      }),
    ).toEqual({ apiKey: "k", tenantId: null, endpoint: null });
  });

  it("writes a real file readable by its owner alone", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentsafe-credentials-"));
    scratch.push(dir);
    const options = { env: { AGENTSAFE_HOME: join(dir, "nested") } };
    const path = writeStoredCredentials(options, { apiKey: "k", tenantId: ORG, endpoint: null });
    expect(readFileSync(path, "utf8")).toContain('"apiKey": "k"');
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(statSync(join(dir, "nested")).mode & 0o777).toBe(0o700);
    expect(readStoredCredentials(options)).toEqual({ apiKey: "k", tenantId: ORG, endpoint: null });
    expect(readStoredCredentials({ env: { AGENTSAFE_HOME: join(dir, "absent") } })).toBeNull();
  });
});
