import { describe, expect, it } from "vitest";
import {
  credentialsDirectory,
  credentialsPath,
  readCredentials,
  removeCredentials,
  writeCredentials,
} from "../../src/cli/Credentials.js";
import { fakeProcess } from "../support/GatewayHarness.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";

describe("the stored login", () => {
  it("lives under AGENTSAFE_HOME, else XDG, else ~/.config", () => {
    expect(credentialsDirectory(fakeProcess())).toBe("/home/synthetic/.config/agentsafe");
    expect(credentialsDirectory(fakeProcess({ env: { XDG_CONFIG_HOME: "/xdg" } }))).toBe(
      "/xdg/agentsafe",
    );
    expect(
      credentialsDirectory(
        fakeProcess({ env: { AGENTSAFE_HOME: "/opt/agentsafe", XDG_CONFIG_HOME: "/xdg" } }),
      ),
    ).toBe("/opt/agentsafe");
    expect(credentialsPath(fakeProcess())).toBe(
      "/home/synthetic/.config/agentsafe/credentials.json",
    );
  });

  it("round-trips through a file readable by this user alone, and is removed on logout", () => {
    const io = fakeProcess();
    const path = writeCredentials(io, {
      apiKey: "synthetic-key-0123456789",
      tenantId: TENANT_ID,
      endpoint: null,
    });
    expect(path).toBe(credentialsPath(io));
    expect(io.stored.get(path)?.mode).toBe(0o600);
    expect(readCredentials(io)).toEqual({
      apiKey: "synthetic-key-0123456789",
      tenantId: TENANT_ID,
      endpoint: null,
    });
    expect(removeCredentials(io)).toBe(path);
    expect(readCredentials(io)).toBeNull();
  });

  it("ignores a file it cannot read as a login, and every file in production", () => {
    const path = credentialsPath(fakeProcess());
    expect(readCredentials(fakeProcess({ files: { [path]: "{not json" } }))).toBeNull();
    expect(
      readCredentials(fakeProcess({ files: { [path]: JSON.stringify({ version: 2 }) } })),
    ).toBeNull();
    expect(
      readCredentials(
        fakeProcess({
          files: {
            [path]: JSON.stringify({
              version: 1,
              decionis: { apiKey: "k", tenantId: String("org"), endpoint: null },
            }),
          },
        }),
      ),
    ).toBeNull();
    expect(readCredentials(fakeProcess({ files: { [path]: "x".repeat(20 * 1024) } }))).toBeNull();
    const valid = JSON.stringify({
      version: 1,
      decionis: {
        apiKey: "synthetic-key-0123456789",
        tenantId: null,
        endpoint: "https://api.decionis.example",
      },
    });
    expect(readCredentials(fakeProcess({ files: { [path]: valid } }))?.endpoint).toBe(
      "https://api.decionis.example",
    );
    expect(
      readCredentials(fakeProcess({ env: { NODE_ENV: "production" }, files: { [path]: valid } })),
    ).toBeNull();
  });
});
