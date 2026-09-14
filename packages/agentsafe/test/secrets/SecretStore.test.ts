import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { SecretStore } from "../../src/secrets/SecretStore.js";

describe("SecretStore", () => {
  const directory = mkdtempSync(join(tmpdir(), "agentsafe-secrets-"));
  afterAll(() => rmSync(directory, { recursive: true, force: true }));

  it("resolves a value given directly, trimmed", () => {
    expect(
      SecretStore.resolve({ DECIONIS_API_KEY: "  synthetic-key \n" }, "DECIONIS_API_KEY"),
    ).toBe("synthetic-key");
  });

  it("resolves a value from a mounted file, trimmed", () => {
    const path = join(directory, "api-key");
    writeFileSync(path, "synthetic-file-key\n");
    expect(SecretStore.resolve({ DECIONIS_API_KEY_FILE: path }, "DECIONIS_API_KEY")).toBe(
      "synthetic-file-key",
    );
  });

  it("refuses a secret given both ways, naming the variable only", () => {
    expect(() =>
      SecretStore.resolve(
        { DECIONIS_API_KEY: "synthetic-key", DECIONIS_API_KEY_FILE: join(directory, "api-key") },
        "DECIONIS_API_KEY",
      ),
    ).toThrow("CONFIG_SECRET_AMBIGUOUS: DECIONIS_API_KEY");
  });

  it("refuses a missing, empty, unreadable, or empty-file secret", () => {
    expect(() => SecretStore.resolve({}, "DECIONIS_API_KEY")).toThrow(
      "CONFIG_SECRET_MISSING: DECIONIS_API_KEY",
    );
    expect(() => SecretStore.resolve({ DECIONIS_API_KEY: "   " }, "DECIONIS_API_KEY")).toThrow(
      "CONFIG_SECRET_EMPTY: DECIONIS_API_KEY",
    );
    expect(() =>
      SecretStore.resolve({ DECIONIS_API_KEY_FILE: join(directory, "absent") }, "DECIONIS_API_KEY"),
    ).toThrow("CONFIG_SECRET_FILE_UNREADABLE: DECIONIS_API_KEY");
    const empty = join(directory, "empty");
    writeFileSync(empty, "\n");
    expect(() => SecretStore.resolve({ DECIONIS_API_KEY_FILE: empty }, "DECIONIS_API_KEY")).toThrow(
      "CONFIG_SECRET_EMPTY: DECIONIS_API_KEY",
    );
  });
});
