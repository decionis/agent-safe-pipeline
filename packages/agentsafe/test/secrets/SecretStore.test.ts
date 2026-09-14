import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { CompositeSecretStore } from "../../src/secrets/CompositeSecretStore.js";
import { EnvSecretStore } from "../../src/secrets/EnvSecretStore.js";
import { FileSecretStore, MAX_SECRET_BYTES } from "../../src/secrets/FileSecretStore.js";
import type { SecretHandle } from "../../src/secrets/SecretHandle.js";
import { collectedEvents } from "../support/Environment.js";

const directory = mkdtempSync(join(tmpdir(), "agentsafe-secrets-"));
afterAll(() => rmSync(directory, { recursive: true, force: true }));

let files = 0;
function secretFile(content: string, mode = 0o600): string {
  files += 1;
  const path = join(directory, `secret-${files}`);
  writeFileSync(path, content, { mode });
  chmodSync(path, mode);
  return path;
}

const wait = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

describe("EnvSecretStore", () => {
  it("holds trimmed values from the environment and cannot rotate", async () => {
    const store = EnvSecretStore.open(
      { DECIONIS_API_KEY: "  synthetic-key \n", EXECUTOR_CALLER_TOKEN: "synthetic-token" },
      ["DECIONIS_API_KEY", "EXECUTOR_CALLER_TOKEN"],
    );
    expect(store.has("DECIONIS_API_KEY")).toBe(true);
    expect(store.has("PRESENCE_API_KEY")).toBe(false);
    expect(store.get("DECIONIS_API_KEY").use((value) => value.toString())).toBe("synthetic-key");
    expect(await store.reload("SIGHUP")).toEqual({ reason: "SIGHUP", rotated: [], refused: [] });
    expect(store.onRotate()).toBeTypeOf("function");
    expect(() => store.get("PRESENCE_API_KEY")).toThrow("SECRET_UNKNOWN: PRESENCE_API_KEY");
    store.close();
    expect(store.get("DECIONIS_API_KEY").disposed).toBe(true);
  });

  it("refuses a missing or empty variable, naming it only", () => {
    expect(() => EnvSecretStore.open({}, ["DECIONIS_API_KEY"])).toThrow(
      "CONFIG_SECRET_MISSING: DECIONIS_API_KEY",
    );
    expect(() => EnvSecretStore.open({ DECIONIS_API_KEY: "  " }, ["DECIONIS_API_KEY"])).toThrow(
      "CONFIG_SECRET_EMPTY: DECIONIS_API_KEY",
    );
  });
});

describe("FileSecretStore", () => {
  const open = (
    files: Partial<Record<"DECIONIS_API_KEY" | "EXECUTOR_CALLER_TOKEN", string>>,
    options: {
      enforcePermissions?: boolean;
      graceMs?: number;
      pollMs?: number;
      watch?: boolean;
    } = {},
    lines: string[] = [],
  ): FileSecretStore =>
    FileSecretStore.open({
      files,
      events: collectedEvents(lines),
      watch: false,
      ...options,
    });

  it("reads a private file, trimmed, and refuses one another user could read", () => {
    const store = open({ DECIONIS_API_KEY: secretFile("synthetic-file-key\n") });
    expect(store.get("DECIONIS_API_KEY").use((value) => value.toString())).toBe(
      "synthetic-file-key",
    );
    store.close();
    const shared = secretFile("synthetic-shared-key", 0o644);
    expect(() => open({ DECIONIS_API_KEY: shared })).toThrow(
      "CONFIG_SECRET_FILE_MODE: DECIONIS_API_KEY",
    );
    const lenient = open({ DECIONIS_API_KEY: shared }, { enforcePermissions: false });
    expect(lenient.get("DECIONIS_API_KEY").use((value) => value.toString())).toBe(
      "synthetic-shared-key",
    );
    lenient.close();
  });

  it("refuses a missing, empty, oversized, or non-regular file, naming the variable only", () => {
    expect(() => open({ DECIONIS_API_KEY: join(directory, "absent") })).toThrow(
      "CONFIG_SECRET_FILE_UNREADABLE: DECIONIS_API_KEY",
    );
    expect(() => open({ DECIONIS_API_KEY: secretFile("\n") })).toThrow(
      "CONFIG_SECRET_EMPTY: DECIONIS_API_KEY",
    );
    expect(() => open({ DECIONIS_API_KEY: secretFile("x".repeat(MAX_SECRET_BYTES + 1)) })).toThrow(
      "CONFIG_SECRET_TOO_LARGE: DECIONIS_API_KEY",
    );
    const nested = join(directory, "a-directory");
    mkdirSync(nested);
    expect(() => open({ DECIONIS_API_KEY: nested })).toThrow(
      "CONFIG_SECRET_FILE_MODE: DECIONIS_API_KEY",
    );
  });

  it("accepts the two ownership shapes a mount can have and no other", () => {
    const refusal = FileSecretStore.permissionRefusal;
    expect(refusal(0o100600, 1000, 1000, 1000, 1000)).toBeNull();
    expect(refusal(0o100640, 1000, 1000, 1000, 1000)).toBe("CONFIG_SECRET_FILE_MODE");
    expect(refusal(0o100440, 0, 1000, 1000, 1000)).toBeNull();
    expect(refusal(0o100444, 0, 1000, 1000, 1000)).toBe("CONFIG_SECRET_FILE_MODE");
    expect(refusal(0o100460, 0, 1000, 1000, 1000)).toBe("CONFIG_SECRET_FILE_MODE");
    expect(refusal(0o100440, 0, 2000, 1000, 1000)).toBe("CONFIG_SECRET_FILE_OWNER");
    expect(refusal(0o100600, 3000, 3000, 1000, 1000)).toBe("CONFIG_SECRET_FILE_OWNER");
  });

  it("rotates a changed file atomically, tells listeners, and retires the old handle after a grace", async () => {
    const lines: string[] = [];
    const path = secretFile("synthetic-token-before");
    const store = open({ EXECUTOR_CALLER_TOKEN: path }, { graceMs: 20 }, lines);
    const before = store.get("EXECUTOR_CALLER_TOKEN");
    const heard: SecretHandle[] = [];
    const stop = store.onRotate("EXECUTOR_CALLER_TOKEN", (next) => heard.push(next));

    expect((await store.reload("OPERATOR")).rotated).toEqual([]);
    writeFileSync(path, "synthetic-token-after\n");
    const report = await store.reload("OPERATOR");
    expect(report).toEqual({ reason: "OPERATOR", rotated: ["EXECUTOR_CALLER_TOKEN"], refused: [] });
    const after = store.get("EXECUTOR_CALLER_TOKEN");
    expect(after).not.toBe(before);
    expect(after.use((value) => value.toString())).toBe("synthetic-token-after");
    expect(heard).toEqual([after]);
    expect(before.disposed).toBe(false);
    await wait(60);
    expect(before.disposed).toBe(true);
    expect(lines.some((line) => line.includes('"SECRET_ROTATED"'))).toBe(true);
    expect(lines.join("\n")).not.toContain("synthetic-token");

    stop();
    writeFileSync(path, "synthetic-token-third\n");
    await store.reload("OPERATOR");
    expect(heard).toHaveLength(1);
    store.close();
  });

  it("keeps the previous handle when a reloaded file fails its checks", async () => {
    const lines: string[] = [];
    const path = secretFile("synthetic-token-good");
    const store = open({ EXECUTOR_CALLER_TOKEN: path }, {}, lines);
    writeFileSync(path, "synthetic-token-exposed");
    chmodSync(path, 0o644);
    const report = await store.reload("SIGHUP");
    expect(report.rotated).toEqual([]);
    expect(report.refused).toEqual([
      { name: "EXECUTOR_CALLER_TOKEN", code: "CONFIG_SECRET_FILE_MODE" },
    ]);
    expect(store.get("EXECUTOR_CALLER_TOKEN").use((value) => value.toString())).toBe(
      "synthetic-token-good",
    );
    expect(lines.some((line) => line.includes('"SECRET_RELOAD_REFUSED"'))).toBe(true);
    store.close();
  });

  it("notices a rotation on its own through the poll", async () => {
    const path = secretFile("synthetic-token-polled");
    const store = FileSecretStore.open({
      files: { EXECUTOR_CALLER_TOKEN: path },
      events: collectedEvents(),
      pollMs: 40,
      debounceMs: 10,
    });
    writeFileSync(path, "synthetic-token-polled-next");
    for (let attempt = 0; attempt < 50; attempt += 1) {
      if (
        store
          .get("EXECUTOR_CALLER_TOKEN")
          .use((value) => value.toString())
          .endsWith("next")
      ) {
        break;
      }
      await wait(40);
    }
    expect(store.get("EXECUTOR_CALLER_TOKEN").use((value) => value.toString())).toBe(
      "synthetic-token-polled-next",
    );
    store.close();
  });
});

describe("CompositeSecretStore", () => {
  it("opens each secret from wherever it was given and reloads only the files", async () => {
    const path = secretFile("synthetic-file-credential");
    const store = CompositeSecretStore.fromEnvironment(
      {
        EXECUTOR_CALLER_TOKEN: "synthetic-env-token",
        DECIONIS_API_KEY: "synthetic-env-key",
        DOWNSTREAM_CREDENTIAL_FILE: path,
      },
      ["EXECUTOR_CALLER_TOKEN", "DECIONIS_API_KEY", "DOWNSTREAM_CREDENTIAL"],
      { events: collectedEvents(), production: false, enforcePermissions: true, watch: false },
    );
    expect([...store.names()].sort()).toEqual([
      "DECIONIS_API_KEY",
      "DOWNSTREAM_CREDENTIAL",
      "EXECUTOR_CALLER_TOKEN",
    ]);
    expect(store.has("PRESENCE_API_KEY")).toBe(false);
    expect(store.get("DOWNSTREAM_CREDENTIAL").use((value) => value.toString())).toBe(
      "synthetic-file-credential",
    );
    writeFileSync(path, "synthetic-file-credential-2");
    expect((await store.reload("OPERATOR")).rotated).toEqual(["DOWNSTREAM_CREDENTIAL"]);
    expect(() => store.get("PRESENCE_API_KEY")).toThrow("SECRET_UNKNOWN: PRESENCE_API_KEY");
    expect(() => store.onRotate("PRESENCE_API_KEY", () => undefined)).toThrow(
      "SECRET_UNKNOWN: PRESENCE_API_KEY",
    );
    store.close();
    expect(store.get("DECIONIS_API_KEY").disposed).toBe(true);
  });

  it("refuses ambiguity, absence, and environment secrets under production", () => {
    const options = {
      events: collectedEvents(),
      production: false,
      enforcePermissions: true,
      watch: false,
    };
    expect(() =>
      CompositeSecretStore.fromEnvironment(
        { DECIONIS_API_KEY: "synthetic-key", DECIONIS_API_KEY_FILE: secretFile("synthetic-key") },
        ["DECIONIS_API_KEY"],
        options,
      ),
    ).toThrow("CONFIG_SECRET_AMBIGUOUS: DECIONIS_API_KEY");
    expect(() => CompositeSecretStore.fromEnvironment({}, ["DECIONIS_API_KEY"], options)).toThrow(
      "CONFIG_SECRET_MISSING: DECIONIS_API_KEY",
    );
    expect(() =>
      CompositeSecretStore.fromEnvironment(
        { DECIONIS_API_KEY: "synthetic-key" },
        ["DECIONIS_API_KEY"],
        {
          ...options,
          production: true,
        },
      ),
    ).toThrow("CONFIG_SECRET_IN_ENV: DECIONIS_API_KEY");
  });
});
