import { randomBytes } from "node:crypto";
import {
  copyFileSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  ATTEMPT_DIRECTORY,
  ATTEMPT_TTL_MS,
  FileAttemptStore,
  MAX_ATTEMPTS,
  MemoryAttemptStore,
  type IndeterminateAttempt,
} from "../../src/gateway/AttemptStore.js";
import { FileHoldStore } from "../../src/gateway/HoldStore.js";

const NOW = Date.parse("2026-11-18T12:00:00.000Z");
const SCOPE = "00000000-0000-4000-8000-000000000009";
const OTHER_SCOPE = "00000000-0000-4000-8000-000000000010";
const KEY = "fixture-idempotency-key-marker";

const root = mkdtempSync(join(tmpdir(), "agentsafe-attempts-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

function keyFile(name: string): string {
  const path = join(root, `${name}.key`);
  writeFileSync(path, `${randomBytes(32).toString("base64url")}\n`, { mode: 0o600 });
  return path;
}

function attempt(
  digest = `sha256:${"a".repeat(64)}`,
  dossier = "synthetic-dossier-1",
): IndeterminateAttempt {
  return {
    requestDigest: digest,
    intentId: "synthetic-intent-1",
    decisionId: "synthetic-decision-1",
    dossierId: dossier,
    recordedAt: new Date(NOW).toISOString(),
    expiresAt: NOW + ATTEMPT_TTL_MS,
  };
}

describe("MemoryAttemptStore", () => {
  it("remembers an attempt until it expires, and forgets it only for its own request", () => {
    let now = NOW;
    const store = new MemoryAttemptStore(() => now);
    expect(store.record(KEY, attempt())).toBe(true);
    expect(store.find(KEY)?.dossierId).toBe("synthetic-dossier-1");
    store.forget(KEY, `sha256:${"b".repeat(64)}`);
    expect(store.find(KEY)).toBeDefined();
    store.forget(KEY, `sha256:${"a".repeat(64)}`);
    expect(store.find(KEY)).toBeUndefined();
    store.record(KEY, attempt());
    now = NOW + ATTEMPT_TTL_MS;
    expect(store.find(KEY)).toBeUndefined();
  });

  it("refuses a new key past capacity, and still replaces one it has", () => {
    const store = new MemoryAttemptStore(() => NOW);
    for (let index = 0; index < MAX_ATTEMPTS; index += 1) store.record(`k-${index}`, attempt());
    expect(store.record("one-more", attempt())).toBe(false);
    expect(store.record("k-0", attempt(undefined, "synthetic-dossier-2"))).toBe(true);
    expect(store.find("k-0")?.dossierId).toBe("synthetic-dossier-2");
  });
});

describe("FileAttemptStore", () => {
  it("is read by another replica and after a restart, beside the holds and not among them", () => {
    const dir = join(root, "shared");
    const key = keyFile("shared");
    const holds = new FileHoldStore(dir, key, SCOPE, () => NOW);
    const first = new FileAttemptStore(dir, key, SCOPE, () => NOW);
    expect(first.record(KEY, attempt())).toBe(true);
    first.close();
    const second = new FileAttemptStore(dir, key, SCOPE, () => NOW);
    expect(second.find(KEY)).toEqual(attempt());
    expect(second.sweep()).toBe(1);
    // The reservation key a retry reserves under travels with the record.
    const reserved = { ...attempt(), reservationKey: `agentsafe:${"e".repeat(64)}` };
    expect(first.record(KEY, reserved)).toBe(true);
    expect(second.find(KEY)).toEqual(reserved);
    // The hold store's sweep counts holds only, and leaves the records alone.
    expect(holds.sweep()).toBe(0);
    expect(second.find(KEY)).toBeDefined();
  });

  it("writes neither the idempotency key nor its digest in the clear", () => {
    const dir = join(root, "sealed");
    const store = new FileAttemptStore(dir, keyFile("sealed"), SCOPE, () => NOW);
    store.record(KEY, attempt());
    const names = readdirSync(join(dir, ATTEMPT_DIRECTORY));
    expect(names).toHaveLength(1);
    expect(names[0]).toMatch(/^[0-9a-f]{64}\.attempt$/);
    const text = readFileSync(join(dir, ATTEMPT_DIRECTORY, names[0]!), "utf8");
    expect(text).not.toContain(KEY);
    expect(text).not.toContain("synthetic-dossier-1");
    expect(text).not.toContain("a".repeat(64));
  });

  it("forgets an expired record and removes its file", () => {
    let now = NOW;
    const dir = join(root, "expiry");
    const store = new FileAttemptStore(dir, keyFile("expiry"), SCOPE, () => now);
    store.record(KEY, attempt());
    now = NOW + ATTEMPT_TTL_MS;
    expect(store.find(KEY)).toBeUndefined();
    expect(readdirSync(join(dir, ATTEMPT_DIRECTORY))).toEqual([]);
  });

  it("opens nothing that was altered, sealed under another key, or made for another tenant", () => {
    const key = keyFile("tamper");
    const dir = join(root, "tamper");
    const store = new FileAttemptStore(dir, key, SCOPE, () => NOW);
    store.record(KEY, attempt());
    const [name] = readdirSync(join(dir, ATTEMPT_DIRECTORY));
    const path = join(dir, ATTEMPT_DIRECTORY, name!);
    const sealed = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;

    // Another key, same directory: does not open.
    const otherKey = new FileAttemptStore(dir, keyFile("tamper-other"), SCOPE, () => NOW);
    expect(otherKey.find(KEY)).toBeUndefined();

    // A longer life written in the clear: the sealed one disagrees.
    store.record(KEY, attempt());
    writeFileSync(path, JSON.stringify({ ...sealed, expiresAt: NOW + 2 * ATTEMPT_TTL_MS }));
    expect(store.find(KEY)).toBeUndefined();

    // One flipped byte of the ciphertext.
    store.record(KEY, attempt());
    const fresh = JSON.parse(readFileSync(path, "utf8")) as { data: string };
    const bytes = Buffer.from(fresh.data, "base64url");
    bytes[0] = bytes[0]! ^ 1;
    writeFileSync(path, JSON.stringify({ ...fresh, data: bytes.toString("base64url") }));
    expect(store.find(KEY)).toBeUndefined();

    // Another tenant with the same key and directory finds no file under its
    // own name, and a file copied under that name does not open.
    store.record(KEY, attempt());
    const other = new FileAttemptStore(dir, key, OTHER_SCOPE, () => NOW);
    expect(other.find(KEY)).toBeUndefined();
    other.record(KEY, attempt());
    const otherName = readdirSync(join(dir, ATTEMPT_DIRECTORY)).find((entry) => entry !== name)!;
    copyFileSync(path, join(dir, ATTEMPT_DIRECTORY, otherName));
    expect(other.find(KEY)).toBeUndefined();
    expect(store.find(KEY)).toBeDefined();
  });

  it("keeps one whole record when replicas write the same key at once", async () => {
    const dir = join(root, "race");
    const key = keyFile("race");
    const replicas = Array.from(
      { length: 4 },
      () => new FileAttemptStore(dir, key, SCOPE, () => NOW),
    );
    const written = await Promise.all(
      replicas.map(
        (store, index) =>
          new Promise<boolean>((resolve) =>
            setImmediate(() =>
              resolve(store.record(KEY, attempt(undefined, `synthetic-dossier-${index}`))),
            ),
          ),
      ),
    );
    expect(written).toEqual([true, true, true, true]);
    const seen = replicas.map((store) => store.find(KEY)?.dossierId);
    expect(new Set(seen).size).toBe(1);
    expect(seen[0]).toMatch(/^synthetic-dossier-[0-3]$/);
    expect(readdirSync(join(dir, ATTEMPT_DIRECTORY))).toHaveLength(1);
  });
});
