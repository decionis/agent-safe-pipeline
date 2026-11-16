import { randomBytes } from "node:crypto";
import {
  copyFileSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  FileHoldStore,
  HoldStoreError,
  MAX_HELD,
  MemoryHoldStore,
  type HeldEscalation,
} from "../../src/gateway/HoldStore.js";

const NOW = Date.parse("2026-11-16T12:00:00.000Z");
const SCOPE = "00000000-0000-4000-8000-000000000009";
const OTHER_SCOPE = "00000000-0000-4000-8000-000000000010";
const SECRET_BODY = '{"amount":500,"note":"fixture-hold-body-marker"}';

const root = mkdtempSync(join(tmpdir(), "agentsafe-holds-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

function keyFile(name: string, key: Buffer = randomBytes(32)): string {
  const path = join(root, `${name}.key`);
  writeFileSync(path, `${key.toString("base64url")}\n`, { mode: 0o600 });
  return path;
}

function held(intentId: string, expiresAt = NOW + 60_000): HeldEscalation {
  return {
    captured: {
      intent: { intentId, expiresAt: new Date(expiresAt).toISOString() } as never,
      canonicalIntent: "{}",
      intentHash: `sha256:${"a".repeat(64)}`,
      byteLength: 2,
    },
    request: {
      method: "POST",
      path: "/payments",
      search: "",
      headers: { "content-type": "application/json", "idempotency-key": "pay-held" },
      body: Buffer.from(SECRET_BODY, "utf8"),
      remoteAddress: "127.0.0.1",
      encrypted: true,
    },
    decision: {
      verdict: "ESCALATE",
      decisionId: "synthetic-decision-1",
      dossierId: "synthetic-dossier-1",
      intentHash: `sha256:${"a".repeat(64)}`,
      reasonCodes: ["ESCALATION_REQUIRED"],
      authorization: null,
      failClosed: false,
    },
    handoff: null,
    heldAt: new Date(NOW).toISOString(),
    expiresAt,
    resumeDigest: Buffer.alloc(32, 7),
  };
}

describe("MemoryHoldStore", () => {
  it("holds, expires and gives a hold to one claimant", () => {
    let now = NOW;
    const store = new MemoryHoldStore(() => now);
    expect(store.put("i-1", held("i-1"))).toBe(true);
    expect(store.get("i-1")?.decision.decisionId).toBe("synthetic-decision-1");
    expect(store.claim("i-1")).toBeDefined();
    expect(store.claim("i-1")).toBeUndefined();
    store.put("i-2", held("i-2"));
    now = NOW + 60_000;
    expect(store.get("i-2")).toBeUndefined();
    expect(store.sweep()).toBe(0);
  });

  it("refuses a hold past capacity rather than dropping one", () => {
    const store = new MemoryHoldStore(() => NOW);
    for (let index = 0; index < MAX_HELD; index += 1) store.put(`i-${index}`, held(`i-${index}`));
    expect(store.put("one-more", held("one-more"))).toBe(false);
    expect(store.get("i-0")).toBeDefined();
  });
});

describe("FileHoldStore", () => {
  it("lets another replica, or a restarted one, read and resume a hold", () => {
    const dir = join(root, "shared");
    const key = keyFile("shared");
    const first = new FileHoldStore(dir, key, SCOPE, () => NOW);
    expect(first.put("i-1", held("i-1"))).toBe(true);
    first.close();
    const second = new FileHoldStore(dir, key, SCOPE, () => NOW);
    const read = second.get("i-1");
    expect(read?.request.body.toString("utf8")).toBe(SECRET_BODY);
    expect(read?.resumeDigest.equals(Buffer.alloc(32, 7))).toBe(true);
    expect(read?.request.headers["idempotency-key"]).toBe("pay-held");
    expect(second.sweep()).toBe(1);
  });

  it("gives a hold to exactly one claimant across replicas", () => {
    const dir = join(root, "claim");
    const key = keyFile("claim");
    const a = new FileHoldStore(dir, key, SCOPE, () => NOW);
    const b = new FileHoldStore(dir, key, SCOPE, () => NOW);
    a.put("i-1", held("i-1"));
    const claims = [b.claim("i-1"), a.claim("i-1"), b.claim("i-1")];
    expect(claims.filter((claim) => claim !== undefined)).toHaveLength(1);
    expect(a.get("i-1")).toBeUndefined();
    expect(readdirSync(dir)).toEqual([]);
  });

  it("writes no plaintext and names files by digest, not by intent id", () => {
    const dir = join(root, "sealed");
    const store = new FileHoldStore(dir, keyFile("sealed"), SCOPE, () => NOW);
    store.put("fixture-intent-visible-id", held("fixture-intent-visible-id"));
    const [name] = readdirSync(dir);
    expect(name).toMatch(/^[0-9a-f]{64}\.hold$/);
    const text = readFileSync(join(dir, name!), "utf8");
    expect(text).not.toContain("fixture-hold-body-marker");
    expect(text).not.toContain("pay-held");
    expect(text).not.toContain("fixture-intent-visible-id");
    expect(text).not.toContain("synthetic-decision-1");
  });

  it("opens nothing under the wrong key", () => {
    const dir = join(root, "wrong-key");
    new FileHoldStore(dir, keyFile("right"), SCOPE, () => NOW).put("i-1", held("i-1"));
    const wrong = new FileHoldStore(dir, keyFile("wrong"), SCOPE, () => NOW);
    expect(wrong.get("i-1")).toBeUndefined();
    // What does not open is removed: nobody can resume it.
    expect(readdirSync(dir)).toEqual([]);
  });

  it("opens nothing with a changed byte or a moved expiry", () => {
    for (const change of ["data", "expiresAt"] as const) {
      const dir = join(root, `tampered-${change}`);
      const store = new FileHoldStore(dir, keyFile(`tampered-${change}`), SCOPE, () => NOW);
      store.put("i-1", held("i-1"));
      const [name] = readdirSync(dir);
      const path = join(dir, name!);
      const sealed = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
      const data = String(sealed["data"]);
      const forged =
        change === "data"
          ? { ...sealed, data: `${data[0] === "A" ? "B" : "A"}${data.slice(1)}` }
          : { ...sealed, expiresAt: Number(sealed["expiresAt"]) + 86_400_000 };
      writeFileSync(path, JSON.stringify(forged));
      expect(store.get("i-1"), change).toBeUndefined();
    }
  });

  it("does not open one intent's hold under another intent's name", () => {
    const dir = join(root, "renamed");
    const store = new FileHoldStore(dir, keyFile("renamed"), SCOPE, () => NOW);
    store.put("i-1", held("i-1"));
    const [first] = readdirSync(dir);
    store.put("i-2", held("i-2"));
    const second = readdirSync(dir).find((name) => name !== first)!;
    copyFileSync(join(dir, first!), join(dir, second));
    expect(store.get("i-2")).toBeUndefined();
    expect(store.get("i-1")?.captured.intent.intentId).toBe("i-1");
  });

  it("removes expired holds, and orphans a crashed claim left behind", () => {
    let now = NOW;
    const dir = join(root, "expiry");
    const store = new FileHoldStore(dir, keyFile("expiry"), SCOPE, () => now);
    store.put("i-1", held("i-1", NOW + 1_000));
    store.put("i-2", held("i-2", NOW + 120_000));
    const orphan = join(dir, "0".repeat(64) + ".hold.abc123.claimed");
    writeFileSync(orphan, "{}");
    utimesSync(orphan, new Date(NOW - 3_600_000), new Date(NOW - 3_600_000));
    now = NOW + 2_000;
    expect(store.sweep()).toBe(1);
    expect(store.get("i-1")).toBeUndefined();
    expect(store.get("i-2")).toBeDefined();
    expect(readdirSync(dir).some((name) => name.endsWith(".claimed"))).toBe(false);
  });

  it("refuses a key that is missing or not 32 bytes, by code", () => {
    const dir = join(root, "keys");
    expect(() => new FileHoldStore(dir, join(root, "absent.key"), SCOPE, () => NOW)).toThrow(
      new HoldStoreError("HOLD_KEY_UNREADABLE"),
    );
    expect(
      () => new FileHoldStore(dir, keyFile("short", randomBytes(16)), SCOPE, () => NOW),
    ).toThrow(new HoldStoreError("HOLD_KEY_INVALID"));
    const hex = join(root, "hex.key");
    writeFileSync(hex, randomBytes(32).toString("hex"));
    expect(() => new FileHoldStore(dir, hex, SCOPE, () => NOW)).not.toThrow();
  });
});

describe("FileHoldStore across tenants", () => {
  it("does not open a hold copied into another tenant's place", () => {
    const dir = join(root, "tenants");
    const key = keyFile("tenants");
    const acme = new FileHoldStore(dir, key, SCOPE, () => NOW);
    const other = new FileHoldStore(dir, key, OTHER_SCOPE, () => NOW);
    acme.put("i-1", held("i-1"));
    const [name] = readdirSync(dir);
    // Where the other tenant would look for the same intent id.
    other.put("i-probe", held("i-probe"));
    const probe = readdirSync(dir).find((entry) => entry !== name)!;
    rmSync(join(dir, probe));
    other.put("i-1", held("i-1"));
    const otherName = readdirSync(dir).find((entry) => entry !== name)!;
    copyFileSync(join(dir, name!), join(dir, otherName));
    expect(other.get("i-1")).toBeUndefined();
    expect(acme.get("i-1")).toBeDefined();
  });
});
