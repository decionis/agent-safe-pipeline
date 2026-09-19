import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { CanonicalIntentHasher } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { verifyIntentVector } from "../../src/verify/VerifyIntentVector.js";

const VECTORS_DIR = new URL("../../../../conformance/vectors/", import.meta.url);
const PINNED = new URL("../../../../conformance/agent-safe-intent-v1.json", import.meta.url);

type Json = Record<string, unknown>;

async function vector(name: string): Promise<Json> {
  return JSON.parse(await readFile(new URL(name, VECTORS_DIR), "utf8")) as Json;
}

function codes(document: unknown): string[] {
  return verifyIntentVector(document).findings.map((finding) => finding.code);
}

describe("verifyIntentVector", () => {
  it("reproduces every vector in the corpus, and knows which kind each is", async () => {
    const names = (await readdir(VECTORS_DIR)).filter((name) => name.endsWith(".json"));
    expect(names.length).toBeGreaterThanOrEqual(7);
    for (const name of names) {
      const report = verifyIntentVector(await vector(name));
      expect(report.ok, `${name}: ${JSON.stringify(report.findings)}`).toBe(true);
      expect(report.pinned).toBe(true);
      expect(report.kind).toBe(name === "compromised-principal.json" ? "binding" : "canonical");
    }
    const principal = verifyIntentVector(await vector("compromised-principal.json"));
    expect(principal.mutations).toBe(8);
    expect(principal.hashes).toBe(9);
    const pinned = verifyIntentVector(JSON.parse(await readFile(PINNED, "utf8")));
    expect(pinned).toMatchObject({ kind: "binding", ok: true, pinned: true, hashes: 1 });
  });

  it("computes the bytes and the hash of a bare binding, exactly as the hasher does", async () => {
    const { binding } = await vector("compromised-principal.json");
    const report = verifyIntentVector(binding);
    const canonical = CanonicalIntentHasher.stringify(binding as never);
    expect(report).toMatchObject({
      kind: "binding",
      ok: true,
      pinned: false,
      canonical_json: canonical,
      intent_hash: `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`,
      mutations: 0,
      hashes: 1,
      findings: [],
    });
  });

  it("names a base that does not reproduce", async () => {
    const base = await vector("compromised-principal.json");
    expect(codes({ ...base, intent_hash: `sha256:${"0".repeat(64)}` })).toEqual(["HASH_MISMATCH"]);
    expect(codes({ ...base, canonical_json: "{}" })).toEqual(["CANONICAL_MISMATCH"]);
    const finding = verifyIntentVector({ ...base, intent_hash: `sha256:${"0".repeat(64)}` })
      .findings[0];
    expect(finding?.expected).toBe(`sha256:${"0".repeat(64)}`);
    expect(finding?.computed).toBe(base["intent_hash"]);
  });

  it("holds a whole binding to the strict schema, and says where it failed", async () => {
    const base = await vector("compromised-principal.json");
    const binding = base["binding"] as Json;
    const report = verifyIntentVector({
      ...base,
      binding: { ...binding, actor: { ...(binding["actor"] as Json), badge: "x" } },
    });
    expect(report.kind).toBe("binding");
    expect(report.ok).toBe(false);
    expect(report.findings.map((finding) => [finding.code, finding.path])).toContainEqual([
      "BINDING_INVALID",
      "actor.badge",
    ]);
    // The hash of an invalid binding is still computed and still compared: the
    // vector is wrong twice, and both findings are reported.
    expect(codes({ ...base, binding: { ...binding, extra: 1 } })).toEqual([
      "BINDING_INVALID",
      "CANONICAL_MISMATCH",
      "HASH_MISMATCH",
    ]);
  });

  it("holds every mutation to its claim: distinct, reproduced, and changed where it says", async () => {
    const base = await vector("compromised-principal.json");
    const mutations = base["mutations"] as Json[];
    const first = mutations[0] as Json;
    // A mutation identical to the base hashes like it and changes nothing at its path.
    expect(
      codes({
        ...base,
        mutations: [
          {
            ...first,
            binding: base["binding"],
            canonical_json: base["canonical_json"],
            intent_hash: base["intent_hash"],
          },
        ],
      }),
    ).toEqual(["MUTATION_NOT_DISTINCT", "MUTATION_PATH_UNCHANGED"]);
    // The same mutation listed twice is distinct from the base, not from itself.
    expect(codes({ ...base, mutations: [first, first] })).toEqual(["MUTATION_NOT_DISTINCT"]);
    expect(
      codes({ ...base, mutations: [{ ...first, intent_hash: `sha256:${"1".repeat(64)}` }] }),
    ).toEqual(["MUTATION_HASH_MISMATCH"]);
    expect(codes({ ...base, mutations: [{ ...first, canonical_json: "{}" }] })).toEqual([
      "MUTATION_CANONICAL_MISMATCH",
    ]);
    expect(codes({ ...base, mutations: [{ path: "x", binding: first["binding"] }] })).toEqual([
      "MUTATION_INVALID",
    ]);
    expect(codes({ ...base, mutations: ["not a mutation"] })).toEqual(["MUTATION_INVALID"]);
    const invalidBinding = {
      ...first,
      binding: { ...(first["binding"] as Json), unknown: true },
    };
    expect(codes({ ...base, mutations: [invalidBinding] })).toEqual([
      "MUTATION_INVALID",
      "MUTATION_CANONICAL_MISMATCH",
      "MUTATION_HASH_MISMATCH",
    ]);
    const report = verifyIntentVector({ ...base, mutations: [invalidBinding] });
    expect(report.findings[0]?.path).toBe("action.parameters.replicas (unknown)");
    expect(report.mutations).toBe(1);
  });

  it("refuses what is not an intent document at all", () => {
    for (const document of [null, 7, "text", [], { text: "a" }, { binding: [] }, { binding: 1 }]) {
      const report = verifyIntentVector(document);
      expect(report.kind).toBe("unrecognised");
      expect(report.ok).toBe(false);
      expect(report.findings.map((finding) => finding.code)).toEqual(["DOCUMENT_UNRECOGNISED"]);
    }
  });

  it("refuses a binding it cannot bound, without hashing it", () => {
    let deep: Json = { leaf: true };
    for (let level = 0; level < 30; level += 1) deep = { deep };
    const report = verifyIntentVector({ binding: deep, intent_hash: "sha256:00" });
    expect(report.kind).toBe("canonical");
    expect(report.intent_hash).toBeNull();
    expect(report.findings.map((finding) => finding.code)).toEqual(["BINDING_INVALID"]);
  });
});
