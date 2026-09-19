/**
 * The offline half of Agent-Safe Intent conformance: given a vector from the
 * corpus under `conformance/`, or a binding another implementation produced,
 * recompute the canonical bytes and the hash with this runtime's own
 * canonicalizer and say whether they agree. Two kinds of vector exist. A
 * `binding` vector holds a whole `agent-safe.intent/1` binding, which must
 * also parse under the strict schema, and may carry `mutations`: single-field
 * changes that must each hash differently from the base and from one
 * another, which is the Compromised Principal requirement. A `canonical`
 * vector holds any JSON object and pins only the bytes and the digest, which
 * is how the Unicode, number and key-order cases are stated. A document with
 * no expected hash is a binding to describe: its canonical bytes and hash are
 * computed and returned, so an implementer can compare them with theirs.
 */
import { createHash } from "node:crypto";
import {
  AuthorityIntentBindingSchema,
  CanonicalIntentHasher,
  type JsonValue,
} from "@decionis/agent-safe-pipeline";

export const INTENT_PROTOCOL = "agent-safe.intent/1";

export type IntentVectorFindingCode =
  | "DOCUMENT_UNRECOGNISED"
  | "BINDING_INVALID"
  | "CANONICAL_MISMATCH"
  | "HASH_MISMATCH"
  | "MUTATION_INVALID"
  | "MUTATION_CANONICAL_MISMATCH"
  | "MUTATION_HASH_MISMATCH"
  | "MUTATION_NOT_DISTINCT"
  | "MUTATION_PATH_UNCHANGED";

export interface IntentVectorFinding {
  readonly code: IntentVectorFindingCode;
  /** The mutation's path, or the schema path that failed; null for the base. */
  readonly path: string | null;
  readonly expected: string | null;
  readonly computed: string | null;
}

export interface IntentVectorReport {
  readonly protocol: typeof INTENT_PROTOCOL;
  /** `binding` for a whole intent binding, `canonical` for a bytes-and-digest case. */
  readonly kind: "binding" | "canonical" | "unrecognised";
  readonly ok: boolean;
  /** Whether the document stated a hash to reproduce, or only asked for one. */
  readonly pinned: boolean;
  readonly canonical_json: string | null;
  readonly intent_hash: string | null;
  /** Mutations the document carried, and how many distinct hashes the whole vector came to. */
  readonly mutations: number;
  readonly hashes: number;
  readonly findings: readonly IntentVectorFinding[];
}

const hasher = new CanonicalIntentHasher();

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function digest(canonical: string): string {
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

/** The value at a dotted path, or undefined; arrays are not addressed. */
function valueAt(value: unknown, path: string): unknown {
  let current: unknown = value;
  for (const key of path.split(".")) {
    if (!isObject(current)) return undefined;
    current = current[key];
  }
  return current;
}

/** Canonical bytes and hash of a bounded JSON object; null when it is not one. */
function canonicalize(value: unknown): { canonical: string; hash: string } | null {
  if (!isObject(value)) return null;
  try {
    hasher.assertInputBounded(value);
    const canonical = CanonicalIntentHasher.stringify(value as JsonValue);
    return { canonical, hash: digest(canonical) };
  } catch {
    return null;
  }
}

function schemaFinding(
  binding: unknown,
  code: "BINDING_INVALID" | "MUTATION_INVALID",
  path: string | null,
): IntentVectorFinding | null {
  const result = AuthorityIntentBindingSchema.safeParse(binding);
  if (result.success) return null;
  const issue = result.error.issues[0];
  const segments = issue === undefined ? [] : issue.path.map(String);
  // A key the schema does not name is reported by that name, not by its parent.
  if (issue?.code === "unrecognized_keys") segments.push(...issue.keys);
  const at = segments.join(".");
  return {
    code,
    path: path === null ? (at === "" ? null : at) : `${path}${at === "" ? "" : ` (${at})`}`,
    expected: issue?.code ?? null,
    computed: null,
  };
}

export function verifyIntentVector(document: unknown): IntentVectorReport {
  const unrecognised: IntentVectorReport = {
    protocol: INTENT_PROTOCOL,
    kind: "unrecognised",
    ok: false,
    pinned: false,
    canonical_json: null,
    intent_hash: null,
    mutations: 0,
    hashes: 0,
    findings: [{ code: "DOCUMENT_UNRECOGNISED", path: null, expected: null, computed: null }],
  };
  if (!isObject(document)) return unrecognised;
  // A vector wraps its binding; a bare binding is the document itself.
  const wrapped = isObject(document["binding"]);
  const binding = wrapped ? document["binding"] : document;
  if (!isObject(binding)) return unrecognised;
  const kind = binding["protocol_version"] === INTENT_PROTOCOL ? "binding" : "canonical";
  if (!wrapped && kind !== "binding") return unrecognised;
  const findings: IntentVectorFinding[] = [];
  const base = canonicalize(binding);
  if (base === null) {
    findings.push({
      code: "BINDING_INVALID",
      path: null,
      expected: "bounded JSON object",
      computed: null,
    });
    return { ...unrecognised, kind, findings };
  }
  if (kind === "binding") {
    const finding = schemaFinding(binding, "BINDING_INVALID", null);
    if (finding !== null) findings.push(finding);
  }
  const expectedCanonical = wrapped ? document["canonical_json"] : undefined;
  const expectedHash = wrapped ? document["intent_hash"] : undefined;
  const pinned = typeof expectedHash === "string";
  if (typeof expectedCanonical === "string" && expectedCanonical !== base.canonical) {
    findings.push({
      code: "CANONICAL_MISMATCH",
      path: null,
      expected: expectedCanonical,
      computed: base.canonical,
    });
  }
  if (pinned && expectedHash !== base.hash) {
    findings.push({
      code: "HASH_MISMATCH",
      path: null,
      expected: expectedHash,
      computed: base.hash,
    });
  }
  const hashes = new Set([base.hash]);
  const mutations = wrapped && Array.isArray(document["mutations"]) ? document["mutations"] : [];
  for (const [index, mutation] of mutations.entries()) {
    const label =
      isObject(mutation) && typeof mutation["path"] === "string"
        ? mutation["path"]
        : `#${String(index)}`;
    const mutated = isObject(mutation) ? canonicalize(mutation["binding"]) : null;
    if (!isObject(mutation) || mutated === null || typeof mutation["intent_hash"] !== "string") {
      findings.push({ code: "MUTATION_INVALID", path: label, expected: null, computed: null });
      continue;
    }
    if (kind === "binding") {
      const finding = schemaFinding(mutation["binding"], "MUTATION_INVALID", label);
      if (finding !== null) findings.push(finding);
    }
    if (
      typeof mutation["canonical_json"] === "string" &&
      mutation["canonical_json"] !== mutated.canonical
    ) {
      findings.push({
        code: "MUTATION_CANONICAL_MISMATCH",
        path: label,
        expected: mutation["canonical_json"],
        computed: mutated.canonical,
      });
    }
    if (mutation["intent_hash"] !== mutated.hash) {
      findings.push({
        code: "MUTATION_HASH_MISMATCH",
        path: label,
        expected: mutation["intent_hash"],
        computed: mutated.hash,
      });
    }
    if (hashes.has(mutated.hash)) {
      findings.push({
        code: "MUTATION_NOT_DISTINCT",
        path: label,
        expected: null,
        computed: mutated.hash,
      });
    }
    hashes.add(mutated.hash);
    // The mutation must be what it says it is: the named field differs from the base.
    if (
      typeof mutation["path"] === "string" &&
      JSON.stringify(valueAt(mutation["binding"], mutation["path"])) ===
        JSON.stringify(valueAt(binding, mutation["path"]))
    ) {
      findings.push({
        code: "MUTATION_PATH_UNCHANGED",
        path: label,
        expected: null,
        computed: null,
      });
    }
  }
  return {
    protocol: INTENT_PROTOCOL,
    kind,
    ok: findings.length === 0,
    pinned,
    canonical_json: base.canonical,
    intent_hash: base.hash,
    mutations: mutations.length,
    hashes: hashes.size,
    findings,
  };
}
