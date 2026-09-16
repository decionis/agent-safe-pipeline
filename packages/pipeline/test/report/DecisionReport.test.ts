import { describe, expect, it } from "vitest";
import type { GateDecision, HostedEvaluation } from "../../src/decision/DecisionAuthority.js";
import { immutableGateDecision } from "../../src/decision/ImmutableGateDecision.js";
import { printDecision } from "../../src/report/DecisionReport.js";

const INTENT_HASH = `sha256:${"b".repeat(64)}`;

function decision(overrides: Partial<GateDecision> = {}): GateDecision {
  return immutableGateDecision({
    verdict: "BLOCK",
    decisionId: "fixture_decision",
    dossierId: "fixture_dossier",
    intentHash: INTENT_HASH,
    reasonCodes: ["FIXTURE_BLOCK"],
    authorization: null,
    failClosed: false,
    ...overrides,
  });
}

function hosted(overrides: Partial<HostedEvaluation> = {}): HostedEvaluation {
  return {
    mode: "SHADOW",
    governs: false,
    verdict: "ALLOW",
    decisionId: "synthetic-decision-1",
    dossierId: "synthetic-dossier-1",
    reasonCodes: ["POLICY_ALLOW"],
    failClosed: false,
    ...overrides,
  };
}

function sink() {
  const chunks: string[] = [];
  return { chunks, out: { write: (chunk: string) => chunks.push(chunk) } };
}

describe("printDecision", () => {
  it("prints nothing for a decision no hosted gate took part in", () => {
    const { chunks, out } = sink();
    printDecision(decision(), { out });
    expect(chunks).toEqual([]);
  });

  it("prints the hosted verdict, the record, and how to verify it", () => {
    const { chunks, out } = sink();
    printDecision(decision({ hosted: hosted() }), { out });
    expect(chunks.join("")).toBe(
      [
        "verdict: BLOCK",
        "decionis: ALLOW (SHADOW, recorded beside the local verdict)",
        "  - POLICY_ALLOW",
        "dossier: synthetic-dossier-1",
        "verify it yourself, no account needed: pnpm decionis:verify synthetic-dossier-1",
        "",
      ].join("\n"),
    );
  });

  it("says when the hosted decision governed, and when it failed closed with no record", () => {
    const governed = sink();
    printDecision(
      decision({
        verdict: "ALLOW",
        hosted: hosted({ mode: "ENFORCEMENT", governs: true, reasonCodes: [] }),
      }),
      { out: governed.out },
    );
    expect(governed.chunks.join("")).toBe(
      [
        "verdict: ALLOW",
        "decionis: ALLOW (ENFORCEMENT, governs)",
        "dossier: synthetic-dossier-1",
        "verify it yourself, no account needed: pnpm decionis:verify synthetic-dossier-1",
        "",
      ].join("\n"),
    );

    const failed = sink();
    printDecision(
      decision({
        hosted: hosted({
          verdict: "BLOCK",
          failClosed: true,
          dossierId: null,
          reasonCodes: ["AUTHORITY_REQUEST_FAILED"],
        }),
      }),
      { out: failed.out },
    );
    expect(failed.chunks.join("")).toBe(
      [
        "verdict: BLOCK",
        "decionis: BLOCK (SHADOW, failed closed)",
        "  - AUTHORITY_REQUEST_FAILED",
        "dossier: none",
        "",
      ].join("\n"),
    );
  });

  it("keeps the record of an evidence-bearing refusal, and takes a caller's verify command", () => {
    const { chunks, out } = sink();
    printDecision(
      decision({
        hosted: hosted({
          verdict: "BLOCK",
          failClosed: true,
          reasonCodes: ["AUTHORITY_STORE_UNAVAILABLE"],
        }),
      }),
      { out, verifyCommand: (id) => `decionis-verify --file ${id}.json` },
    );
    expect(chunks.join("")).toContain("decionis: BLOCK (SHADOW, failed closed)\n");
    expect(chunks.join("")).toContain(
      "verify it yourself, no account needed: decionis-verify --file synthetic-dossier-1.json\n",
    );
  });

  it("writes to stdout by default", () => {
    const written: string[] = [];
    const original = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      written.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      printDecision(decision({ hosted: hosted() }));
    } finally {
      process.stdout.write = original;
    }
    const text = written.join("");
    expect(text.startsWith("verdict: BLOCK\n")).toBe(true);
    expect(text.endsWith("pnpm decionis:verify synthetic-dossier-1\n")).toBe(true);
  });
});
