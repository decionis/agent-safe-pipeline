import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
  mkdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { JsonValue } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { CardOutcomeEvidenceProvider } from "../../src/outcomes/CardOutcomeEvidence.js";
import type { CardOutcomeFact } from "../../src/outcomes/CardOutcomeFact.js";
import { outcomeDigest, type OutcomeEvidenceDraft } from "../../src/outcomes/OutcomeEvidence.js";
import {
  OUTCOME_EVIDENCE_MAX_REVISION,
  OutcomeEvidenceStore,
  type OutcomeEvidenceEntry,
} from "../../src/outcomes/OutcomeEvidenceStore.js";
import { at, claimed, decided, settled } from "../support/CardOutcomeFacts.js";

const provider = new CardOutcomeEvidenceProvider();
const LATER = new Date(Date.parse(at(3_600)));

function entry(facts: readonly CardOutcomeFact[], intent: string): OutcomeEvidenceEntry {
  const draft = provider.map(
    facts.map((fact) => ({ ...fact, intent_id: intent })),
    LATER,
  ) as OutcomeEvidenceDraft;
  return { draft, sha256: outcomeDigest(draft as unknown as JsonValue) };
}

const A = "6a1c2d3e-4f50-4a61-8b72-000000000001";
const B = "6a1c2d3e-4f50-4a61-8b72-000000000002";

describe("what the publisher owes Core", () => {
  it("records new and changed subjects at the next revision, and leaves unchanged ones alone", async () => {
    const store = new OutcomeEvidenceStore();
    const held = entry([decided()], A);
    const blocked = entry([decided({ verdict: "BLOCK", at: at(10) })], B);
    expect(await store.record([held, blocked])).toEqual({
      recorded: 2,
      unchanged: 0,
      exhausted: 0,
    });
    expect(await store.record([held])).toEqual({ recorded: 0, unchanged: 1, exhausted: 0 });
    const approved = entry([decided(), claimed(), settled()], A);
    expect(await store.record([approved])).toEqual({ recorded: 1, unchanged: 0, exhausted: 0 });
    const owed = await store.owed(10);
    expect(owed.map((evidence) => evidence.revision)).toEqual([2, 1]);
    expect(owed[0]?.subject_digest).toBe(approved.draft.subject_digest);
    expect(await store.owed(1)).toHaveLength(1);
  });

  it("marks only the revision Core accepted as sent, so a subject that moved on stays owed", async () => {
    const store = new OutcomeEvidenceStore();
    const first = entry([decided()], A);
    await store.record([first]);
    const [sent] = await store.owed(10);
    if (sent === undefined) throw new Error("nothing owed");
    await store.record([entry([decided(), claimed()], A)]);
    expect(await store.sent([sent])).toBe(0);
    expect(await store.owed(10)).toMatchObject([{ revision: 2 }]);
    expect(await store.sent([{ subject_digest: sent.subject_digest, revision: 2 }])).toBe(1);
    expect(await store.owed(10)).toEqual([]);
    expect(await store.sent([{ subject_digest: "f".repeat(64), revision: 1 }])).toBe(0);
    // Unchanged evidence is never owed again.
    expect(await store.record([entry([decided(), claimed()], A)])).toMatchObject({ unchanged: 1 });
    expect(await store.owed(10)).toEqual([]);
  });

  it("restates the same evidence under the next revision when Core holds another under this one", async () => {
    const store = new OutcomeEvidenceStore();
    const first = entry([decided()], A);
    await store.record([first]);
    expect(await store.supersede(first.draft.subject_digest)).toBe(true);
    const [owed] = await store.owed(10);
    expect(owed).toEqual({ ...first.draft, revision: 2 });
    expect(await store.supersede("f".repeat(64))).toBe(false);
  });

  it("stops at the highest revision Core accepts", async () => {
    const store = new OutcomeEvidenceStore();
    const first = entry([decided()], A);
    await store.record([first]);
    for (let revision = 1; revision < OUTCOME_EVIDENCE_MAX_REVISION; revision += 1) {
      await store.supersede(first.draft.subject_digest);
    }
    expect(await store.supersede(first.draft.subject_digest)).toBe(false);
    expect(await store.record([entry([decided(), claimed()], A)])).toEqual({
      recorded: 0,
      unchanged: 0,
      exhausted: 1,
    });
  });

  it("forgets subjects Core holds that occurred before a time, and keeps what is still owed", async () => {
    const store = new OutcomeEvidenceStore();
    const sent = entry([decided()], A);
    await store.record([sent, entry([decided()], B)]);
    await store.sent([{ subject_digest: sent.draft.subject_digest, revision: 1 }]);
    expect(await store.prune(new Date(Date.parse(at(0))))).toBe(0);
    expect(await store.prune(LATER)).toBe(1);
    expect(await store.owed(10)).toHaveLength(1);
    // A forgotten subject stated again starts over at revision 1, as a new one.
    expect(await store.record([sent])).toMatchObject({ recorded: 1 });
  });

  it("persists across a restart, atomically and privately, and refuses a state it cannot read", async () => {
    const dir = mkdtempSync(join(tmpdir(), "agentsafe-outcome-state-"));
    const file = join(dir, "card-outcomes-state.json");
    const store = new OutcomeEvidenceStore(file);
    expect(await store.owed(10)).toEqual([]);
    await store.record([entry([decided()], A)]);
    const [owed] = await store.owed(10);
    if (owed === undefined) throw new Error("nothing owed");
    await store.sent([owed]);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(readdirSync(dir)).toEqual(["card-outcomes-state.json"]);
    expect(JSON.parse(readFileSync(file, "utf8"))).toMatchObject({
      version: "agent-safe.card-outcomes-state/1",
    });

    const restarted = new OutcomeEvidenceStore(file);
    expect(await restarted.owed(10)).toEqual([]);
    expect(await restarted.record([entry([decided()], A)])).toMatchObject({ unchanged: 1 });
    expect(await restarted.record([entry([decided(), claimed()], A)])).toMatchObject({
      recorded: 1,
    });
    expect(await new OutcomeEvidenceStore(file).owed(10)).toMatchObject([{ revision: 2 }]);

    for (const text of ["not json", JSON.stringify({ version: "other", subjects: {} })]) {
      writeFileSync(file, text);
      await expect(new OutcomeEvidenceStore(file).owed(10)).rejects.toThrow(
        "CARD_OUTCOMES_STATE_UNREADABLE",
      );
    }
    const directoryInstead = join(dir, "state-dir");
    mkdirSync(directoryInstead);
    await expect(new OutcomeEvidenceStore(directoryInstead).owed(10)).rejects.toThrow(
      "CARD_OUTCOMES_STATE_UNREADABLE",
    );
    const nowhere = new OutcomeEvidenceStore(join(dir, "missing", "state.json"));
    await expect(nowhere.record([entry([decided()], A)])).rejects.toThrow(
      "CARD_OUTCOMES_STATE_UNWRITABLE",
    );
  });
});
