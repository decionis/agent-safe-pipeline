import { randomBytes } from "node:crypto";
import { readFile, rename, unlink, writeFile } from "node:fs/promises";
import { z } from "zod";
import {
  OutcomeEvidenceSchema,
  type OutcomeEvidence,
  type OutcomeEvidenceDraft,
} from "./OutcomeEvidence.js";

/** The highest revision Core accepts for one subject. */
export const OUTCOME_EVIDENCE_MAX_REVISION = 10_000;
export const OUTCOME_STATE_VERSION = "agent-safe.card-outcomes-state/1" as const;

/** A stated draft and the digest of exactly that content. */
export interface OutcomeEvidenceEntry {
  readonly draft: OutcomeEvidenceDraft;
  readonly sha256: string;
}

export interface OutcomeEvidenceRecordResult {
  /** New subjects (revision 1) and changed ones (the next revision). */
  readonly recorded: number;
  /** Subjects whose evidence was already recorded as it is. */
  readonly unchanged: number;
  /** Changed subjects already at the highest revision: nothing more can be stated for them. */
  readonly exhausted: number;
}

/** A refusal by the store: the code, never a path or a value. */
export class OutcomeEvidenceStoreError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "OutcomeEvidenceStoreError";
  }
}

const SubjectSchema = z.strictObject({
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  revision: z.number().int().min(1).max(OUTCOME_EVIDENCE_MAX_REVISION),
  sent: z.number().int().min(1).max(OUTCOME_EVIDENCE_MAX_REVISION).nullable(),
  evidence: OutcomeEvidenceSchema,
});

const StateSchema = z.strictObject({
  version: z.literal(OUTCOME_STATE_VERSION),
  subjects: z.record(z.string().regex(/^[a-f0-9]{64}$/), SubjectSchema),
});

type Subject = z.infer<typeof SubjectSchema>;

/**
 * What the publisher owes Core, per subject: the evidence at its current revision, the digest of
 * that content, and the revision Core last accepted. A changed draft takes the next revision, an
 * unchanged one is left alone, and only the revision Core accepted is ever marked sent, so the
 * same evidence is never sent twice and a subject's revision rises exactly when it changes.
 *
 * With a file, the whole state is written to a temporary file and renamed over the old one after
 * every change, so a crash leaves the previous state or the next, never half of one. A state
 * file that cannot be read as one is refused rather than replaced: starting again from nothing
 * would restate every subject at revision 1, which Core already holds with other content.
 */
export class OutcomeEvidenceStore {
  private subjects: Map<string, Subject> | null = null;

  /** `file` is where the state persists; null keeps it in memory, for tests. */
  public constructor(private readonly file: string | null = null) {}

  public async record(
    entries: readonly OutcomeEvidenceEntry[],
  ): Promise<OutcomeEvidenceRecordResult> {
    const subjects = await this.load();
    let recorded = 0;
    let unchanged = 0;
    let exhausted = 0;
    for (const { draft, sha256 } of entries) {
      const row = subjects.get(draft.subject_digest);
      if (row === undefined) {
        subjects.set(draft.subject_digest, {
          sha256,
          revision: 1,
          sent: null,
          evidence: { ...draft, revision: 1 },
        });
        recorded += 1;
      } else if (row.sha256 === sha256) {
        unchanged += 1;
      } else if (row.revision >= OUTCOME_EVIDENCE_MAX_REVISION) {
        exhausted += 1;
      } else {
        const revision = row.revision + 1;
        subjects.set(draft.subject_digest, {
          sha256,
          revision,
          sent: row.sent,
          evidence: { ...draft, revision },
        });
        recorded += 1;
      }
    }
    if (recorded > 0) await this.save();
    return { recorded, unchanged, exhausted };
  }

  /** Evidence whose current revision Core has not accepted, oldest action first. */
  public async owed(limit: number): Promise<OutcomeEvidence[]> {
    const subjects = await this.load();
    return [...subjects.values()]
      .filter((row) => row.sent !== row.revision)
      .sort(
        (a, b) =>
          Date.parse(a.evidence.occurred_at) - Date.parse(b.evidence.occurred_at) ||
          a.evidence.subject_digest.localeCompare(b.evidence.subject_digest),
      )
      .slice(0, limit)
      .map((row) => row.evidence);
  }

  /** Core accepted these revisions; a subject that moved on since then stays owed. */
  public async sent(
    items: readonly Pick<OutcomeEvidence, "subject_digest" | "revision">[],
  ): Promise<number> {
    const subjects = await this.load();
    let marked = 0;
    for (const item of items) {
      const row = subjects.get(item.subject_digest);
      if (row === undefined || row.revision !== item.revision) continue;
      row.sent = item.revision;
      marked += 1;
    }
    if (marked > 0) await this.save();
    return marked;
  }

  /**
   * Core holds this subject's revision with other content: the same evidence goes again under
   * the next revision. False when the subject is unknown or has no revision left.
   */
  public async supersede(subjectDigest: string): Promise<boolean> {
    const subjects = await this.load();
    const row = subjects.get(subjectDigest);
    if (row === undefined || row.revision >= OUTCOME_EVIDENCE_MAX_REVISION) return false;
    row.revision += 1;
    row.evidence = { ...row.evidence, revision: row.revision };
    await this.save();
    return true;
  }

  /**
   * Forgets subjects Core holds at their current revision that occurred before `before`: nothing
   * reads their facts any more, so nothing can change them. Owed subjects are kept until sent.
   */
  public async prune(before: Date): Promise<number> {
    const subjects = await this.load();
    const floor = before.getTime();
    let pruned = 0;
    for (const [subject, row] of subjects) {
      if (row.sent === row.revision && Date.parse(row.evidence.occurred_at) < floor) {
        subjects.delete(subject);
        pruned += 1;
      }
    }
    if (pruned > 0) await this.save();
    return pruned;
  }

  private async load(): Promise<Map<string, Subject>> {
    if (this.subjects !== null) return this.subjects;
    if (this.file === null) {
      this.subjects = new Map();
      return this.subjects;
    }
    let text: string | null;
    try {
      text = await readFile(this.file, "utf8");
    } catch (error) {
      if ((error as { readonly code?: unknown }).code !== "ENOENT") {
        throw new OutcomeEvidenceStoreError("CARD_OUTCOMES_STATE_UNREADABLE");
      }
      text = null;
    }
    if (text === null) {
      this.subjects = new Map();
      return this.subjects;
    }
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      throw new OutcomeEvidenceStoreError("CARD_OUTCOMES_STATE_UNREADABLE");
    }
    const parsed = StateSchema.safeParse(value);
    if (!parsed.success) throw new OutcomeEvidenceStoreError("CARD_OUTCOMES_STATE_UNREADABLE");
    this.subjects = new Map(Object.entries(parsed.data.subjects));
    return this.subjects;
  }

  private async save(): Promise<void> {
    if (this.file === null || this.subjects === null) return;
    const state = {
      version: OUTCOME_STATE_VERSION,
      subjects: Object.fromEntries(this.subjects),
    };
    const temporary = `${this.file}.${randomBytes(6).toString("hex")}.tmp`;
    try {
      await writeFile(temporary, `${JSON.stringify(state)}\n`, { mode: 0o600, flag: "wx" });
      await rename(temporary, this.file);
    } catch {
      await unlink(temporary).catch(() => undefined);
      throw new OutcomeEvidenceStoreError("CARD_OUTCOMES_STATE_UNWRITABLE");
    }
  }
}
