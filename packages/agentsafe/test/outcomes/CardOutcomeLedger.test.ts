import {
  appendFileSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { InMemoryCardOutcomeLedger } from "../../src/outcomes/CardOutcomeLedger.js";
import { FileCardOutcomeLedger, MAX_FACT_BYTES } from "../../src/outcomes/FileCardOutcomeLedger.js";
import { at, claimed, decided, settled } from "../support/CardOutcomeFacts.js";

const directory = (): string => mkdtempSync(join(tmpdir(), "agentsafe-card-outcomes-"));
const T0 = new Date(Date.parse(at(0)));

describe("the file outcome ledger", () => {
  it("appends each day's facts to that day's file for this replica, private to the process", async () => {
    const dir = directory();
    const ledger = new FileCardOutcomeLedger(join(dir, "outcomes"), { replica: "executor-0" });
    const nextDay = at(86_400);
    await ledger.append([decided(), claimed(), settled({ at: nextDay })]);
    await ledger.append([decided({ intent_id: "7b2d3e4f-5061-4b72-8c83-a4b5c6d7e8f9" })]);
    const files = readdirSync(join(dir, "outcomes")).sort();
    expect(files).toEqual([
      "card-outcomes-2026-10-12.executor-0.jsonl",
      "card-outcomes-2026-10-13.executor-0.jsonl",
    ]);
    expect(statSync(join(dir, "outcomes")).mode & 0o777).toBe(0o700);
    const first = join(dir, "outcomes", files[0] ?? "");
    expect(statSync(first).mode & 0o777).toBe(0o600);
    expect(readFileSync(first, "utf8").trim().split("\n")).toHaveLength(3);
    expect(await ledger.since(T0)).toEqual([
      decided(),
      decided({ intent_id: "7b2d3e4f-5061-4b72-8c83-a4b5c6d7e8f9" }),
      claimed(),
      settled({ at: nextDay }),
    ]);
    // Only the days a read asks for, and only the facts at or after its start.
    expect(await ledger.since(new Date(Date.parse(at(60))))).toEqual([
      claimed(),
      settled({ at: nextDay }),
    ]);
    expect(await ledger.since(new Date(Date.parse(nextDay)))).toEqual([settled({ at: nextDay })]);
  });

  it("reads every replica's files in one directory as one ledger, ordered by time", async () => {
    const dir = directory();
    const holding = new FileCardOutcomeLedger(dir, { replica: "executor-0" });
    const claiming = new FileCardOutcomeLedger(dir, { replica: "executor-1" });
    await claiming.append([claimed(), settled()]);
    await holding.append([decided()]);
    expect((await holding.since(T0)).map((fact) => fact.kind)).toEqual([
      "DECIDED",
      "CLAIMED",
      "SETTLED",
    ]);
    expect(readdirSync(dir).sort()).toEqual([
      "card-outcomes-2026-10-12.executor-0.jsonl",
      "card-outcomes-2026-10-12.executor-1.jsonl",
    ]);
  });

  it("skips what is not a fact, and leaves alone files that are not its own", async () => {
    const dir = directory();
    const ledger = new FileCardOutcomeLedger(dir, { replica: "executor-0" });
    await ledger.append([decided()]);
    const file = join(dir, "card-outcomes-2026-10-12.executor-0.jsonl");
    appendFileSync(
      file,
      [
        "not json",
        JSON.stringify({ kind: "DECIDED" }),
        JSON.stringify({ ...claimed(), card_token_ref: "fixture_card_ref_1" }),
        `{"padding":"${"x".repeat(MAX_FACT_BYTES)}"}`,
        "",
      ].join("\n"),
    );
    writeFileSync(join(dir, "notes.txt"), JSON.stringify(claimed()));
    writeFileSync(join(dir, "card-outcomes-2026-10-12.UPPER.jsonl"), JSON.stringify(claimed()));
    expect(await ledger.since(T0)).toEqual([decided()]);
  });

  it("refuses a fact it cannot keep as one, a directory it cannot use, and a link where its file should be", async () => {
    const dir = directory();
    const ledger = new FileCardOutcomeLedger(dir, { replica: "executor-0" });
    await expect(
      ledger.append([{ ...decided(), card_token_ref: "fixture_card_ref_1" } as never]),
    ).rejects.toThrow("CARD_OUTCOMES_FACT_INVALID");
    // The largest fact the schema allows is still one line a read takes.
    const largest = decided({ reason_codes: Array.from({ length: 50 }, () => "R".repeat(200)) });
    await ledger.append([largest]);
    expect(JSON.stringify(largest).length).toBeLessThan(MAX_FACT_BYTES);
    expect(await ledger.since(T0)).toEqual([largest]);
    const plain = join(dir, "plain-file");
    writeFileSync(plain, "");
    expect(() => new FileCardOutcomeLedger(plain)).toThrow("CARD_OUTCOMES_DIRECTORY_UNUSABLE");
    const target = join(dir, "elsewhere.jsonl");
    writeFileSync(target, "");
    symlinkSync(target, join(dir, "card-outcomes-2026-10-12.linked.jsonl"));
    const linked = new FileCardOutcomeLedger(dir, { replica: "linked" });
    await expect(linked.append([decided()])).rejects.toThrow("CARD_OUTCOMES_UNWRITABLE");
    expect(readFileSync(target, "utf8")).toBe("");
    const gone = new FileCardOutcomeLedger(join(dir, "gone"));
    rmSync(join(dir, "gone"), { recursive: true });
    await expect(gone.since(T0)).rejects.toThrow("CARD_OUTCOMES_UNREADABLE");
  });

  it("names a replica's files by what a file may carry", () => {
    expect(FileCardOutcomeLedger.replicaName("agent-safe-executor-7d9f-x2")).toBe(
      "agent-safe-executor-7d9f-x2",
    );
    expect(FileCardOutcomeLedger.replicaName("Executor_0.Bank.Example")).toBe(
      "executor-0-bank-example",
    );
    expect(FileCardOutcomeLedger.replicaName("--..--")).toBe("local");
    expect(FileCardOutcomeLedger.replicaName("é")).toBe("local");
    expect(FileCardOutcomeLedger.replicaName("a".repeat(100))).toHaveLength(63);
    expect(new FileCardOutcomeLedger(directory())).toBeInstanceOf(FileCardOutcomeLedger);
  });
});

describe("the in-memory outcome ledger", () => {
  it("keeps facts in order and reads them from a time on", async () => {
    const ledger = new InMemoryCardOutcomeLedger();
    await ledger.append([settled(), decided()]);
    await ledger.append([claimed()]);
    expect(ledger.all.map((fact) => fact.kind)).toEqual(["SETTLED", "DECIDED", "CLAIMED"]);
    expect((await ledger.since(T0)).map((fact) => fact.kind)).toEqual([
      "DECIDED",
      "CLAIMED",
      "SETTLED",
    ]);
    expect(await ledger.since(new Date(Date.parse(at(91))))).toEqual([settled()]);
  });
});
