import { describe, expect, it } from "vitest";
import {
  authorizationsFrom,
  dispatchedUnderFrom,
  IDEMPOTENCY_KEY_DISPATCHED,
  JOURNAL_VERSION,
  JournalError,
  JournalRecordSchema,
  openAttemptsFrom,
  type JournalRecord,
} from "../../src/execution/ExecutionJournal.js";
import {
  DEFAULT_JOURNAL_TABLE,
  PostgresExecutionJournal,
} from "../../src/execution/PostgresExecutionJournal.js";
import type { SqlClient } from "../../src/execution/PostgresReplayStore.js";

const HASH = `sha256:${"a".repeat(64)}`;
const AT = "2026-10-18T09:00:00.000Z";

const opened = (id: string, key = "payout-1"): JournalRecord => ({
  record: "ATTEMPT_OPENED",
  at: AT,
  intent_id: id,
  intent_hash: HASH,
  idempotency_key: key,
  decision_id: `decision-${id}`,
  dossier_id: `dossier-${id}`,
  caller_principal: null,
  intent: { intentId: id },
});

const claimed = (id: string, key = "payout-1", grant = `grant-${id}`): JournalRecord => ({
  record: "GRANT_CLAIMED",
  at: AT,
  intent_id: id,
  intent_hash: HASH,
  idempotency_key: key,
  grant_id: grant,
  expires_at: "2026-10-18T09:01:00.000Z",
  request_digest: HASH,
});

const closed = (id: string): JournalRecord => ({
  record: "ATTEMPT_CLOSED",
  at: AT,
  intent_id: id,
  intent_hash: HASH,
  outcome: "COMPLETED",
  executed: true,
  finalization: "RECORDED",
});

describe("the journal folds", () => {
  it("names its version and refuses a record outside the contract", () => {
    expect(JOURNAL_VERSION).toBe("agent-safe.attempts/1");
    expect(JournalRecordSchema.safeParse({ record: "GRANT_CLAIMED" }).success).toBe(false);
    expect(new JournalError("JOURNAL_WRITE_FAILED")).toMatchObject({
      name: "JournalError",
      code: "JOURNAL_WRITE_FAILED",
    });
  });

  it("keeps an attempt open until it is closed, and claimed once its grant is", () => {
    const open = openAttemptsFrom([opened("a"), claimed("a"), opened("b"), closed("b")]);
    expect(open).toHaveLength(1);
    expect(open[0]).toMatchObject({ intentId: "a", state: "CLAIMED", grantId: "grant-a" });
    expect(openAttemptsFrom([claimed("orphan")])).toEqual([]);
  });

  it("reads back the authorizations an intent was dispatched under", () => {
    expect(authorizationsFrom([opened("a"), claimed("a"), claimed("b")], "a")).toEqual([
      {
        decisionId: "decision-a",
        dossierId: "dossier-a",
        grantId: "grant-a",
        intentHash: HASH,
        expiresAt: "2026-10-18T09:01:00.000Z",
      },
    ]);
  });

  it("finds every claim made under one idempotency key, across intents", () => {
    const records = [
      opened("a"),
      claimed("a"),
      opened("b", "other"),
      claimed("b", "other"),
      opened("c"),
      claimed("c"),
      claimed("unopened"),
    ];
    expect(dispatchedUnderFrom(records, "payout-1").map((entry) => entry.grantId)).toEqual([
      "grant-a",
      "grant-c",
    ]);
    expect(dispatchedUnderFrom(records, "never")).toEqual([]);
  });
});

/** A client with the semantics the journal relies on, the unique claim index included. */
class FakePostgres implements SqlClient {
  public readonly rows: {
    namespace: string;
    intent_id: string;
    record_kind: string;
    idempotency_key: string | null;
    record: string;
  }[] = [];
  public failWith: unknown = null;
  public rawRecords: unknown[] | null = null;

  public async query(
    text: string,
    values: readonly unknown[],
  ): Promise<{ readonly rowCount: number | null; readonly rows?: readonly unknown[] }> {
    await Promise.resolve();
    if (this.failWith !== null) throw this.failWith;
    const namespace = String(values[0]);
    const mine = this.rows.filter((row) => row.namespace === namespace);
    if (text.startsWith("INSERT")) {
      const [, intentId, kind, key, record] = values as [
        string,
        string,
        string,
        string | null,
        string,
      ];
      if (
        kind === "GRANT_CLAIMED" &&
        mine.some((row) => row.record_kind === "GRANT_CLAIMED" && row.idempotency_key === key)
      ) {
        throw Object.assign(new Error("duplicate key"), { code: "23505" });
      }
      this.rows.push({
        namespace,
        intent_id: intentId,
        record_kind: kind,
        idempotency_key: key,
        record,
      });
      return { rowCount: 1 };
    }
    if (this.rawRecords !== null) {
      return {
        rowCount: this.rawRecords.length,
        rows: this.rawRecords.map((record) => ({ record })),
      };
    }
    let selected = mine;
    if (text.includes("EXCEPT")) {
      const closedIds = new Set(
        mine
          .filter((row) => row.record_kind === "ATTEMPT_CLOSED" || row.record_kind === "RECONCILED")
          .map((row) => row.intent_id),
      );
      const openedIds = new Set(
        mine.filter((row) => row.record_kind === "ATTEMPT_OPENED").map((row) => row.intent_id),
      );
      selected = mine.filter(
        (row) => openedIds.has(row.intent_id) && !closedIds.has(row.intent_id),
      );
    } else if (text.includes("idempotency_key = $2")) {
      const ids = new Set(
        mine
          .filter((row) => row.record_kind === "GRANT_CLAIMED" && row.idempotency_key === values[1])
          .map((row) => row.intent_id),
      );
      selected = mine.filter((row) => ids.has(row.intent_id));
    } else if (text.includes("intent_id = $2")) {
      selected = mine.filter((row) => row.intent_id === values[1]);
    } else if (text.includes("LIMIT 0")) {
      return { rowCount: 0, rows: [] };
    }
    // jsonb comes back parsed, as `pg` returns it.
    return {
      rowCount: selected.length,
      rows: selected.map((row) => ({ record: JSON.parse(row.record) as unknown })),
    };
  }
}

describe("PostgresExecutionJournal", () => {
  const journal = (client: SqlClient, namespace = "org-a"): PostgresExecutionJournal =>
    new PostgresExecutionJournal({ client, namespace });

  it("refuses a table or namespace it could not safely name", () => {
    const client = new FakePostgres();
    expect(() => new PostgresExecutionJournal({ client, namespace: "" })).toThrow(
      "JOURNAL_NAMESPACE_INVALID",
    );
    expect(() => new PostgresExecutionJournal({ client, namespace: "x".repeat(201) })).toThrow(
      "JOURNAL_NAMESPACE_INVALID",
    );
    expect(
      () => new PostgresExecutionJournal({ client, namespace: "org", table: "drop table; --" }),
    ).toThrow("JOURNAL_TABLE_INVALID");
    expect(() => PostgresExecutionJournal.schema("Bad Table")).toThrow("JOURNAL_TABLE_INVALID");
  });

  it("publishes the DDL with the unique index that makes a key single-use", () => {
    const ddl = PostgresExecutionJournal.schema();
    expect(ddl).toContain(`CREATE TABLE IF NOT EXISTS ${DEFAULT_JOURNAL_TABLE}`);
    expect(ddl).toContain("WHERE record_kind = 'GRANT_CLAIMED'");
    expect(PostgresExecutionJournal.schema("ops.journal")).toContain("ops_journal_claim_once");
  });

  it("appends records and folds them back exactly as the file journal does", async () => {
    const client = new FakePostgres();
    const store = journal(client);
    await store.append(opened("a"));
    await store.append(claimed("a"));
    await store.append(opened("b", "payout-2"));
    await store.append(claimed("b", "payout-2"));
    await store.append(closed("b"));
    expect((await store.openAttempts()).map((attempt) => attempt.intentId)).toEqual(["a"]);
    expect((await store.authorizationsOf("a")).map((entry) => entry.grantId)).toEqual(["grant-a"]);
    expect((await store.dispatchedUnder("payout-2")).map((entry) => entry.grantId)).toEqual([
      "grant-b",
    ]);
    // Only a claim carries its key into the indexed column.
    expect(client.rows.find((row) => row.record_kind === "ATTEMPT_OPENED")?.idempotency_key).toBe(
      null,
    );
    // Another organisation's journal reads none of it.
    expect(await journal(client, "org-b").openAttempts()).toEqual([]);
    await expect(store.probe()).resolves.toBeUndefined();
    expect(store.close()).toBeUndefined();
  });

  it("refuses the second claim under one key, so two replicas dispatch once", async () => {
    const client = new FakePostgres();
    const first = journal(client);
    const second = journal(client);
    await first.append(opened("a"));
    await second.append(opened("b"));
    await first.append(claimed("a"));
    const refusal = await second.append(claimed("b")).catch((error: unknown) => error);
    expect(refusal).toBeInstanceOf(JournalError);
    expect((refusal as JournalError).code).toBe(IDEMPOTENCY_KEY_DISPATCHED);
    // The code is a wire value the runner and its callers read, not just a constant.
    expect(IDEMPOTENCY_KEY_DISPATCHED).toBe("IDEMPOTENCY_KEY_DISPATCHED");
  });

  it("throws rather than lose a record, and never writes one outside the contract", async () => {
    const client = new FakePostgres();
    const store = journal(client);
    await expect(
      store.append({ record: "NOPE" } as unknown as JournalRecord),
    ).rejects.toMatchObject({
      code: "JOURNAL_RECORD_INVALID",
    });
    client.failWith = new Error("connection terminated");
    await expect(store.append(opened("a"))).rejects.toMatchObject({ code: "JOURNAL_WRITE_FAILED" });
    client.failWith = "not an error object";
    await expect(store.append(opened("a"))).rejects.toMatchObject({ code: "JOURNAL_WRITE_FAILED" });
  });

  it("skips a row that is not a record, as the file journal skips a bad line", async () => {
    const client = new FakePostgres();
    client.rawRecords = [JSON.stringify(opened("a")), "{not json", { record: "NOPE" }, opened("b")];
    expect((await journal(client).openAttempts()).map((attempt) => attempt.intentId)).toEqual([
      "a",
      "b",
    ]);
    client.rawRecords = [];
    expect(await journal(client).authorizationsOf("a")).toEqual([]);
  });
});

describe("PostgresExecutionJournal statements", () => {
  /** A client that records each statement and answers with the rows it is given. */
  class StatementLog implements SqlClient {
    public readonly statements: { readonly text: string; readonly values: readonly unknown[] }[] =
      [];
    public rows: readonly unknown[] | undefined = [];

    public async query(
      text: string,
      values: readonly unknown[],
    ): Promise<{ readonly rowCount: number | null; readonly rows?: readonly unknown[] }> {
      this.statements.push({ text, values });
      return this.rows === undefined
        ? { rowCount: 0 }
        : { rowCount: this.rows.length, rows: this.rows };
    }
  }

  it("publishes exactly this DDL", () => {
    expect(PostgresExecutionJournal.schema()).toBe(
      [
        "CREATE TABLE IF NOT EXISTS agentsafe_execution_journal (",
        "  seq bigserial PRIMARY KEY,",
        "  namespace text NOT NULL,",
        "  intent_id text NOT NULL,",
        "  record_kind text NOT NULL,",
        "  idempotency_key text,",
        "  record jsonb NOT NULL,",
        "  recorded_at timestamptz NOT NULL DEFAULT now()",
        ");",
        "CREATE INDEX IF NOT EXISTS agentsafe_execution_journal_intent ON agentsafe_execution_journal (namespace, intent_id, seq);",
        "CREATE UNIQUE INDEX IF NOT EXISTS agentsafe_execution_journal_claim_once ON agentsafe_execution_journal (namespace, idempotency_key) WHERE record_kind = 'GRANT_CLAIMED';",
        "",
      ].join("\n"),
    );
  });

  it("issues exactly these statements, in its own namespace and table", async () => {
    const client = new StatementLog();
    const journal = new PostgresExecutionJournal({
      client,
      namespace: "n".repeat(200),
      table: "ops.journal",
    });
    await journal.append(claimed("a"));
    await journal.append(opened("a"));
    await journal.openAttempts();
    await journal.authorizationsOf("a");
    await journal.dispatchedUnder("payout-1");
    await journal.probe();
    const n = "n".repeat(200);
    expect(client.statements).toEqual([
      {
        text: "INSERT INTO ops.journal (namespace, intent_id, record_kind, idempotency_key, record) VALUES ($1, $2, $3, $4, $5)",
        values: [n, "a", "GRANT_CLAIMED", "payout-1", JSON.stringify(claimed("a"))],
      },
      {
        text: "INSERT INTO ops.journal (namespace, intent_id, record_kind, idempotency_key, record) VALUES ($1, $2, $3, $4, $5)",
        values: [n, "a", "ATTEMPT_OPENED", null, JSON.stringify(opened("a"))],
      },
      {
        text:
          "SELECT record FROM ops.journal WHERE namespace = $1 AND intent_id IN (" +
          "SELECT intent_id FROM ops.journal WHERE namespace = $1 AND record_kind = 'ATTEMPT_OPENED' " +
          "EXCEPT SELECT intent_id FROM ops.journal WHERE namespace = $1 AND record_kind IN ('ATTEMPT_CLOSED', 'RECONCILED')" +
          ") ORDER BY seq",
        values: [n],
      },
      {
        text: "SELECT record FROM ops.journal WHERE namespace = $1 AND intent_id = $2 ORDER BY seq",
        values: [n, "a"],
      },
      {
        text:
          "SELECT record FROM ops.journal WHERE namespace = $1 AND intent_id IN (" +
          "SELECT intent_id FROM ops.journal WHERE namespace = $1 AND record_kind = 'GRANT_CLAIMED' AND idempotency_key = $2" +
          ") ORDER BY seq",
        values: [n, "payout-1"],
      },
      {
        text: "SELECT seq, namespace, intent_id, record_kind, idempotency_key, record FROM ops.journal LIMIT 0",
        values: [],
      },
    ]);
  });

  it("reads a result with no rows as no records, and reads only what parses", async () => {
    const client = new StatementLog();
    const journal = new PostgresExecutionJournal({ client, namespace: "org" });
    client.rows = undefined;
    expect(await journal.authorizationsOf("a")).toEqual([]);
    client.rows = [{ record: opened("a") }, { record: claimed("a") }];
    expect((await journal.authorizationsOf("a")).map((entry) => entry.grantId)).toEqual([
      "grant-a",
    ]);
  });

  it("refuses a thrown null as a write failure, never as a used key", async () => {
    const client: SqlClient = {
      query: async () => {
        throw null;
      },
    };
    await expect(
      new PostgresExecutionJournal({ client, namespace: "org" }).append(opened("a")),
    ).rejects.toMatchObject({ code: "JOURNAL_WRITE_FAILED" });
    const numeric: SqlClient = {
      query: async () => {
        throw Object.assign(new Error("duplicate"), { code: 23505 });
      },
    };
    await expect(
      new PostgresExecutionJournal({ client: numeric, namespace: "org" }).append(claimed("a")),
    ).rejects.toMatchObject({ code: "JOURNAL_WRITE_FAILED" });
  });
});
