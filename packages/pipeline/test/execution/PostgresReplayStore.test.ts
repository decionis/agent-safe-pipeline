import { describe, expect, it } from "vitest";
import {
  DEFAULT_REPLAY_TABLE,
  PostgresReplayStore,
  type SqlClient,
} from "../../src/execution/PostgresReplayStore.js";

interface Query {
  readonly text: string;
  readonly values: readonly unknown[];
}

/**
 * A client with the semantics the store relies on: a unique key on
 * `(namespace, intent_id)` and `ON CONFLICT DO NOTHING`. Each statement is
 * answered on a later turn, so claims made together really interleave.
 */
class FakePostgres implements SqlClient {
  public readonly queries: Query[] = [];
  public readonly rows = new Map<string, string>();
  public nullRowCount = false;

  public async query(
    text: string,
    values: readonly unknown[],
  ): Promise<{ readonly rowCount: number | null }> {
    this.queries.push({ text, values });
    await new Promise((resolve) => setImmediate(resolve));
    const key = `${String(values[0])}\u0000${String(values[1])}`;
    if (text.startsWith("INSERT")) {
      if (this.rows.has(key)) return { rowCount: 0 };
      this.rows.set(key, String(values[2]));
      return { rowCount: 1 };
    }
    if (text.startsWith("SELECT 1")) return { rowCount: this.rows.has(key) ? 1 : 0 };
    if (text.startsWith("DELETE")) {
      let removed = 0;
      for (const [row, expiresAt] of this.rows) {
        if (Date.parse(expiresAt) <= Date.parse(String(values[0]))) {
          this.rows.delete(row);
          removed += 1;
        }
      }
      return { rowCount: this.nullRowCount ? null : removed };
    }
    return { rowCount: 0 };
  }
}

const NOW = Date.parse("2026-10-02T12:00:00.000Z");
const clock = (): number => NOW;
const later = new Date(NOW + 60_000);

function store(client: SqlClient = new FakePostgres(), table?: string): PostgresReplayStore {
  return new PostgresReplayStore({
    client,
    namespace: "org-synthetic",
    clock,
    ...(table === undefined ? {} : { table }),
  });
}

describe("PostgresReplayStore", () => {
  it("lets exactly one of many concurrent claims win, and says so afterwards", async () => {
    const client = new FakePostgres();
    const shared = store(client);
    const other = store(client);
    const claims = await Promise.all(
      Array.from({ length: 50 }, async (_, index) =>
        (index % 2 === 0 ? shared : other).claim("intent-1", later),
      ),
    );
    expect(claims.filter(Boolean)).toHaveLength(1);
    await expect(other.consumed("intent-1")).resolves.toBe(true);
    await expect(other.consumed("intent-2")).resolves.toBe(false);
  });

  it("sends one parameterised insert with the namespace, the key and the expiry", async () => {
    const client = new FakePostgres();
    await expect(store(client).claim("intent-1", later)).resolves.toBe(true);
    expect(client.queries).toEqual([
      {
        text: `INSERT INTO ${DEFAULT_REPLAY_TABLE} (namespace, intent_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT (namespace, intent_id) DO NOTHING`,
        values: ["org-synthetic", "intent-1", later.toISOString()],
      },
    ]);
  });

  it("keeps namespaces apart", async () => {
    const client = new FakePostgres();
    const first = new PostgresReplayStore({ client, namespace: "org-a", clock });
    const second = new PostgresReplayStore({ client, namespace: "org-b", clock });
    await expect(first.claim("intent-1", later)).resolves.toBe(true);
    await expect(second.claim("intent-1", later)).resolves.toBe(true);
    expect(client.queries.map((query) => query.values[0])).toEqual(["org-a", "org-b"]);
  });

  it("refuses an empty, oversized, lapsed or unreadable claim without asking the database", async () => {
    const client = new FakePostgres();
    const replay = store(client);
    await expect(replay.claim("", later)).resolves.toBe(false);
    await expect(replay.claim("x".repeat(201), later)).resolves.toBe(false);
    await expect(replay.claim("intent-1", new Date(NOW))).resolves.toBe(false);
    await expect(replay.claim("intent-1", new Date(Number.NaN))).resolves.toBe(false);
    expect(client.queries).toEqual([]);
    await expect(replay.claim("x".repeat(200), new Date(NOW + 1))).resolves.toBe(true);
  });

  it("answers false when the database touched no row, and true only for exactly one", async () => {
    const answers: (number | null)[] = [null, 2, 0];
    const client: SqlClient = { query: async () => ({ rowCount: answers.shift() ?? 0 }) };
    const replay = store({ query: client.query });
    await expect(replay.claim("intent-1", later)).resolves.toBe(false);
    await expect(replay.claim("intent-1", later)).resolves.toBe(false);
    await expect(replay.consumed("intent-1")).resolves.toBe(false);
  });

  it("asks consumed with a parameterised select on its own namespace", async () => {
    const client = new FakePostgres();
    await store(client, "edge.claims").consumed("intent-9");
    expect(client.queries).toEqual([
      {
        text: "SELECT 1 FROM edge.claims WHERE namespace = $1 AND intent_id = $2",
        values: ["org-synthetic", "intent-9"],
      },
    ]);
  });

  it("removes claims that lapsed more than the retention ago, and only those", async () => {
    const client = new FakePostgres();
    const replay = new PostgresReplayStore({
      client,
      namespace: "org-synthetic",
      clock,
      retentionMs: 1_000,
    });
    client.rows.set("org-synthetic\u0000old", new Date(NOW - 1_000).toISOString());
    client.rows.set("org-synthetic\u0000recent", new Date(NOW - 999).toISOString());
    await expect(replay.cleanup()).resolves.toBe(1);
    expect(client.queries.at(-1)).toEqual({
      text: `DELETE FROM ${DEFAULT_REPLAY_TABLE} WHERE expires_at <= $1`,
      values: [new Date(NOW - 1_000).toISOString()],
    });
    expect([...client.rows.keys()]).toEqual(["org-synthetic\u0000recent"]);
    client.nullRowCount = true;
    await expect(replay.cleanup()).resolves.toBe(0);
  });

  it("keeps a day by default", async () => {
    const client = new FakePostgres();
    await store(client).cleanup();
    expect(client.queries[0]?.values).toEqual([new Date(NOW - 86_400_000).toISOString()]);
  });

  it("follows the real clock when none is given", async () => {
    const client = new FakePostgres();
    const replay = new PostgresReplayStore({ client, namespace: "org-synthetic" });
    await expect(replay.claim("intent-1", new Date(Date.now() + 60_000))).resolves.toBe(true);
    await expect(replay.claim("intent-2", new Date(Date.now() - 1))).resolves.toBe(false);
  });

  it("probes the table and its columns", async () => {
    const client = new FakePostgres();
    await store(client).probe();
    expect(client.queries).toEqual([
      {
        text: `SELECT namespace, intent_id, expires_at FROM ${DEFAULT_REPLAY_TABLE} LIMIT 0`,
        values: [],
      },
    ]);
    const failing: SqlClient = {
      query: async () => {
        throw new Error('relation "agentsafe_edge_replay" does not exist');
      },
    };
    await expect(store({ query: failing.query }).probe()).rejects.toThrow("does not exist");
  });

  it("refuses a table name, a namespace or a retention it cannot use", () => {
    const client = new FakePostgres();
    for (const table of ["", "Claims", "claims; drop", "a.b.c", "1claims", `t${"x".repeat(63)}`]) {
      expect(() => store(client, table), table).toThrow("REPLAY_TABLE_INVALID");
    }
    expect(() => store(client, `t${"x".repeat(62)}`)).not.toThrow();
    expect(() => store(client, "edge.claims")).not.toThrow();
    expect(() => new PostgresReplayStore({ client, namespace: "" })).toThrow(
      "REPLAY_NAMESPACE_INVALID",
    );
    expect(() => new PostgresReplayStore({ client, namespace: "n".repeat(201) })).toThrow(
      "REPLAY_NAMESPACE_INVALID",
    );
    expect(() => new PostgresReplayStore({ client, namespace: "n".repeat(200) })).not.toThrow();
    for (const retentionMs of [-1, 1.5, Number.NaN]) {
      expect(
        () => new PostgresReplayStore({ client, namespace: "org", retentionMs }),
        String(retentionMs),
      ).toThrow("REPLAY_RETENTION_INVALID");
    }
    expect(
      () => new PostgresReplayStore({ client, namespace: "org", retentionMs: 0 }),
    ).not.toThrow();
  });

  it("writes the DDL an operator runs, for a plain and a schema-qualified table", () => {
    expect(PostgresReplayStore.schema()).toBe(
      [
        "CREATE TABLE IF NOT EXISTS agentsafe_edge_replay (",
        "  namespace text NOT NULL,",
        "  intent_id text NOT NULL,",
        "  expires_at timestamptz NOT NULL,",
        "  claimed_at timestamptz NOT NULL DEFAULT now(),",
        "  PRIMARY KEY (namespace, intent_id)",
        ");",
        "CREATE INDEX IF NOT EXISTS agentsafe_edge_replay_expires_at ON agentsafe_edge_replay (expires_at);",
        "",
      ].join("\n"),
    );
    expect(PostgresReplayStore.schema("edge.claims")).toContain(
      "CREATE INDEX IF NOT EXISTS edge_claims_expires_at ON edge.claims (expires_at);",
    );
    expect(() => PostgresReplayStore.schema("Claims")).toThrow("REPLAY_TABLE_INVALID");
  });
});
