import type { ReplayStore } from "./ReplayStore.js";

/**
 * The one method of a Postgres client the store uses: a parameterised query
 * and the number of rows it touched. A `pg` `Pool` is one; this package does
 * not depend on `pg`, so a deployment that never names the store never loads
 * a database driver.
 */
export interface SqlClient {
  query(
    text: string,
    values: readonly unknown[],
  ): Promise<{ readonly rowCount: number | null; readonly rows?: readonly unknown[] }>;
}

export interface PostgresReplayStoreOptions {
  readonly client: SqlClient;
  /**
   * Whose claims these are: the organisation the executor decides for. Two
   * deployments that share a database never see each other's keys.
   */
  readonly namespace: string;
  /** The claims table, optionally schema-qualified; `agentsafe_edge_replay` by default. */
  readonly table?: string;
  /** How long a lapsed claim is kept before `cleanup` removes it; a day by default. */
  readonly retentionMs?: number;
  readonly clock?: () => number;
}

export const DEFAULT_REPLAY_TABLE = "agentsafe_edge_replay";

/** A lowercase SQL identifier, or `schema.table`: interpolated into SQL, so nothing else is. */
const TABLE = /^[a-z_][a-z0-9_]{0,62}(?:\.[a-z_][a-z0-9_]{0,62})?$/;
const DAY_MS = 86_400_000;

/**
 * Single use shared by every replica: a claim is one row, unique on
 * `(namespace, intent_id)`, inserted with `ON CONFLICT DO NOTHING`. The
 * database's unique index decides which of two concurrent claims wins, so
 * the same intent decided on two replicas executes once.
 *
 * A row stays until `cleanup` removes it, a retention period after its
 * expiry: a key is never claimable again while its row exists, which is
 * stricter than the in-memory store and never weaker. The operator creates
 * the table (`PostgresReplayStore.schema()`); the executor's role needs
 * SELECT, INSERT and DELETE on it and nothing else.
 */
export class PostgresReplayStore implements ReplayStore {
  private readonly client: SqlClient;
  private readonly namespace: string;
  private readonly table: string;
  private readonly retentionMs: number;
  private readonly clock: () => number;

  public constructor(options: PostgresReplayStoreOptions) {
    const table = options.table ?? DEFAULT_REPLAY_TABLE;
    if (!TABLE.test(table)) throw new Error("REPLAY_TABLE_INVALID");
    if (options.namespace.length === 0 || options.namespace.length > 200) {
      throw new Error("REPLAY_NAMESPACE_INVALID");
    }
    const retentionMs = options.retentionMs ?? DAY_MS;
    if (!Number.isSafeInteger(retentionMs) || retentionMs < 0) {
      throw new Error("REPLAY_RETENTION_INVALID");
    }
    this.client = options.client;
    this.namespace = options.namespace;
    this.table = table;
    this.retentionMs = retentionMs;
    this.clock = options.clock ?? Date.now;
  }

  /** The DDL an operator runs once, before the first replica starts. */
  public static schema(table = DEFAULT_REPLAY_TABLE): string {
    if (!TABLE.test(table)) throw new Error("REPLAY_TABLE_INVALID");
    return [
      `CREATE TABLE IF NOT EXISTS ${table} (`,
      "  namespace text NOT NULL,",
      "  intent_id text NOT NULL,",
      "  expires_at timestamptz NOT NULL,",
      "  claimed_at timestamptz NOT NULL DEFAULT now(),",
      "  PRIMARY KEY (namespace, intent_id)",
      ");",
      `CREATE INDEX IF NOT EXISTS ${table.replace(".", "_")}_expires_at ON ${table} (expires_at);`,
      "",
    ].join("\n");
  }

  public async claim(key: string, expiresAt: Date): Promise<boolean> {
    const expiry = expiresAt.valueOf();
    if (key.length === 0 || key.length > 200 || !(expiry > this.clock())) return false;
    const result = await this.client.query(
      `INSERT INTO ${this.table} (namespace, intent_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT (namespace, intent_id) DO NOTHING`,
      [this.namespace, key, new Date(expiry).toISOString()],
    );
    return result.rowCount === 1;
  }

  /** Whether a row holds `key`, lapsed or not: exactly when `claim` would refuse it. */
  public async consumed(key: string): Promise<boolean> {
    const result = await this.client.query(
      `SELECT 1 FROM ${this.table} WHERE namespace = $1 AND intent_id = $2`,
      [this.namespace, key],
    );
    return result.rowCount === 1;
  }

  /** Removes every claim that lapsed more than the retention period ago; returns how many. */
  public async cleanup(): Promise<number> {
    const before = new Date(this.clock() - this.retentionMs).toISOString();
    const result = await this.client.query(`DELETE FROM ${this.table} WHERE expires_at <= $1`, [
      before,
    ]);
    return result.rowCount ?? 0;
  }

  /** Throws unless the table exists with the columns this store uses. */
  public async probe(): Promise<void> {
    await this.client.query(
      `SELECT namespace, intent_id, expires_at FROM ${this.table} LIMIT 0`,
      [],
    );
  }
}
