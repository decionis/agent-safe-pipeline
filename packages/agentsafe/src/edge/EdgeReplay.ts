import {
  InMemoryReplayStore,
  PostgresReplayStore,
  type ReplayStore,
  type SqlClient,
} from "@decionis/agent-safe-pipeline";

/** The part of a `pg` `Pool` this host uses. */
export interface PgPool {
  query(text: string, values: unknown[]): Promise<{ rowCount: number | null }>;
  on(event: "error", listener: (error: Error) => void): unknown;
  end(): Promise<void>;
}

export type LoadPg = () => Promise<{
  Pool: new (options: { connectionString: string; max: number }) => PgPool;
}>;

/**
 * Loads `pg` only when the Postgres store is configured. The specifier is
 * not a literal, so a bundler leaves it alone and a deployment that never
 * names the store never loads a database driver; `pg` is an optional
 * dependency of the package and is present in the image.
 */
export const loadPg: LoadPg = async () => {
  const name = "pg";
  try {
    const module = (await import(name)) as { default?: unknown };
    return (module.default ?? module) as Awaited<ReturnType<LoadPg>>;
  } catch {
    throw new Error("REPLAY_DRIVER_MISSING");
  }
};

/** The replay store the edge runtime claims intents in, with its lifecycle. */
export interface EdgeReplay {
  readonly kind: "memory" | "postgres";
  readonly store: ReplayStore;
  /** Throws unless the store can be used: for Postgres, the table is reachable. */
  ready(): Promise<void>;
  /** Removes lapsed claims; nothing to do in memory. */
  cleanup(): Promise<void>;
  close(): Promise<void>;
}

export function memoryReplay(): EdgeReplay {
  return {
    kind: "memory",
    store: new InMemoryReplayStore(),
    ready: async () => undefined,
    cleanup: async () => undefined,
    close: async () => undefined,
  };
}

/**
 * The shared store: one pool, opened on first use. The connection string is
 * a secret, read when the pool is opened.
 */
export function postgresReplay(options: {
  readonly databaseUrl: () => string;
  readonly namespace: string;
  readonly table: string;
  readonly load?: LoadPg;
  readonly clock?: () => number;
}): EdgeReplay {
  let opened: Promise<{ store: PostgresReplayStore; pool: PgPool }> | null = null;
  const open = async (): Promise<{ store: PostgresReplayStore; pool: PgPool }> => {
    opened ??= (async () => {
      const { Pool } = await (options.load ?? loadPg)();
      const pool = new Pool({ connectionString: options.databaseUrl(), max: 4 });
      // An idle connection's error is the next query's failure, not the process's.
      pool.on("error", () => undefined);
      const client: SqlClient = { query: async (text, values) => pool.query(text, [...values]) };
      const store = new PostgresReplayStore({
        client,
        namespace: options.namespace,
        table: options.table,
        ...(options.clock === undefined ? {} : { clock: options.clock }),
      });
      return { store, pool };
    })();
    return await opened;
  };
  const store: ReplayStore = {
    claim: async (key, expiresAt) => (await open()).store.claim(key, expiresAt),
    consumed: async (key) => (await open()).store.consumed(key),
  };
  return {
    kind: "postgres",
    store,
    ready: async () => {
      await (await open()).store.probe();
    },
    cleanup: async () => {
      await (await open()).store.cleanup();
    },
    close: async () => {
      if (opened !== null) await (await opened).pool.end();
    },
  };
}
