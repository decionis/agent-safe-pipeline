import { randomBytes } from "node:crypto";
import {
  EdgeBundleManager,
  EdgeDecisionAuthority,
  IntentCapture,
  LocalAuthorizationVerifier,
  LocalGrants,
  ActionRegistry,
  PostgresReplayStore,
  SafeExecutor,
  type DecisionAuthority,
  type EdgeBundleSource,
} from "@decionis/agent-safe-pipeline";
import { z } from "zod";
import { afterAll, describe, expect, it, vi } from "vitest";
import {
  loadPg,
  memoryReplay,
  postgresReplay,
  type LoadPg,
  type PgPool,
} from "../../src/edge/EdgeReplay.js";
import { edgeBundle, edgeModuleDouble } from "../support/EdgeModuleDouble.js";

/** A pool that answers like the claims table, in memory, and remembers what it was asked. */
function fakePg(options: { failQuery?: boolean } = {}) {
  const rows = new Set<string>();
  const pools: { connectionString: string; max: number; ended: boolean; errors: number }[] = [];
  const queries: string[] = [];
  const load: LoadPg = async () => ({
    Pool: class implements PgPool {
      private readonly state: (typeof pools)[number];
      public constructor(settings: { connectionString: string; max: number }) {
        this.state = { ...settings, ended: false, errors: 0 };
        pools.push(this.state);
      }
      public async query(text: string, values: unknown[]): Promise<{ rowCount: number | null }> {
        queries.push(text);
        if (options.failQuery === true) throw new Error("connection refused");
        const key = `${String(values[0])}/${String(values[1])}`;
        if (text.startsWith("INSERT")) {
          if (rows.has(key)) return { rowCount: 0 };
          rows.add(key);
          return { rowCount: 1 };
        }
        if (text.startsWith("SELECT 1")) return { rowCount: rows.has(key) ? 1 : 0 };
        return { rowCount: 0 };
      }
      public on(_event: "error", listener: (error: Error) => void): void {
        // An idle client's error reaches the listener and must not escape it.
        listener(new Error("idle client lost"));
        this.state.errors += 1;
      }
      public async end(): Promise<void> {
        this.state.ended = true;
      }
    },
  });
  return { load, pools, queries, rows };
}

describe("memoryReplay", () => {
  it("holds single use in this process and needs no lifecycle", async () => {
    const replay = memoryReplay();
    expect(replay.kind).toBe("memory");
    await replay.ready();
    await replay.cleanup();
    await replay.close();
    const later = new Date(Date.now() + 60_000);
    await expect(replay.store.claim("intent-1", later)).resolves.toBe(true);
    await expect(replay.store.claim("intent-1", later)).resolves.toBe(false);
    await expect(replay.store.consumed?.("intent-1")).resolves.toBe(true);
  });
});

describe("postgresReplay", () => {
  it("opens one pool on first use, with the secret read then, and claims through it", async () => {
    const pg = fakePg();
    const databaseUrl = vi.fn(() => "postgres://executor@db.invalid/edge");
    const replay = postgresReplay({
      databaseUrl,
      namespace: "org-synthetic",
      table: "edge.claims",
      load: pg.load,
    });
    expect(replay.kind).toBe("postgres");
    expect(databaseUrl).not.toHaveBeenCalled();
    await replay.ready();
    const later = new Date(Date.now() + 60_000);
    await expect(replay.store.claim("intent-1", later)).resolves.toBe(true);
    await expect(replay.store.claim("intent-1", later)).resolves.toBe(false);
    await expect(replay.store.consumed?.("intent-1")).resolves.toBe(true);
    await replay.cleanup();
    expect(pg.pools).toEqual([
      { connectionString: "postgres://executor@db.invalid/edge", max: 4, ended: false, errors: 1 },
    ]);
    expect(databaseUrl).toHaveBeenCalledTimes(1);
    expect(pg.queries[0]).toBe("SELECT namespace, intent_id, expires_at FROM edge.claims LIMIT 0");
    expect(pg.queries.at(-1)).toBe("DELETE FROM edge.claims WHERE expires_at <= $1");
    await replay.close();
    expect(pg.pools[0]?.ended).toBe(true);
  });

  it("follows the clock it is given", async () => {
    const pg = fakePg();
    const replay = postgresReplay({
      databaseUrl: () => "postgres://db.invalid/edge",
      namespace: "org-synthetic",
      table: "agentsafe_edge_replay",
      load: pg.load,
      clock: () => Date.parse("2030-01-01T00:00:00.000Z"),
    });
    await expect(replay.store.claim("intent-1", new Date(Date.now() + 60_000))).resolves.toBe(
      false,
    );
  });

  it("closes nothing it never opened, and fails a store it cannot reach", async () => {
    const pg = fakePg({ failQuery: true });
    const replay = postgresReplay({
      databaseUrl: () => "postgres://db.invalid/edge",
      namespace: "org-synthetic",
      table: "agentsafe_edge_replay",
      load: pg.load,
    });
    await replay.close();
    expect(pg.pools).toEqual([]);
    await expect(replay.ready()).rejects.toThrow("connection refused");
    await expect(replay.store.consumed?.("intent-1")).rejects.toThrow("connection refused");
  });

  it("names a missing driver", async () => {
    const replay = postgresReplay({
      databaseUrl: () => "postgres://db.invalid/edge",
      namespace: "org-synthetic",
      table: "agentsafe_edge_replay",
      load: async () => {
        throw new Error("REPLAY_DRIVER_MISSING");
      },
    });
    await expect(replay.ready()).rejects.toThrow("REPLAY_DRIVER_MISSING");
  });

  it("loads the installed pg package", async () => {
    const pg = await loadPg();
    expect(typeof pg.Pool).toBe("function");
  });
});

/**
 * Against a real Postgres, when one is named: `AGENTSAFE_TEST_POSTGRES_URL`
 * (a throwaway database; the test creates and drops its own table).
 */
const databaseUrl = process.env["AGENTSAFE_TEST_POSTGRES_URL"];

describe.skipIf(databaseUrl === undefined)("the shared replay store on Postgres", () => {
  const table = `agentsafe_edge_replay_${randomBytes(4).toString("hex")}`;
  const replicas = [0, 1].map(() =>
    postgresReplay({ databaseUrl: () => databaseUrl ?? "", namespace: "org-synthetic", table }),
  );
  const admin = postgresReplay({ databaseUrl: () => databaseUrl ?? "", namespace: "admin", table });

  afterAll(async () => {
    const pg = await loadPg();
    const pool = new pg.Pool({ connectionString: databaseUrl ?? "", max: 1 });
    await pool.query(`DROP TABLE IF EXISTS ${table}`, []);
    await pool.end();
    for (const replica of [...replicas, admin]) await replica.close();
  });

  it("refuses to be ready before the operator has created the table", async () => {
    await expect(admin.ready()).rejects.toThrow();
  });

  it("lets one of many concurrent claims from two replicas win", async () => {
    const pg = await loadPg();
    const pool = new pg.Pool({ connectionString: databaseUrl ?? "", max: 1 });
    for (const statement of PostgresReplayStore.schema(table)
      .split(";\n")
      .filter((s) => s.trim() !== "")) {
      await pool.query(statement, []);
    }
    await pool.end();
    for (const replica of replicas) await replica.ready();
    const later = new Date(Date.now() + 60_000);
    const claims = await Promise.all(
      Array.from({ length: 40 }, async (_, index) =>
        (replicas[index % 2] ?? replicas[0])?.store.claim("intent-concurrent", later),
      ),
    );
    expect(claims.filter(Boolean)).toHaveLength(1);
    for (const replica of replicas) {
      await expect(replica.store.consumed?.("intent-concurrent")).resolves.toBe(true);
    }
    await expect(replicas[0]?.store.consumed?.("intent-unknown")).resolves.toBe(false);
  });

  it("executes an intent decided on two replicas once", async () => {
    const captured = new IntentCapture({ ttlSeconds: 120 }).capture(
      {
        action: "payment.create",
        target: "core:account:synthetic-1",
        parameters: { amountMinor: 500 },
      },
      {
        tenantId: "00000000-0000-4000-8000-000000000002",
        actor: { id: "synthetic-payments-agent", type: "AI_AGENT" },
        downstreamTarget: { system: "core", operation: "payment" },
        idempotencyKey: "synthetic-replica-1",
        context: {},
      },
    );
    const execute = vi.fn(async () => ({ posted: true }));
    const runs = await Promise.all(
      replicas.map(async (replica) => {
        const module = edgeModuleDouble();
        const source: EdgeBundleSource = {
          kind: "file",
          read: async () => ({ ok: true, signedBundle: edgeBundle() }),
        };
        const bundles = new EdgeBundleManager({ module, source, orgId: "org-synthetic" });
        await bundles.refresh();
        const grants = new LocalGrants();
        const hosted: DecisionAuthority = { evaluationMode: "ENFORCEMENT", evaluate: vi.fn() };
        const authority = new EdgeDecisionAuthority({
          module,
          bundles,
          hosted,
          grants,
          replay: replica.store,
        });
        const registry = new ActionRegistry();
        registry.register("payment.create", {
          parametersSchema: z.object({}).passthrough(),
          execute,
        });
        registry.seal();
        const executor = new SafeExecutor(
          registry,
          new LocalAuthorizationVerifier({
            grants,
            replay: replica.store,
            record: () => undefined,
          }),
        );
        return { authority, executor };
      }),
    );
    const decisions = await Promise.all(runs.map(async (run) => run.authority.evaluate(captured)));
    expect(decisions.map((decision) => decision.verdict)).toEqual(["ALLOW", "ALLOW"]);
    const outcomes = await Promise.all(
      runs.map(async (run, index) => run.executor.run(captured, decisions[index] ?? decisions[0]!)),
    );
    expect(outcomes.map((outcome) => outcome.outcome).sort()).toEqual(["BLOCKED", "COMPLETED"]);
    expect(execute).toHaveBeenCalledTimes(1);
    // A third decision about it, on either replica, is refused before it is made.
    const again = await runs[1]?.authority.evaluate(captured);
    expect(again).toMatchObject({ verdict: "BLOCK", reasonCodes: ["INTENT_ALREADY_CONSUMED"] });
  });

  it("removes only claims lapsed past the retention", async () => {
    const lapsed = postgresReplay({
      databaseUrl: () => databaseUrl ?? "",
      namespace: "org-synthetic",
      table,
      clock: () => Date.now() + 3 * 86_400_000,
    });
    await replicas[0]?.store.claim("intent-lapsing", new Date(Date.now() + 1_000));
    await lapsed.cleanup();
    await expect(replicas[0]?.store.consumed?.("intent-lapsing")).resolves.toBe(false);
    await lapsed.close();
  });
});
