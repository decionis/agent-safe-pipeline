import type { SqlClient } from "@decionis/agent-safe-pipeline";
import { loadPg, type LoadPg, type PgPool } from "../../edge/EdgeReplay.js";
import type { CardHoldSeal } from "./CardHoldSeal.js";
import type {
  CardClaimInput,
  CardHoldAdoption,
  CardHoldKey,
  CardHoldStore,
  CardVelocity,
  ClaimedCardAuthorization,
  HeldCardGrant,
  HeldCardGrantRecord,
} from "./CardHoldStore.js";
import type { CardAuthorizationRequest } from "./CardPurchase.js";
import { PostgresCardHolds } from "./PostgresCardHolds.js";

/**
 * The shared hold store over one `pg` pool, opened on first use: the
 * connection string and the hold key are secrets, read when the pool is
 * opened and when a row is sealed, and never held as strings here.
 */
export function postgresCardHolds(options: {
  readonly databaseUrl: () => string;
  readonly seal: () => CardHoldSeal;
  readonly namespace: string;
  readonly table: string;
  readonly adopt: CardHoldAdoption;
  readonly load?: LoadPg;
  readonly clock?: () => number;
  readonly claimRetentionMs?: number;
}): CardHoldStore {
  let opened: Promise<{ store: PostgresCardHolds; pool: PgPool }> | null = null;
  const open = async (): Promise<{ store: PostgresCardHolds; pool: PgPool }> => {
    opened ??= (async () => {
      const { Pool } = await (options.load ?? loadPg)();
      const pool = new Pool({ connectionString: options.databaseUrl(), max: 4 });
      // An idle connection's error is the next query's failure, not the process's.
      pool.on("error", () => undefined);
      const client: SqlClient = {
        query: async (text, values) =>
          (await pool.query(text, [...values])) as Awaited<ReturnType<SqlClient["query"]>>,
      };
      const store = new PostgresCardHolds({
        client,
        namespace: options.namespace,
        table: options.table,
        seal: options.seal(),
        adopt: options.adopt,
        ...(options.clock === undefined ? {} : { clock: options.clock }),
        ...(options.claimRetentionMs === undefined
          ? {}
          : { claimRetentionMs: options.claimRetentionMs }),
      });
      return { store, pool };
    })();
    return await opened;
  };
  return {
    kind: "postgres",
    spendable: async (key: CardHoldKey) => (await open()).store.spendable(key),
    hold: async (grant: HeldCardGrant) => (await open()).store.hold(grant),
    grant: async (key: CardHoldKey): Promise<HeldCardGrantRecord | undefined> =>
      (await open()).store.grant(key),
    spend: async (grant: HeldCardGrant) => (await open()).store.spend(grant),
    claimed: async (id: string): Promise<ClaimedCardAuthorization | undefined> =>
      (await open()).store.claimed(id),
    recordClaim: async (id: string, claim: CardClaimInput) =>
      (await open()).store.recordClaim(id, claim),
    amend: async (id: string, request: CardAuthorizationRequest) =>
      (await open()).store.amend(id, request),
    settle: async (id: string) => (await open()).store.settle(id),
    velocity: async (card: string, windowMs?: number): Promise<CardVelocity> =>
      (await open()).store.velocity(card, windowMs),
    ready: async () => {
      await (await open()).store.ready();
    },
    cleanup: async () => {
      await (await open()).store.cleanup();
    },
    close: async () => {
      if (opened !== null) await (await opened).pool.end();
    },
  };
}
