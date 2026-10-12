import type { SqlClient } from "@decionis/agent-safe-pipeline";

interface HoldRow {
  intent_id: string;
  expires_at: string;
  held_at: string;
  used: boolean;
  replica: string;
  sealed: string;
}

interface ClaimRow {
  intent_id: string;
  lease_expires_at: string;
  retain_until: string;
  settled: boolean;
  sealed: string;
}

/**
 * A client with the semantics the store relies on: the primary keys, the
 * conditional upsert, the conditional updates and the counts, over the
 * statement text the store sends. Each statement is answered on a later
 * turn, so calls made together really interleave.
 */
export class FakeCardHoldsSql implements SqlClient {
  public readonly holds = new Map<string, HoldRow>();
  public readonly claims = new Map<string, ClaimRow>();
  public readonly activity: { namespace: string; card: string; kind: string; at: string }[] = [];
  public readonly statements: string[] = [];
  public failProbe = false;
  public failAll = false;

  public async query(
    text: string,
    values: readonly unknown[],
  ): Promise<{ readonly rowCount: number | null; readonly rows?: readonly unknown[] }> {
    this.statements.push(text);
    await new Promise((resolve) => setImmediate(resolve));
    if (this.failAll) throw new Error("connection refused");
    const v = values.map(String);
    if (text.includes("LIMIT 0")) {
      if (this.failProbe) throw new Error("relation does not exist");
      return { rowCount: 0, rows: [] };
    }
    if (text.includes("_holds")) return this.onHolds(text, v);
    if (text.includes("_claims")) return this.onClaims(text, v);
    if (text.includes("_activity")) return this.onActivity(text, v);
    throw new Error(`unexpected statement: ${text}`);
  }

  private onHolds(text: string, v: string[]) {
    const key = (ns: string, card: string, merchant: string) => `${ns}|${card}|${merchant}`;
    if (text.startsWith("SELECT 1")) {
      const row = this.holds.get(key(v[0]!, v[1]!, v[2]!));
      return { rowCount: row !== undefined && !row.used && row.expires_at > v[3]! ? 1 : 0 };
    }
    if (text.startsWith("INSERT")) {
      const k = key(v[0]!, v[1]!, v[2]!);
      const existing = this.holds.get(k);
      const next: HoldRow = {
        intent_id: v[3]!,
        expires_at: v[4]!,
        held_at: v[5]!,
        used: false,
        replica: v[6]!,
        sealed: v[7]!,
      };
      if (existing === undefined || existing.used || existing.expires_at <= next.held_at) {
        this.holds.set(k, next);
        return { rowCount: 1 };
      }
      return { rowCount: 0 };
    }
    if (text.startsWith("SELECT intent_id")) {
      const row = this.holds.get(key(v[0]!, v[1]!, v[2]!));
      if (row === undefined) return { rowCount: 0, rows: [] };
      return {
        rowCount: 1,
        rows: [
          {
            intent_id: row.intent_id,
            used: row.used,
            expires_at_ms: String(Date.parse(row.expires_at)),
            sealed: row.sealed,
          },
        ],
      };
    }
    if (text.startsWith("UPDATE")) {
      const row = this.holds.get(key(v[0]!, v[1]!, v[2]!));
      if (row === undefined || row.intent_id !== v[3] || row.used || row.expires_at <= v[4]!) {
        return { rowCount: 0 };
      }
      row.used = true;
      row.replica = v[5]!;
      return { rowCount: 1 };
    }
    if (text.startsWith("DELETE")) {
      let removed = 0;
      for (const [k, row] of this.holds) {
        if (row.expires_at <= v[0]!) {
          this.holds.delete(k);
          removed += 1;
        }
      }
      return { rowCount: removed };
    }
    throw new Error(`unexpected holds statement: ${text}`);
  }

  private onClaims(text: string, v: string[]) {
    const key = (ns: string, id: string) => `${ns}|${id}`;
    if (text.startsWith("SELECT intent_id")) {
      const row = this.claims.get(key(v[0]!, v[1]!));
      if (row === undefined) return { rowCount: 0, rows: [] };
      return {
        rowCount: 1,
        rows: [
          {
            intent_id: row.intent_id,
            settled: row.settled,
            lease_expires_at_ms: String(Date.parse(row.lease_expires_at)),
            retain_until_ms: String(Date.parse(row.retain_until)),
            sealed: row.sealed,
          },
        ],
      };
    }
    if (text.startsWith("INSERT")) {
      const k = key(v[0]!, v[1]!);
      if (this.claims.has(k)) return { rowCount: 0 };
      this.claims.set(k, {
        intent_id: v[2]!,
        lease_expires_at: v[4]!,
        retain_until: v[5]!,
        settled: false,
        sealed: v[7]!,
      });
      return { rowCount: 1 };
    }
    if (text.startsWith("UPDATE") && text.includes("SET sealed")) {
      const row = this.claims.get(key(v[0]!, v[1]!));
      if (row === undefined || row.settled) return { rowCount: 0 };
      row.sealed = v[2]!;
      return { rowCount: 1 };
    }
    if (text.startsWith("UPDATE") && text.includes("SET settled")) {
      const row = this.claims.get(key(v[0]!, v[1]!));
      if (row === undefined || row.settled) return { rowCount: 0 };
      row.settled = true;
      return { rowCount: 1 };
    }
    if (text.startsWith("DELETE")) {
      let removed = 0;
      for (const [k, row] of this.claims) {
        if (row.retain_until <= v[0]!) {
          this.claims.delete(k);
          removed += 1;
        }
      }
      return { rowCount: removed };
    }
    throw new Error(`unexpected claims statement: ${text}`);
  }

  private onActivity(text: string, v: string[]) {
    if (text.startsWith("INSERT")) {
      this.activity.push({ namespace: v[0]!, card: v[1]!, kind: v[2]!, at: v[3]! });
      return { rowCount: 1 };
    }
    if (text.startsWith("SELECT kind")) {
      const counts = new Map<string, number>();
      for (const entry of this.activity) {
        if (entry.namespace === v[0] && entry.card === v[1] && entry.at > v[2]!) {
          counts.set(entry.kind, (counts.get(entry.kind) ?? 0) + 1);
        }
      }
      return { rowCount: counts.size, rows: [...counts].map(([kind, n]) => ({ kind, n })) };
    }
    if (text.startsWith("DELETE")) {
      const before = this.activity.length;
      const kept = this.activity.filter((entry) => entry.at > v[0]!);
      this.activity.splice(0, this.activity.length, ...kept);
      return { rowCount: before - kept.length };
    }
    throw new Error(`unexpected activity statement: ${text}`);
  }
}
