/**
 * Single use. `claim` takes a key once until its expiry; a second claim of
 * the same key, from this process or, for a shared store, from any replica,
 * answers false. `consumed` asks without claiming, so a decision about an
 * intent that has already run can be refused before it is made.
 */
export interface ReplayStore {
  claim(grantId: string, expiresAt: Date): Promise<boolean>;
  /** Whether `key` holds an unexpired claim. Optional: a store without it is never asked. */
  consumed?(key: string): Promise<boolean>;
}

/**
 * The claims of one process. Single use holds within that process only: a
 * deployment with more than one replica needs a shared store (the Postgres
 * one), or the same intent decided on two replicas runs twice.
 */
export class InMemoryReplayStore implements ReplayStore {
  private readonly claims = new Map<string, number>();

  public constructor(private readonly maxEntries = 10_000) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new Error("REPLAY_STORE_CAPACITY_INVALID");
    }
  }

  public async claim(grantId: string, expiresAt: Date): Promise<boolean> {
    const now = Date.now();
    const expiry = expiresAt.valueOf();
    if (grantId.length === 0 || grantId.length > 200 || !Number.isFinite(expiry) || expiry <= now) {
      return false;
    }
    for (const [key, expiry] of this.claims) {
      if (expiry <= now) this.claims.delete(key);
    }
    if (this.claims.has(grantId)) return false;
    if (this.claims.size >= this.maxEntries) throw new Error("REPLAY_STORE_CAPACITY_EXCEEDED");
    this.claims.set(grantId, expiry);
    return true;
  }

  public async consumed(key: string): Promise<boolean> {
    return (this.claims.get(key) ?? 0) > Date.now();
  }
}
