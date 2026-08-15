export interface ReplayStore {
  claim(grantId: string, expiresAt: Date): Promise<boolean>;
}

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
}
