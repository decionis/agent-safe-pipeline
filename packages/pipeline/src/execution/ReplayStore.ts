export interface ReplayStore {
  claim(grantId: string, expiresAt: Date): Promise<boolean>;
}

export class InMemoryReplayStore implements ReplayStore {
  private readonly claims = new Map<string, number>();

  public constructor(private readonly maxEntries = 10_000) {}

  public async claim(grantId: string, expiresAt: Date): Promise<boolean> {
    const now = Date.now();
    for (const [key, expiry] of this.claims) {
      if (expiry <= now) this.claims.delete(key);
    }
    if (this.claims.has(grantId)) return false;
    if (this.claims.size >= this.maxEntries) throw new Error("REPLAY_STORE_CAPACITY_EXCEEDED");
    this.claims.set(grantId, expiresAt.valueOf());
    return true;
  }
}
