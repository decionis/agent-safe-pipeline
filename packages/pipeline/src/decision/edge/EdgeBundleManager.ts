import { z } from "zod";
import { BundleWindow, type BundleValidity, type RefreshPolicy } from "./BundleWindow.js";
import type { EdgeBundleSource } from "./EdgeBundleSource.js";
import type { EdgeModule } from "./EdgeModule.js";

/** A bundle the module verified and holds under `handle`. */
export interface LoadedBundle extends BundleValidity {
  readonly handle: number;
  readonly bundleId: string;
  readonly policyVersion: string;
  readonly kid: string;
  readonly expiresAt: string;
}

/**
 * What the manager reports. Identifiers, codes and counts only: no URL, no
 * header, no response body and no credential can reach a field here.
 */
export type EdgeBundleEvent =
  | {
      readonly event: "EDGE_BUNDLE_LOADED";
      readonly bundle_id: string;
      readonly policy_version: string;
      readonly kid: string;
      readonly expires_at: string;
    }
  | {
      readonly event: "EDGE_BUNDLE_REFRESH_FAILED";
      readonly code: string;
      readonly failures: number;
      readonly retry_ms: number;
    }
  | {
      readonly event: "EDGE_BUNDLE_EXPIRED";
      readonly bundle_id: string;
      readonly policy_version: string;
    };

export interface EdgeBundleManagerOptions {
  readonly module: EdgeModule;
  readonly source: EdgeBundleSource;
  /** The organisation the bundle must be issued to; the module checks it against `aud`. */
  readonly orgId: string;
  /** The routine refresh interval. One hour by default. */
  readonly refreshSeconds?: number;
  /** Epoch milliseconds; the only time the module is ever given. */
  readonly clock?: () => number;
  readonly onEvent?: (event: EdgeBundleEvent) => void;
  readonly retryBaseMs?: number;
  readonly retryMaxMs?: number;
  readonly minimumMs?: number;
}

const DEFAULT_REFRESH_SECONDS = 3_600;
/** A file is looked at this often, whatever the routine interval: it changes when an operator says so. */
const FILE_POLL_MS = 10_000;

const LoadResultSchema = z.object({
  handle: z.number().int().min(1).max(0xffffffff),
  bundle_id: z.string().min(1).max(200),
  policy_version: z.string().min(1).max(200),
  kid: z.string().min(1).max(200),
  not_before: z.string().datetime({ offset: true }),
  expires_at: z.string().datetime({ offset: true }),
});

/**
 * Keeps one verified bundle loaded in the module and the next one coming.
 *
 * The loaded bundle is replaced only by one the module has verified: the new
 * handle becomes current in one assignment and the old handle is released
 * after it, so a decision always runs on exactly one of the two. A failed
 * fetch or a refused bundle leaves the last good bundle in place until its
 * own expiry, and is retried with backoff. Past its expiry a bundle is
 * released and nothing is loaded: there is no grace period, because a bundle
 * past `exp` is one Decionis no longer stands behind.
 */
export class EdgeBundleManager {
  private loaded: (LoadedBundle & { readonly signedBundle: string }) | null = null;
  private failures = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private inflight: Promise<string | null> | null = null;
  private stopped = false;
  private readonly clock: () => number;
  private readonly policy: RefreshPolicy;

  public constructor(private readonly options: EdgeBundleManagerOptions) {
    this.clock = options.clock ?? Date.now;
    const refreshMs = (options.refreshSeconds ?? DEFAULT_REFRESH_SECONDS) * 1_000;
    this.policy = {
      refreshMs: options.source.kind === "file" ? Math.min(refreshMs, FILE_POLL_MS) : refreshMs,
      retryBaseMs: options.retryBaseMs ?? 1_000,
      retryMaxMs: options.retryMaxMs ?? 300_000,
      minimumMs: options.minimumMs ?? 30_000,
    };
  }

  /**
   * The bundle a decision may run on at `now`, or null. A bundle past its
   * expiry is released here, so the moment it lapses is the moment it stops
   * being used, whatever the refresh schedule is doing.
   */
  public current(now: number): LoadedBundle | null {
    const loaded = this.loaded;
    if (loaded === null) return null;
    if (now >= loaded.expiresAtMs) {
      this.loaded = null;
      this.options.module.unloadBundle(loaded.handle);
      this.emit({
        event: "EDGE_BUNDLE_EXPIRED",
        bundle_id: loaded.bundleId,
        policy_version: loaded.policyVersion,
      });
      return null;
    }
    return BundleWindow.usable(loaded, now) ? loaded : null;
  }

  /** Fetches and loads once now; the first call of `start`, and what a test drives. */
  public async refresh(): Promise<string | null> {
    this.inflight ??= this.attempt().finally(() => {
      this.inflight = null;
    });
    return await this.inflight;
  }

  /** The first refresh, awaited, then the schedule. */
  public async start(): Promise<void> {
    this.stopped = false;
    await this.tick();
  }

  /** Stops the schedule and releases the loaded bundle. */
  public stop(): void {
    this.stopped = true;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    const loaded = this.loaded;
    this.loaded = null;
    if (loaded !== null) this.options.module.unloadBundle(loaded.handle);
  }

  private async tick(): Promise<void> {
    const failure = await this.refresh();
    if (this.stopped) return;
    const delay = BundleWindow.nextDelay(this.policy, this.loaded, this.failures, this.clock());
    if (failure !== null) {
      this.emit({
        event: "EDGE_BUNDLE_REFRESH_FAILED",
        code: failure,
        failures: this.failures,
        retry_ms: delay,
      });
    }
    this.timer = setTimeout(() => void this.tick(), delay);
    this.timer.unref();
  }

  /** One fetch and load. Null when the loaded bundle is current; otherwise the failure's code. */
  private async attempt(): Promise<string | null> {
    const read = await this.options.source.read();
    if (!read.ok) return this.failed(read.code);
    if (this.loaded?.signedBundle === read.signedBundle) {
      this.failures = 0;
      return null;
    }
    let envelope;
    try {
      envelope = this.options.module.loadBundle({
        signed_bundle: read.signedBundle,
        org_id: this.options.orgId,
        now: new Date(this.clock()).toISOString(),
      });
    } catch {
      return this.failed("EDGE_MODULE_FAULTED");
    }
    if (!envelope.ok) return this.failed(EdgeBundleManager.refusal(envelope.code));
    const parsed = LoadResultSchema.safeParse(envelope.result);
    if (!parsed.success) {
      const handle = (envelope.result as { readonly handle?: unknown } | null)?.handle;
      if (typeof handle === "number") this.options.module.unloadBundle(handle);
      return this.failed("BUNDLE_LOAD_RESULT_INVALID");
    }
    const result = parsed.data;
    const previous = this.loaded;
    this.loaded = {
      handle: result.handle,
      bundleId: result.bundle_id,
      policyVersion: result.policy_version,
      kid: result.kid,
      notBeforeMs: Date.parse(result.not_before),
      expiresAtMs: Date.parse(result.expires_at),
      expiresAt: new Date(Date.parse(result.expires_at)).toISOString(),
      signedBundle: read.signedBundle,
    };
    if (previous !== null) this.options.module.unloadBundle(previous.handle);
    this.failures = 0;
    this.emit({
      event: "EDGE_BUNDLE_LOADED",
      bundle_id: result.bundle_id,
      policy_version: result.policy_version,
      kid: result.kid,
      expires_at: this.loaded.expiresAt,
    });
    return null;
  }

  private failed(code: string): string {
    this.failures += 1;
    return code;
  }

  private emit(event: EdgeBundleEvent): void {
    try {
      this.options.onEvent?.(event);
    } catch {
      // Reporting never changes which bundle is loaded.
    }
  }

  /** The module's refusal as a log code: its own identifier, upper-cased, and nothing else of it. */
  private static refusal(code: string): string {
    return /^[a-z][a-z0-9_]{0,62}$/.test(code) ? code.toUpperCase() : "BUNDLE_REFUSED";
  }
}
