import { join } from "node:path";
import {
  EdgeBundleManager,
  EdgeModule,
  EdgeModuleError,
  FileBundleSource,
  LocalGrants,
  UrlBundleSource,
  type EdgeBundleSource,
  type EdgeDecisionRecord,
  type JsonValue,
  type LocalFinalizationRecord,
  type ReplayStore,
} from "@decionis/agent-safe-pipeline";
import type { HashChain } from "../audit/HashChain.js";
import type { LineWriter } from "../audit/LineAuditSink.js";
import type { ExecutorConfig } from "../config/ExecutorConfig.js";
import { EdgeLicence } from "../edge/EdgeLicence.js";
import { memoryReplay, postgresReplay, type EdgeReplay, type LoadPg } from "../edge/EdgeReplay.js";
import { FileEntitlementSource, UrlEntitlementSource } from "../edge/Entitlement.js";
import {
  FileUsageDelivery,
  UrlUsageDelivery,
  UsageMeter,
  type UsageDelivery,
} from "../edge/UsageMeter.js";
import { usageSigningKey, type UsageSigningKey } from "../edge/UsageReport.js";
import type { FetchLike } from "../handlers/HandlerRegistration.js";
import { RequestContext } from "../http/RequestContext.js";
import type { SecurityEvents } from "../incident/SecurityEvents.js";
import type { SecretStore } from "../secrets/SecretStore.js";

export interface EdgeRuntimeOptions {
  readonly config: ExecutorConfig;
  /** Where the replay store's connection string and the usage-report key are read from. */
  readonly secrets: SecretStore;
  /** The organisation's Decionis key, read at the moment of each bundle fetch. */
  readonly apiKey: () => string;
  /** The guarded fetch: a bundle comes from the authority's origin, and nowhere else. */
  readonly fetch: FetchLike;
  readonly events: SecurityEvents;
  /** The executor's evidence chain, and the writer its audit lines go through. */
  readonly chain: HashChain;
  readonly write: LineWriter;
  /** Loads the module; the configured file unless a test hands in its own. */
  readonly loadModule?: (path: string) => EdgeModule;
  /** Loads `pg` for the Postgres replay store; the installed package unless a test hands in its own. */
  readonly loadPg?: LoadPg;
  readonly clock?: () => number;
}

/** How often usage reports are attempted, the entitlement re-read and lapsed claims removed. */
const TICK_MS = 3_600_000;

/**
 * The long-lived half of the edge authority: the module, the bundle it holds,
 * the local grants, the replay store, the usage meter and the licence check.
 * It outlives a rebuild of the authority clients, so a rotated Presence
 * credential neither reloads the module nor forgets which intents have run.
 */
export class EdgeRuntime {
  public readonly module: EdgeModule;
  public readonly bundles: EdgeBundleManager;
  public readonly grants: LocalGrants;
  public readonly replay: ReplayStore;
  public readonly usage: UsageMeter;
  public readonly licence: EdgeLicence;
  public readonly onUnavailable: "hosted" | "block";
  public readonly clock: () => number;
  private readonly shared: EdgeReplay;
  private timer: ReturnType<typeof setInterval> | null = null;

  private constructor(
    private readonly options: EdgeRuntimeOptions,
    module: EdgeModule,
    source: EdgeBundleSource,
    key: (() => UsageSigningKey) | null,
  ) {
    const { config, events } = options;
    const edge = config.edge;
    if (edge === null) throw new Error("EDGE_NOT_CONFIGURED");
    this.module = module;
    this.clock = options.clock ?? Date.now;
    this.onUnavailable = edge.onUnavailable;
    this.grants = new LocalGrants(this.clock);
    this.shared =
      edge.replay.store === "memory"
        ? memoryReplay()
        : postgresReplay({
            databaseUrl: () =>
              options.secrets
                .get("EXECUTOR_EDGE_REPLAY_DATABASE_URL")
                .use((value) => value.toString("utf8").trim()),
            namespace: edge.orgId,
            table: edge.replay.table,
            clock: this.clock,
            ...(options.loadPg === undefined ? {} : { load: options.loadPg }),
          });
    this.replay = this.shared.store;
    this.bundles = new EdgeBundleManager({
      module,
      source,
      orgId: edge.orgId,
      refreshSeconds: edge.refreshSeconds,
      clock: this.clock,
      onEvent: (event) => events.emit(event),
    });
    const url = edge.bundle.source === "url";
    const delivery: UsageDelivery | null = url
      ? new UrlUsageDelivery({
          baseUrl: config.authority.baseUrl,
          apiKey: options.apiKey,
          fetch: options.fetch,
        })
      : edge.usage.reportDir === null
        ? null
        : new FileUsageDelivery(edge.usage.reportDir);
    this.usage = new UsageMeter({
      orgId: edge.orgId,
      chain: options.chain,
      installationId: edge.usage.installationId,
      stateDir:
        config.evidence.journalDir === null ? null : join(config.evidence.journalDir, "edge"),
      checkpointLines: config.evidence.checkpointLines,
      events,
      key,
      delivery,
      clock: this.clock,
    });
    this.licence = new EdgeLicence({
      source: url
        ? new UrlEntitlementSource({
            baseUrl: config.authority.baseUrl,
            apiKey: options.apiKey,
            fetch: options.fetch,
          })
        : new FileEntitlementSource(edge.entitlement.file, edge.entitlement.jwksFile),
      meter: this.usage,
      orgId: edge.orgId,
      events,
      clock: this.clock,
    });
    if (key !== null) {
      // The kid an operator registers as a `usage_report` provider key.
      events.emit({
        event: "EDGE_USAGE_KEY_LOADED",
        kid: key().kid,
        installation_id: this.usage.installationId,
      });
    }
  }

  /**
   * The runtime the configuration asks for, or null for a hosted deployment.
   * A module that cannot be read, is not WebAssembly, or is not ABI 3, and a
   * usage-report key that is not an Ed25519 private key, are refusals to
   * start that name the variable and the reason, never a deployment that
   * quietly decides hosted instead.
   */
  public static create(options: EdgeRuntimeOptions): EdgeRuntime | null {
    const edge = options.config.edge;
    if (edge === null) return null;
    let module: EdgeModule;
    try {
      module = (options.loadModule ?? EdgeModule.fromFile)(edge.wasmPath);
    } catch (error) {
      const code = error instanceof EdgeModuleError ? error.code : "EDGE_MODULE_INVALID";
      throw new Error(`CONFIG_INVALID: EXECUTOR_EDGE_WASM_PATH (${code})`);
    }
    let key: (() => UsageSigningKey) | null = null;
    if (edge.usage.signing) {
      // Read at each use, so a rotated key file is followed; checked once here.
      key = (): UsageSigningKey =>
        usageSigningKey(
          options.secrets
            .get("EXECUTOR_EDGE_USAGE_SIGNING_KEY")
            .use((value) => value.toString("utf8")),
          edge.usage.keyId,
        );
      try {
        key();
      } catch {
        throw new Error("CONFIG_INVALID: EXECUTOR_EDGE_USAGE_SIGNING_KEY (not an Ed25519 key)");
      }
    }
    const source: EdgeBundleSource =
      edge.bundle.source === "file"
        ? new FileBundleSource(edge.bundle.file)
        : new UrlBundleSource({
            baseUrl: options.config.authority.baseUrl,
            apiKey: options.apiKey,
            allowInsecureLoopback: options.config.authority.allowInsecureLoopback,
            fetch: options.fetch as typeof fetch,
          });
    return new EdgeRuntime(options, module, source, key);
  }

  /**
   * Links one local decision, or a local attempt's outcome, on the evidence
   * chain. A decision is counted as its line is written, with the sequence
   * and hash that line carries, so the count is the chain's own.
   */
  public record(record: EdgeDecisionRecord | LocalFinalizationRecord): void {
    // The record holds identifiers, codes and digests only; copied as JSON so
    // the chain links exactly what the line will say.
    const fields = JSON.parse(JSON.stringify(record)) as Record<string, JsonValue>;
    const at = new Date(this.clock()).toISOString();
    const chain = this.options.chain;
    chain.link(
      { at, ...fields, caller_principal: RequestContext.current()?.principal ?? null },
      (line) => {
        this.options.write(line);
        if (record.event !== "EDGE_DECISION") return;
        this.usage.observe({
          at,
          mode: record.mode,
          verdict: record.verdict,
          delegated: record.delegated,
          jti: record.jti,
          seq: chain.head.seq,
          hash: chain.head.hash,
        });
      },
    );
  }

  /**
   * The replay store first: a shared store that cannot be reached is a
   * refusal to start, since nothing could be run once. Then the first
   * bundle fetch, the first usage report and licence check, and the hourly
   * schedule for both and for removing lapsed claims.
   */
  public async start(): Promise<void> {
    try {
      await this.shared.ready();
    } catch (error) {
      const code =
        error instanceof Error && error.message === "REPLAY_DRIVER_MISSING"
          ? "REPLAY_DRIVER_MISSING"
          : "REPLAY_STORE_UNAVAILABLE";
      throw new Error(`CONFIG_INVALID: EXECUTOR_EDGE_REPLAY_DATABASE_URL (${code})`);
    }
    await this.bundles.start();
    await this.tick();
    this.timer = setInterval(() => void this.tick(), TICK_MS);
    this.timer.unref();
  }

  /** One round of housekeeping. Never throws, and touches no decision. */
  public async tick(): Promise<void> {
    await this.usage.report();
    await this.licence.check();
    await this.shared.cleanup().catch(() => {
      this.options.events.emit({ event: "EDGE_REPLAY_CLEANUP_FAILED" });
    });
  }

  public stop(): void {
    if (this.timer !== null) clearInterval(this.timer);
    this.timer = null;
    this.bundles.stop();
    this.usage.stop();
    void this.shared.close().catch(() => undefined);
  }
}
