import {
  EdgeBundleManager,
  EdgeModule,
  EdgeModuleError,
  FileBundleSource,
  InMemoryReplayStore,
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
import type { FetchLike } from "../handlers/HandlerRegistration.js";
import { RequestContext } from "../http/RequestContext.js";
import type { SecurityEvents } from "../incident/SecurityEvents.js";

export interface EdgeRuntimeOptions {
  readonly config: ExecutorConfig;
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
  readonly clock?: () => number;
}

/**
 * The long-lived half of the edge authority: the module, the bundle it holds,
 * the local grants and the replay store. It outlives a rebuild of the
 * authority clients, so a rotated Presence credential neither reloads the
 * module nor forgets which intents have already run.
 */
export class EdgeRuntime {
  public readonly module: EdgeModule;
  public readonly bundles: EdgeBundleManager;
  public readonly grants: LocalGrants;
  public readonly replay: ReplayStore;
  public readonly onUnavailable: "hosted" | "block";
  public readonly clock: () => number;

  private constructor(
    private readonly options: EdgeRuntimeOptions,
    module: EdgeModule,
    source: EdgeBundleSource,
  ) {
    const edge = options.config.edge;
    if (edge === null) throw new Error("EDGE_NOT_CONFIGURED");
    this.module = module;
    this.clock = options.clock ?? Date.now;
    this.onUnavailable = edge.onUnavailable;
    this.grants = new LocalGrants(this.clock);
    this.replay = new InMemoryReplayStore();
    this.bundles = new EdgeBundleManager({
      module,
      source,
      orgId: edge.orgId,
      refreshSeconds: edge.refreshSeconds,
      clock: this.clock,
      onEvent: (event) => options.events.emit(event),
    });
  }

  /**
   * The runtime the configuration asks for, or null for a hosted deployment.
   * A module that cannot be read, is not WebAssembly, or is not ABI 3 is a
   * refusal to start that names the variable and the reason, never a
   * deployment that quietly decides hosted instead.
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
    const source: EdgeBundleSource =
      edge.bundle.source === "file"
        ? new FileBundleSource(edge.bundle.file)
        : new UrlBundleSource({
            baseUrl: options.config.authority.baseUrl,
            apiKey: options.apiKey,
            allowInsecureLoopback: options.config.authority.allowInsecureLoopback,
            fetch: options.fetch as typeof fetch,
          });
    return new EdgeRuntime(options, module, source);
  }

  /** Links one local decision, or a local attempt's outcome, on the evidence chain. */
  public record(record: EdgeDecisionRecord | LocalFinalizationRecord): void {
    // The record holds identifiers, codes and digests only; copied as JSON so
    // the chain links exactly what the line will say.
    const fields = JSON.parse(JSON.stringify(record)) as Record<string, JsonValue>;
    this.options.chain.link(
      {
        at: new Date(this.clock()).toISOString(),
        ...fields,
        caller_principal: RequestContext.current()?.principal ?? null,
      },
      this.options.write,
    );
  }

  /** The first bundle fetch, awaited, then the refresh schedule. */
  public async start(): Promise<void> {
    await this.bundles.start();
  }

  public stop(): void {
    this.bundles.stop();
  }
}
