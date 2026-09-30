import { join } from "node:path";
import { Gateway, type GatewayDependencies, type GatewayIo } from "../gateway/Gateway.js";
import {
  GatewayConfigError,
  GatewayConfigLoader,
  type GatewayConfig,
} from "../gateway/GatewayConfig.js";
import type { GatewaySelector } from "../http/GatewayHttpServer.js";
import { SecretError } from "../secrets/SecretStore.js";
import {
  parseTenantRegistry,
  tenantFingerprint,
  tenantHostname,
  TenantRegistryError,
  type TenantEntry,
  type TenantRegistry,
} from "./TenantRegistry.js";

/**
 * What a tenant's gateway inherits from the host's environment: how to reach
 * the authority and how long to wait for it and for the upstream. Nothing
 * else crosses, and never a credential: each tenant's workspace key comes
 * from its own mounted file, and the host's own environment may hold keys
 * no tenant should ever run under.
 */
export const SHARED_ENVIRONMENT = [
  "NODE_ENV",
  "DECIONIS_API_URL",
  "DECIONIS_TIMEOUT_MS",
  "DECIONIS_ALLOW_INSECURE_LOOPBACK",
  "AGENTSAFE_UPSTREAM_TIMEOUT_MS",
  "AGENTSAFE_FAILURE_POLICY",
] as const;

/** How long a replaced or removed tenant's gateway keeps finishing requests already in flight. */
export const DEFAULT_DRAIN_MS = 30_000;

export interface TenantHostOptions {
  readonly registryPath: string;
  /** The host's environment; only `SHARED_ENVIRONMENT` reaches a tenant. */
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly io: GatewayIo;
  /** The registry's text, or null when there is no such file. */
  readonly readFile: (path: string) => string | null;
  readonly version?: string;
  readonly drainMs?: number;
  /** Assembles one tenant's gateway; `Gateway.create` unless a test says otherwise. */
  readonly createGateway?: (
    config: GatewayConfig,
    dependencies: GatewayDependencies,
  ) => Promise<Gateway>;
  /** Handed to every tenant's gateway beside its own environment and output (transports, in tests). */
  readonly dependencies?: Omit<GatewayDependencies, "env" | "io">;
}

/** What one load of the registry did, as the host reports it. */
export interface TenantLoadReport {
  readonly event: "TENANT_REGISTRY_LOADED" | "TENANT_REGISTRY_REFUSED";
  /** The code when the registry itself was refused; the tenants served are then unchanged. */
  readonly code: string | null;
  readonly served: number;
  readonly built: readonly string[];
  readonly kept: number;
  readonly retired: number;
  /** Tenants whose gateway could not be built, with the reason; each keeps its previous gateway, if it had one. */
  readonly failed: readonly { readonly tenant: string; readonly code: string }[];
}

interface Served {
  readonly id: string;
  readonly fingerprint: string;
  readonly gateway: Gateway;
}

/**
 * Many tenants' gateways in one process, each at `{id}.{domain}`, built from
 * the registry the operator mounts. Every tenant gets an ordinary hosted
 * gateway (public-only upstream, shadow only, operator-only status,
 * host-only cookies, its tenant key required) assembled from its entry and
 * its own workspace key file; nothing about one tenant is visible to
 * another, because each request is routed to one gateway by its host alone.
 *
 * A reload rebuilds only the tenants whose entry changed, swaps the set at
 * once, and lets a replaced gateway drain before it is closed. A registry
 * that cannot be read or is not valid changes nothing: the tenants served
 * stay served.
 */
export class TenantHost {
  private served = new Map<string, Served>();
  private readonly draining = new Set<Gateway>();
  private readonly timers = new Set<ReturnType<typeof setTimeout>>();
  private queue: Promise<unknown> = Promise.resolve();
  private closed = false;
  private refusal: TenantRegistryError | null = null;

  /** The gateway for a request's host, or null (the listener answers 421). */
  public readonly select: GatewaySelector = (hostname) =>
    hostname === null ? null : (this.served.get(hostname)?.gateway ?? null);

  private constructor(private readonly options: TenantHostOptions) {}

  /** Loads the registry and builds every tenant; a registry that cannot be served refuses the start. */
  public static async start(options: TenantHostOptions): Promise<TenantHost> {
    const host = new TenantHost(options);
    await host.reload();
    if (host.refusal !== null) {
      await host.close();
      throw host.refusal;
    }
    return host;
  }

  /** The hostnames served, sorted. */
  public hostnames(): readonly string[] {
    return [...this.served.keys()].sort();
  }

  /** Reads the registry again; reloads never overlap, and each is reported as one line. */
  public reload(): Promise<TenantLoadReport> {
    const next = this.queue.then(() => this.load());
    this.queue = next.catch(() => undefined);
    return next;
  }

  /** Closes every gateway, the draining ones included, at once. */
  public async close(): Promise<void> {
    this.closed = true;
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
    const gateways = [...[...this.served.values()].map((entry) => entry.gateway), ...this.draining];
    this.served = new Map();
    this.draining.clear();
    await Promise.all(gateways.map((gateway) => gateway.close()));
  }

  private async load(): Promise<TenantLoadReport> {
    let registry: TenantRegistry;
    try {
      const text = this.options.readFile(this.options.registryPath);
      if (text === null) throw new TenantRegistryError("REGISTRY_UNREADABLE");
      registry = parseTenantRegistry(text);
    } catch (error) {
      this.refusal =
        error instanceof TenantRegistryError
          ? error
          : new TenantRegistryError("REGISTRY_UNREADABLE");
      return this.report({
        event: "TENANT_REGISTRY_REFUSED",
        code: this.refusal.message,
        served: this.served.size,
        built: [],
        kept: this.served.size,
        retired: 0,
        failed: [],
      });
    }
    this.refusal = null;
    const next = new Map<string, Served>();
    const built: string[] = [];
    const failed: { tenant: string; code: string }[] = [];
    let kept = 0;
    for (const tenant of registry.tenants) {
      const hostname = tenantHostname(registry, tenant);
      const fingerprint = tenantFingerprint(registry, tenant);
      const current = this.served.get(hostname);
      if (current !== undefined && current.fingerprint === fingerprint) {
        next.set(hostname, current);
        kept += 1;
        continue;
      }
      try {
        const gateway = await this.build(registry, tenant);
        next.set(hostname, { id: tenant.id, fingerprint, gateway });
        built.push(tenant.id);
      } catch (error) {
        failed.push({ tenant: tenant.id, code: TenantHost.codeOf(error) });
        // A tenant whose new entry cannot be built keeps the gateway it had.
        if (current !== undefined) next.set(hostname, current);
      }
    }
    const live = new Set([...next.values()].map((entry) => entry.gateway));
    const retired = [...this.served.values()]
      .map((entry) => entry.gateway)
      .filter((gateway) => !live.has(gateway));
    if (this.closed) {
      await Promise.all([...next.values()].map((entry) => entry.gateway.close()));
    } else {
      this.served = next;
      for (const gateway of retired) this.drain(gateway);
    }
    return this.report({
      event: "TENANT_REGISTRY_LOADED",
      code: null,
      served: next.size,
      built,
      kept,
      retired: retired.length,
      failed,
    });
  }

  /** One tenant's hosted gateway, from its entry, the shared environment and its own key file. */
  private async build(registry: TenantRegistry, tenant: TenantEntry): Promise<Gateway> {
    const env = TenantHost.tenantEnvironment(this.options.env, tenant);
    const rateLimit = tenant.rateLimit ?? registry.rateLimit;
    const config = GatewayConfigLoader.load({
      flags: { json: true },
      env,
      file: {
        version: 1,
        ...(rateLimit === undefined ? {} : { gateway: { rateLimit } }),
        ...(tenant.interception === undefined ? {} : { interception: tenant.interception }),
        ...(registry.evidenceDir === undefined
          ? {}
          : { evidence: { journalDir: join(registry.evidenceDir, tenant.id) } }),
      },
      credentials: null,
      version: this.options.version ?? "0.0.0",
    });
    const create = this.options.createGateway ?? Gateway.create.bind(Gateway);
    return await create(config, {
      ...(this.options.dependencies ?? {}),
      env,
      io: TenantHost.taggedIo(this.options.io, tenant.id),
      ...(this.options.version === undefined ? {} : { version: this.options.version }),
    });
  }

  /** The environment a tenant's gateway runs in: the shared settings, and its own entry. */
  public static tenantEnvironment(
    host: Readonly<Record<string, string | undefined>>,
    tenant: TenantEntry,
  ): Record<string, string> {
    const env: Record<string, string> = {};
    for (const name of SHARED_ENVIRONMENT) {
      const value = host[name];
      if (value !== undefined) env[name] = value;
    }
    return {
      ...env,
      AGENTSAFE_HOSTED_GATEWAY: "true",
      AGENTSAFE_MODE: "shadow",
      AGENTSAFE_UPSTREAM: tenant.upstream,
      AGENTSAFE_TENANT_KEY_DIGESTS: tenant.tenantKeyDigests.join(","),
      DECIONIS_TENANT_ID: tenant.workspace.tenantId,
      DECIONIS_API_KEY_FILE: tenant.workspace.apiKeyFile,
    };
  }

  /**
   * The tenant's own output: every line a tenant's gateway writes carries its
   * id first, so one process's stream can be read, retained and deleted per
   * tenant.
   */
  public static taggedIo(io: GatewayIo, tenant: string): GatewayIo {
    const tag = (line: string): string =>
      line.startsWith("{") && line.length > 2
        ? `{"tenant":${JSON.stringify(tenant)},${line.slice(1)}`
        : JSON.stringify({ tenant, line });
    return {
      stdout: (line) => io.stdout(tag(line)),
      stderr: (line) => io.stderr(tag(line)),
      color: false,
    };
  }

  /** Why a tenant's gateway could not be built: a code and the setting, never a value. */
  private static codeOf(error: unknown): string {
    if (error instanceof GatewayConfigError) return `${error.code}:${error.setting}`;
    if (error instanceof SecretError) return `${error.code}:${error.secret}`;
    return "TENANT_BUILD_FAILED";
  }

  private drain(gateway: Gateway): void {
    this.draining.add(gateway);
    const timer = setTimeout(() => {
      this.timers.delete(timer);
      this.draining.delete(gateway);
      void gateway.close();
    }, this.options.drainMs ?? DEFAULT_DRAIN_MS);
    timer.unref();
    this.timers.add(timer);
  }

  private report(report: TenantLoadReport): TenantLoadReport {
    this.options.io.stdout(JSON.stringify(report));
    return report;
  }
}
