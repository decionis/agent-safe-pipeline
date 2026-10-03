import { join } from "node:path";
import {
  Gateway,
  shortDigest,
  type GatewayDependencies,
  type GatewayIo,
} from "../gateway/Gateway.js";
import {
  GatewayConfigError,
  GatewayConfigLoader,
  type GatewayConfig,
} from "../gateway/GatewayConfig.js";
import type { GatewaySelector } from "../http/GatewayHttpServer.js";
import { SecretError } from "../secrets/SecretStore.js";
import {
  parseTenantRegistry,
  registryRevision,
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
  /** The registry's text, as read, as a short digest; null when there was none to read. */
  readonly revision: string | null;
  readonly served: number;
  readonly built: readonly string[];
  readonly kept: number;
  /** Tenants whose gateway took new keys in place, without a rebuild. */
  readonly rekeyed: readonly string[];
  readonly retired: number;
  /**
   * Tenants whose entry could not be applied, with the reason. Each keeps the
   * gateway it had, if it had one, admitting only keys its entry still lists;
   * when that is none, it is not served.
   */
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
 * once, and lets a replaced gateway drain before it is closed; the gateway
 * built in its place continues its chains. A change to a tenant's keys alone
 * rebuilds nothing: its gateway takes them in place. A registry that cannot
 * be read or is not valid changes nothing: the tenants served stay served.
 */
export class TenantHost {
  private served = new Map<string, Served>();
  private readonly draining = new Set<Gateway>();
  private readonly timers = new Set<ReturnType<typeof setTimeout>>();
  private queue: Promise<unknown> = Promise.resolve();
  private closed = false;
  private refusal: TenantRegistryError | null = null;
  private failing: readonly string[] = [];
  private currentDomain: string | null = null;
  /** How the tenants' hosts are reached, once the listener is bound; null before. */
  private scheme: "http" | "https" | null = null;
  private everyTenantServed = false;

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

  /**
   * The tenants whose entry the last load could not apply: a reload with an
   * unchanged registry tries exactly these again, since every other tenant
   * is kept. A tenant whose key file had not arrived yet is one of them.
   */
  public failures(): readonly string[] {
    return this.failing;
  }

  /**
   * Whether the process is ready for traffic: from the first load that served
   * every tenant its registry names, and from then on. A new process, in a
   * rollout or after a restart, gets no traffic while a tenant it should
   * serve would be answered 421; once ready, a tenant that cannot be built
   * later is reported, and never takes every other tenant out of service.
   */
  public ready(): boolean {
    return this.everyTenantServed;
  }

  /** The domain of the registry last loaded: the apex, and the parent of every tenant's host. */
  public domain(): string | null {
    return this.currentDomain;
  }

  /** The hostnames served, sorted. */
  public hostnames(): readonly string[] {
    return [...this.served.keys()].sort();
  }

  /**
   * The listener is bound: every tenant's gateway starts, with its banner and
   * its chained start line, and so does each gateway built from now on as it
   * is swapped in. A started gateway reports its stop, and its shadow tally,
   * when it is replaced or the host stops.
   */
  public listening(scheme: "http" | "https"): void {
    this.scheme = scheme;
    for (const [hostname, entry] of this.served) entry.gateway.started(`${scheme}://${hostname}`);
  }

  /** Reads the registry again; reloads never overlap, and each is reported as one line. */
  public reload(): Promise<TenantLoadReport> {
    const next = this.queue.then(() => this.load());
    this.queue = next.catch(() => undefined);
    return next;
  }

  /**
   * Stops every gateway, the draining ones included, and closes them: the
   * draining ones first, so the head a journal persists last is the one the
   * live gateway links on.
   */
  public async close(signal = "SHUTDOWN"): Promise<void> {
    this.closed = true;
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
    const draining = [...this.draining];
    const served = [...this.served.values()].map((entry) => entry.gateway);
    this.served = new Map();
    this.draining.clear();
    if (this.scheme !== null) {
      for (const gateway of [...draining, ...served]) gateway.stopped(signal);
    }
    await Promise.all(draining.map((gateway) => gateway.close()));
    await Promise.all(served.map((gateway) => gateway.close()));
  }

  private async load(): Promise<TenantLoadReport> {
    let registry: TenantRegistry;
    let revision: string | null = null;
    try {
      const text = this.options.readFile(this.options.registryPath);
      if (text === null) throw new TenantRegistryError("REGISTRY_UNREADABLE");
      revision = shortDigest(registryRevision(text));
      registry = parseTenantRegistry(text);
    } catch (error) {
      this.refusal =
        error instanceof TenantRegistryError
          ? error
          : new TenantRegistryError("REGISTRY_UNREADABLE");
      return this.report({
        event: "TENANT_REGISTRY_REFUSED",
        code: this.refusal.message,
        revision,
        served: this.served.size,
        built: [],
        kept: this.served.size,
        rekeyed: [],
        retired: 0,
        failed: [],
      });
    }
    this.refusal = null;
    this.currentDomain = registry.domain;
    const next = new Map<string, Served>();
    const built: string[] = [];
    const fresh: [string, Gateway][] = [];
    const replaced: Gateway[] = [];
    const rekeyed: string[] = [];
    const failed: { tenant: string; code: string }[] = [];
    let kept = 0;
    for (const tenant of registry.tenants) {
      const hostname = tenantHostname(registry, tenant);
      const fingerprint = tenantFingerprint(registry, tenant);
      const current = this.served.get(hostname);
      const unchanged = current?.fingerprint === fingerprint;
      let failure: unknown = null;
      if (!unchanged) {
        try {
          // A rebuilt tenant's gateway takes up the chains its old one links
          // on, so its evidence goes on in one sequence, never from genesis.
          const gateway = await this.build(registry, tenant, current?.gateway);
          next.set(hostname, { id: tenant.id, fingerprint, gateway });
          built.push(tenant.id);
          fresh.push([hostname, gateway]);
          if (current !== undefined) replaced.push(current.gateway);
          continue;
        } catch (error) {
          failure = error;
        }
      }
      if (current !== undefined) {
        // The gateway it had: unchanged but for its keys, or kept because its
        // new entry cannot be built. Either way it admits, from now on, only
        // keys the entry lists.
        const keys = TenantHost.rekey(current.gateway, TenantHost.keyDigests(tenant));
        failure ??= keys.error;
        if (keys.changed) rekeyed.push(tenant.id);
        if (keys.served) {
          next.set(hostname, current);
          if (unchanged) kept += 1;
        }
      }
      if (failure !== null) failed.push({ tenant: tenant.id, code: TenantHost.codeOf(failure) });
    }
    this.failing = failed.map((entry) => entry.tenant);
    const live = new Set([...next.values()].map((entry) => entry.gateway));
    const retired = [...this.served.values()]
      .map((entry) => entry.gateway)
      .filter((gateway) => !live.has(gateway));
    if (this.closed) {
      await Promise.all([...next.values()].map((entry) => entry.gateway.close()));
    } else {
      this.served = next;
      if (next.size === registry.tenants.length) this.everyTenantServed = true;
      // The replacement persists the chains' heads from now on, not the
      // gateway it replaced, which links on them only until it has drained.
      for (const gateway of replaced) gateway.releaseJournal();
      for (const gateway of retired) this.drain(gateway);
      for (const entry of next.values()) {
        entry.gateway.builtFrom({ revision, entry: shortDigest(`sha256:${entry.fingerprint}`) });
      }
    }
    const report = this.report({
      event: "TENANT_REGISTRY_LOADED",
      code: null,
      revision,
      served: next.size,
      built,
      kept,
      rekeyed,
      retired: retired.length,
      failed,
    });
    const scheme = this.scheme;
    if (scheme !== null && !this.closed) {
      for (const [hostname, gateway] of fresh) gateway.started(`${scheme}://${hostname}`);
    }
    return report;
  }

  /**
   * Makes a kept gateway admit exactly the keys its tenant's entry lists now,
   * in place and at once. Digests it refuses (malformed, repeated) leave it
   * only the keys it already admits that the entry still lists, and none of
   * those means it is not served: a key the registry dropped is never left
   * admitted because the rest of an entry could not be applied.
   */
  private static rekey(
    gateway: Gateway,
    digests: readonly string[],
  ): { readonly changed: boolean; readonly served: boolean; readonly error: unknown } {
    const before = gateway.tenantKeys;
    if (before.length === digests.length && before.every((digest) => digests.includes(digest))) {
      return { changed: false, served: true, error: null };
    }
    try {
      gateway.admitKeys(digests);
      return { changed: true, served: true, error: null };
    } catch (error) {
      const still = before.filter((digest) => digests.includes(digest));
      if (still.length === 0) return { changed: false, served: false, error };
      gateway.admitKeys(still);
      return { changed: still.length !== before.length, served: true, error };
    }
  }

  /**
   * One tenant's hosted gateway, from its entry, the shared environment and
   * its own key file; continuing the gateway it replaces, when there is one.
   */
  private async build(
    registry: TenantRegistry,
    tenant: TenantEntry,
    replacing: Gateway | undefined,
  ): Promise<Gateway> {
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
      ...(replacing === undefined ? {} : { continues: replacing.continuation() }),
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
      AGENTSAFE_HOSTED_TENANT: tenant.id,
      AGENTSAFE_MODE: "shadow",
      AGENTSAFE_UPSTREAM: tenant.upstream,
      AGENTSAFE_TENANT_KEY_DIGESTS: TenantHost.keyDigests(tenant).join(","),
      // The tenant's own timeout wins over the host's.
      ...(tenant.upstreamTimeoutMs === undefined
        ? {}
        : { AGENTSAFE_UPSTREAM_TIMEOUT_MS: String(tenant.upstreamTimeoutMs) }),
      DECIONIS_TENANT_ID: tenant.workspace.tenantId,
      DECIONIS_API_KEY_FILE: tenant.workspace.apiKeyFile,
    };
  }

  /**
   * A tenant's key digests as its gateway's loader reads them: split at
   * commas, trimmed, and without empty values. A build and an in-place rekey
   * both start from these, so a reload of an entry the build admitted admits
   * the same keys, and never refuses them.
   */
  private static keyDigests(tenant: TenantEntry): readonly string[] {
    return tenant.tenantKeyDigests
      .join(",")
      .split(",")
      .map((digest) => digest.trim())
      .filter((digest) => digest !== "");
  }

  /**
   * The tenant's own output: every line a tenant's gateway writes names its
   * tenant, so one process's stream can be read, retained and deleted per
   * tenant. A chained line already carries `tenant` in its envelope, covered
   * by its hash, and is passed through untouched: adding anything to it
   * would break the chain. Any other JSON line gets `tenant` first; anything
   * else is wrapped.
   */
  public static taggedIo(io: GatewayIo, tenant: string): GatewayIo {
    const tag = (line: string): string => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        return JSON.stringify({ tenant, line });
      }
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        return JSON.stringify({ tenant, line });
      }
      if ("tenant" in parsed) return line;
      return Object.keys(parsed).length === 0
        ? JSON.stringify({ tenant, line })
        : `{"tenant":${JSON.stringify(tenant)},${line.trimStart().slice(1)}`;
    };
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

  /**
   * Lets a replaced or removed gateway finish what it has in flight, then
   * stops it, so its shadow report counts what settled while it drained.
   */
  private drain(gateway: Gateway): void {
    this.draining.add(gateway);
    const timer = setTimeout(() => {
      this.timers.delete(timer);
      this.draining.delete(gateway);
      if (this.scheme !== null) gateway.stopped("RELOAD");
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
