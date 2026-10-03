import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import {
  ActionRegistry,
  AuditRecorder,
  DecionisGate,
  DecionisGrantVerifier,
  IntentCapture,
  SafeExecutor,
  ShadowPipeline,
  type CapturedIntent,
  type GateDecision,
  type SafeExecutionResult,
  type ShadowObservation,
  type TrustedIntentContext,
  type WorkloadSignal,
} from "@decionis/agent-safe-pipeline";
import {
  boundarySignal,
  resolveBoundary,
  type EnforcementBoundary,
} from "../boundary/BoundaryIdentity.js";
import { DockerProvenanceProvider } from "../provenance/DockerProvenanceProvider.js";
import { KubernetesProvenanceProvider } from "../provenance/KubernetesProvenanceProvider.js";
import { NoneProvenanceProvider } from "../provenance/NoneProvenanceProvider.js";
import { resolveWorkload, type ProvenanceProvider } from "../provenance/ProvenanceProvider.js";
import { ChainJournal } from "../audit/ChainJournal.js";
import { HashChain } from "../audit/HashChain.js";
import { EVIDENCE_STREAM, HashChainedAuditSink } from "../audit/HashChainedAuditSink.js";
import type { LineWriter } from "../audit/LineAuditSink.js";
import { EgressPolicy } from "../egress/EgressPolicy.js";
import { EgressError } from "../egress/EgressError.js";
import { GuardedFetch, type AddressResolver } from "../egress/GuardedFetch.js";
import type { FetchLike } from "../handlers/HandlerRegistration.js";
import { RequestContext } from "../http/RequestContext.js";
import { SECURITY_STREAM, SecurityEvents } from "../incident/SecurityEvents.js";
import { LineEmitter } from "../logging/LineEmitter.js";
import { CompositeSecretStore } from "../secrets/CompositeSecretStore.js";
import { Redactor } from "../secrets/Redactor.js";
import type { SecretStore } from "../secrets/SecretStore.js";
import { EscalationResolver, type EscalationHandoff } from "../service/EscalationResolver.js";
import { ActivationFunnel, type ActivationMilestone } from "./Activation.js";
import { startDemoAuthority, type DemoAuthorityHandle } from "./DemoAuthority.js";
import {
  httpForwardHandler,
  registerHttpActions,
  RequestHolder,
  type ForwardOutcome,
} from "./ForwardHandler.js";
import { GatewayConfigLoader, type GatewayConfig } from "./GatewayConfig.js";
import { gatewayMetrics, type GatewayMetrics } from "./GatewayMetrics.js";
import { processSurface, type InstallSurface } from "./InstallSurface.js";
import {
  renderHuman,
  renderJson,
  type ExecutionDisposition,
  type GatewayReport,
  type GatewayState,
  type InterceptionReport,
} from "./GatewayReport.js";
import { normalizeRequest, type InterceptedRequest } from "./InterceptedRequest.js";
import { TokenBucket, type RateDecision } from "./RateLimit.js";
import { RefusalSampler } from "./RefusalSampler.js";
import { RouteTable, type RoutePlan } from "./RouteTable.js";
import { enforcementSwitch, ShadowLedger, type ShadowSummary } from "./ShadowLedger.js";

/**
 * When a shadow gateway prints its report unasked: as the count of settled
 * observations reaches each of these, and whenever a day has passed since
 * the last report at the moment an observation settles. A gateway that
 * observes nothing says nothing; the stop always prints one.
 */
export const SHADOW_REPORT_MILESTONES: readonly number[] = [
  10, 100, 1_000, 10_000, 100_000, 1_000_000,
];
export const SHADOW_REPORT_INTERVAL_MS = 24 * 60 * 60 * 1_000;
import { Upstream, type UpstreamResult } from "./Upstream.js";

/** The gateway's own evidence stream: what it did that the pipeline's audit contract has no event for. */
export const GATEWAY_STREAM = "agent-safe.gateway-events/1";
/** Every path under it belongs to the gateway and is never forwarded. */
export const GATEWAY_PREFIX = "/_agentsafe";
/** The version of the wire shape the gateway answers with on its own responses. */
export const GATEWAY_RESPONSE_VERSION = "agent-safe.gateway/1";
/** The most escalations held at once; beyond it a new hold is refused rather than an old one dropped. */
const MAX_HELD = 1_000;
const RETRY_AFTER_SECONDS = 5;
/**
 * The transport codes of a send that ended before a connection to the
 * upstream existed: the name did not resolve, or the connection was refused
 * or never made. Nothing of the request left this process.
 */
const BEFORE_CONNECTION: ReadonlySet<string> = new Set([
  "ENOTFOUND",
  "EAI_AGAIN",
  "EAI_FAIL",
  "ECONNREFUSED",
  "UND_ERR_CONNECT_TIMEOUT",
]);

export interface GatewayResponse {
  readonly status: number;
  readonly headers: readonly (readonly [string, string])[];
  readonly body: Buffer;
}

export interface GatewayIo {
  readonly stdout: (line: string) => void;
  readonly stderr: (line: string) => void;
  readonly color: boolean;
}

export interface GatewayDependencies {
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly io?: GatewayIo;
  /** The transport under the guard for the authority and Presence; `node:https` when absent. */
  readonly authorityFetch?: FetchLike;
  /** The transport to the upstream; the global fetch when absent, or the guarded egress when public-only. */
  readonly upstreamFetch?: FetchLike;
  /** Name resolution for a public-only upstream; the system resolver when absent. */
  readonly upstreamResolve?: AddressResolver;
  readonly secrets?: SecretStore;
  readonly demoAuthority?: () => Promise<DemoAuthorityHandle>;
  readonly clock?: () => number;
  readonly version?: string;
  /**
   * The distribution this process was installed from, carried as `surface`
   * in the `User-Agent` of hosted calls; derived from the process when
   * absent, and `null` when it is not one of the named surfaces.
   */
  readonly surface?: InstallSurface | null;
  /** The provenance providers to ask, in order; the surface picks them when unset. */
  readonly provenance?: readonly ProvenanceProvider[];
  /**
   * What a hosted call names as the example, `agentsafe-gateway@<version>`
   * when absent; `agentsafe test --hosted` names itself, so the authority's
   * record tells a test run from a gateway in service.
   */
  readonly clientExample?: string;
  /**
   * What the gateway this one replaces hands on: its chains are continued,
   * neither restored from the journal nor started again from genesis, and
   * its funnel's milestones are not reported twice.
   */
  readonly continues?: GatewayContinuation;
}

/**
 * A gateway's chains and adoption funnel, handed to the gateway built to
 * replace it. Linking is synchronous, so the replaced gateway, finishing
 * what it has in flight, and its replacement write one sequence per stream.
 */
export interface GatewayContinuation {
  readonly evidence: HashChain;
  readonly gateway: HashChain;
  readonly security: HashChain;
  readonly activation: ActivationFunnel;
}

/** Where a hosted gateway's configuration came from, when a host built it from a tenant registry. */
export interface RegistrySource {
  /** The registry the host last loaded, as a short digest of its text. */
  readonly revision: string;
  /** The tenant's entry this gateway was built from, as a short digest of its fingerprint. */
  readonly entry: string;
}

/** What `/_agentsafe/status` reports: identifiers and counts, never a value. */
export interface GatewayStatus {
  readonly status: "ready";
  readonly version: string;
  readonly mode: "SHADOW" | "ENFORCEMENT";
  readonly authority: string;
  readonly failure_policy: "FAIL_CLOSED" | "FAIL_OPEN";
  readonly upstream: string;
  readonly routes: number;
  readonly held: number;
  readonly counts: Readonly<Record<string, number>>;
  readonly evidence: { readonly seq: number; readonly hash: string };
  /** The adoption milestones this process has reached, with when; never a payload. */
  readonly activation: Readonly<Record<ActivationMilestone, string | null>>;
  /** The distribution this process came from, as sent on hosted calls; null when unknown. */
  readonly surface: InstallSurface | null;
  /** In shadow, what the authority would have decided so far, by verdict and action; null in enforcement. */
  readonly shadow: ShadowSummary | null;
  /**
   * A hosted gateway's tenant, the tenant keys it admits now, each as a
   * short prefix of its digest and never the digest, and the registry it was
   * built from when a host built it; null for a gateway that is not hosted,
   * whose status may answer without the operator's token.
   */
  readonly hosted: {
    readonly tenant: string | null;
    readonly tenant_keys: readonly string[];
    readonly registry: RegistrySource | null;
  } | null;
}

/** How much of a `sha256:` digest a readback shows: enough to tell two apart, never the digest. */
export function shortDigest(digest: string): string {
  return digest.slice(0, "sha256:".length + 12);
}

interface HeldEscalation {
  readonly captured: CapturedIntent;
  readonly request: InterceptedRequest;
  readonly decision: GateDecision;
  readonly handoff: EscalationHandoff | null;
  readonly heldAt: string;
  readonly expiresAt: number;
  /** SHA-256 of the resume token handed to the caller whose request was held; the token itself is not kept. */
  readonly resumeDigest: Buffer;
}

/** Why a caller cannot see or resume a hold: nothing is held, or the token is not the holder's. */
type HoldRefusal = "ESCALATION_NOT_HELD" | "RESUME_TOKEN_INVALID";

/** Why a tenant key refuses a request: none was presented, or not one of the tenant's. */
export type TenantKeyRefusal = "TENANT_KEY_MISSING" | "TENANT_KEY_INVALID";

/**
 * The header a resume token travels in. Never the path or the query: those
 * are what proxies, access logs and this gateway's own report write down.
 */
export const RESUME_TOKEN_HEADER = "agentsafe-resume-token";

/**
 * The HTTP-interception ingress over the unchanged lifecycle. A request the
 * route table calls consequential becomes a captured intent; the authority
 * decides; on `ALLOW` the executor claims the grant and the forwarding
 * handler sends the exact bytes the intent bound; the outcome is finalized
 * and every step is chained evidence. In shadow the request goes through
 * unchanged while the authority is asked what it would have decided.
 * Nothing here decides ALLOW, BLOCK or ESCALATE; it asks, enforces and records.
 */
export class Gateway {
  private readonly held = new Map<string, HeldEscalation>();
  private readonly holder = new RequestHolder();
  private readonly capture: IntentCapture;
  private readonly executor: SafeExecutor;
  private readonly shadow: ShadowPipeline | null;
  private readonly resolver: EscalationResolver | null;
  private readonly stopFollowing: (() => void)[];
  private readonly counts: Record<string, number> = {};
  private readonly activation: ActivationFunnel;
  private readonly ledger = new ShadowLedger();
  private readonly bucket: TokenBucket | null;
  /** The tenant key's refusals on the security stream, bounded per window. */
  private readonly refusals: RefusalSampler<TenantKeyRefusal>;
  private lastShadowReportAt: number;
  /** The tenant keys admitted now: the configuration's, until a host replaces them in place. */
  private admitted: readonly string[];
  private registry: RegistrySource | null = null;

  private constructor(
    public readonly config: GatewayConfig,
    private readonly upstream: Upstream,
    private readonly routes: RouteTable,
    audit: AuditRecorder,
    gate: DecionisGate,
    verifier: DecionisGrantVerifier,
    private readonly metrics: GatewayMetrics,
    private readonly emitLine: LineWriter,
    private readonly io: GatewayIo,
    private readonly security: SecurityEvents,
    private readonly secrets: SecretStore | null,
    private readonly demo: DemoAuthorityHandle | null,
    journal: ChainJournal | null,
    private readonly evidence: HashChain,
    private readonly chain: HashChain,
    private readonly clock: () => number,
    private readonly version: string,
    private readonly surface: InstallSurface | null,
    public readonly boundary: EnforcementBoundary,
    public readonly workload: WorkloadSignal | null,
    activation: ActivationFunnel | null,
  ) {
    this.lastShadowReportAt = clock();
    this.admitted = config.tenantKeys;
    this.capture = new IntentCapture({ audit, ttlSeconds: config.intentTtlSeconds });
    this.bucket = config.rateLimit === null ? null : new TokenBucket(config.rateLimit, clock);
    this.refusals = new RefusalSampler(
      (code) => security.emit({ event: "AUTH_FAILED", method: "tenant_key", code }),
      (code, count) =>
        security.emit({ event: "AUTH_FAILED_SUPPRESSED", method: "tenant_key", code, count }),
    );
    // A funnel handed on keeps reporting through the gateway that made it:
    // the same tenant's output, so a milestone is still reported once.
    this.activation =
      activation ??
      new ActivationFunnel(
        (milestone, at) => this.report({ event: "ACTIVATION", milestone, at }),
        clock,
      );
    const registry = registerHttpActions(
      new ActionRegistry(),
      routes.actions(),
      httpForwardHandler(upstream, this.holder),
    );
    // The executor refuses an intent captured through another boundary: an
    // authority issued at one door is not presentable at the next.
    this.executor = new SafeExecutor(registry, verifier, audit, {
      boundaryId: boundary.boundaryId,
      ...(workload?.digest === undefined ? {} : { workloadDigest: workload.digest }),
    });
    this.shadow =
      config.authority.mode === "SHADOW"
        ? new ShadowPipeline(gate, { audit, timeoutMs: config.authority.timeoutMs })
        : null;
    this.resolver =
      config.authority.mode === "ENFORCEMENT"
        ? new EscalationResolver(config.escalation, gate, audit, {})
        : null;
    this.stopFollowing =
      journal === null
        ? []
        : [
            journal.follow(evidence, security),
            journal.follow(chain, security),
            journal.follow(security.chain, security),
          ];
  }

  /**
   * Assembles the gateway: the secrets it needs opened, the demo authority
   * started when chosen, the guarded egress sealed to the authority, the
   * pipeline objects built over it, the evidence chains restored or
   * continued. Nothing listens; the listener is the caller's.
   */
  public static async create(
    config: GatewayConfig,
    dependencies: GatewayDependencies = {},
  ): Promise<Gateway> {
    const env = dependencies.env ?? process.env;
    const clock = dependencies.clock ?? (() => Date.now());
    const version = dependencies.version ?? "0.0.0";
    const surface = dependencies.surface === undefined ? processSurface(env) : dependencies.surface;
    const io: GatewayIo = dependencies.io ?? {
      stdout: (line) => {
        process.stdout.write(`${line}\n`);
      },
      stderr: (line) => {
        process.stderr.write(`${line}\n`);
      },
      color: process.stdout.isTTY === true && env["NO_COLOR"] === undefined,
    };
    let store: SecretStore | null = dependencies.secrets ?? null;
    const emitter = new LineEmitter(
      { stdout: io.stdout, stderr: io.stderr },
      new Redactor(() =>
        store === null || !(store instanceof CompositeSecretStore)
          ? []
          : store.names().map((name) => store?.get(name).digest() ?? ""),
      ),
    );
    let journal: ChainJournal | null = null;
    if (config.evidence.enabled && config.evidence.journalDir !== null) {
      mkdirSync(config.evidence.journalDir, { recursive: true });
      journal = new ChainJournal(config.evidence.journalDir, { checkpointLines: 100 });
    }
    // Each chain goes on from the gateway this one replaces, else from the
    // head the journal last persisted, else from genesis.
    const continues = dependencies.continues ?? null;
    const takeUp = (stream: string, handed: HashChain | undefined): HashChain =>
      handed ?? new HashChain(stream, journal?.restore(stream) ?? null, config.hostedTenant);
    const security = new SecurityEvents(emitter.security, {
      chain: takeUp(SECURITY_STREAM, continues?.security),
    });
    const securityHead = security.chain.head.seq;
    emitter.reportRedactions((patterns) =>
      security.emit({ event: "LEAK_SUSPECTED", patterns: [...patterns] }),
    );
    if (store === null && config.secrets.required.length > 0) {
      store = CompositeSecretStore.fromEnvironment(env, config.secrets.required, {
        events: security,
        production: config.production,
        enforcePermissions: config.production,
        // A hosted gateway lives as long as its host, and its tenant's
        // workspace key is rotated under it, in a mounted Secret: it watches
        // the file, so a rotation takes effect without a rebuild or a restart.
        watch: config.hosted,
      });
    }
    const secrets = store;
    const demo =
      config.authority.kind === "LOCAL"
        ? await (dependencies.demoAuthority ?? startDemoAuthority)()
        : null;
    const authorityUrl = demo === null ? config.authority.endpoint : demo.baseUrl;
    const egress = new GuardedFetch({
      policy: new EgressPolicy([
        { origin: new URL(authorityUrl).origin, pathPrefixes: ["/"], ca: null, pins: [] },
      ]),
      events: security,
      maxResponseBytes: 1024 * 1024,
      ...(dependencies.authorityFetch === undefined
        ? {}
        : { transport: dependencies.authorityFetch }),
    });
    const apiKey =
      demo !== null
        ? demo.apiKey
        : (): string =>
            secrets === null
              ? ""
              : secrets.get("DECIONIS_API_KEY").use((value) => value.toString("utf8"));
    const connection = {
      baseUrl: authorityUrl,
      apiKey,
      allowInsecureLoopback: demo !== null || config.authority.allowInsecureLoopback,
      timeoutMs: config.authority.timeoutMs,
      fetch: egress.fetch,
    };
    // What a hosted call says about where it came from: the runtime and its
    // version, and the surface it was installed from; never the machine.
    const gate = new DecionisGate({
      ...connection,
      mode: config.authority.mode,
      source: {
        example: dependencies.clientExample ?? `agentsafe-gateway@${version}`,
        ...(surface === null ? {} : { surface }),
      },
    });
    const verifier = new DecionisGrantVerifier(connection);
    const metrics = gatewayMetrics();
    // Evidence lines: always in JSON mode; in human mode to the terminal only
    // when asked, and to the journal directory's file whenever there is one.
    const evidenceFile =
      config.evidence.enabled && config.evidence.journalDir !== null
        ? join(config.evidence.journalDir, "evidence.jsonl")
        : null;
    const toTerminal = config.output.format === "JSON" || config.output.verbose;
    const emitLine: LineWriter = (line) => {
      if (evidenceFile !== null) appendFileSync(evidenceFile, `${line}\n`);
      if (toTerminal) emitter.audit(line);
    };
    // A public-only upstream goes through the guarded egress, sealed to its
    // one origin: every address it resolves to is checked before a socket
    // exists. Its own bounds sit just outside the upstream's, so an answer too
    // large or too slow is still reported the way it always was.
    const upstreamGuard = config.upstream.publicOnly
      ? new GuardedFetch({
          policy: new EgressPolicy([
            {
              origin: new URL(config.upstream.url).origin,
              pathPrefixes: ["/"],
              ca: null,
              pins: [],
            },
          ]),
          events: security,
          maxResponseBytes: config.upstream.maxResponseBytes + 1,
          timeoutMs: config.upstream.timeoutMs + 1_000,
          publicOnly: true,
          ...(dependencies.upstreamFetch === undefined
            ? {}
            : { transport: dependencies.upstreamFetch }),
          ...(dependencies.upstreamResolve === undefined
            ? {}
            : { resolve: dependencies.upstreamResolve }),
        })
      : null;
    const upstream = new Upstream({
      url: config.upstream.url,
      timeoutMs: config.upstream.timeoutMs,
      maxResponseBytes: config.upstream.maxResponseBytes,
      fetch: upstreamGuard?.fetch ?? dependencies.upstreamFetch ?? fetch,
      hostOnlyCookies: config.hosted,
      sandboxed: config.hosted,
      ...(upstreamGuard === null ? {} : { close: () => upstreamGuard.close() }),
    });
    const routes = new RouteTable(
      config.interception.routes,
      config.interception.unmatched,
      config.interception.http,
    );
    const evidence = takeUp(EVIDENCE_STREAM, continues?.evidence);
    const chain = takeUp(GATEWAY_STREAM, continues?.gateway);
    const audit = new AuditRecorder({
      sink: new HashChainedAuditSink(emitLine, evidence),
      failurePolicy: config.evidence.enabled ? "REQUIRE_BEFORE_EXECUTION" : "BEST_EFFORT",
    });
    const boundary = resolveBoundary({
      env,
      version,
      deploymentType: surface,
      environment: config.upstream.environment,
      upstreamOrigin: new URL(config.upstream.url).origin,
      configuredId: config.boundary.id,
    });
    // The providers this runtime can honestly ask, in order. A surface that
    // describes no artifact reaches `NoneProvenanceProvider` and the intent
    // carries no workload at all, which is the answer a policy needs.
    const providers: readonly ProvenanceProvider[] = [
      ...(surface === "docker" ? [new DockerProvenanceProvider()] : []),
      ...(surface === "kubernetes" ? [new KubernetesProvenanceProvider()] : []),
      new NoneProvenanceProvider(),
    ];
    const workload = resolveWorkload(dependencies.provenance ?? providers, { env });
    // A chain that does not start at genesis says where it was taken up, once
    // nothing is left that can refuse the gateway.
    for (const [stream, head] of [
      [SECURITY_STREAM, securityHead],
      [EVIDENCE_STREAM, evidence.head.seq],
      [GATEWAY_STREAM, chain.head.seq],
    ] as const) {
      if (head > 0) security.emit({ event: "CHAIN_RESUMED", chain: stream, head });
    }
    const gateway = new Gateway(
      config,
      upstream,
      routes,
      audit,
      gate,
      verifier,
      metrics,
      emitLine,
      io,
      security,
      secrets,
      demo,
      journal,
      evidence,
      chain,
      clock,
      version,
      surface,
      boundary,
      workload,
      continues?.activation ?? null,
    );
    return gateway;
  }

  public get authorityLabel(): string {
    return this.demo !== null
      ? "local/demo (synthetic policy on loopback; not Decionis)"
      : `decionis ${this.config.authority.endpoint}`;
  }

  public get evidenceLabel(): string {
    if (this.config.evidence.journalDir !== null) {
      return join(this.config.evidence.journalDir, "evidence.jsonl");
    }
    if (this.config.output.format === "JSON" || this.config.output.verbose) return "terminal";
    return "not written; use --verbose or evidence.journalDir";
  }

  /** The banner, once the listener is bound. */
  public started(gatewayUrl: string): void {
    this.report({
      event: "GATEWAY_STARTED",
      at: new Date(this.clock()).toISOString(),
      gateway: gatewayUrl,
      upstream: this.config.upstream.url,
      mode: this.config.authority.mode,
      authority: this.authorityLabel,
      failure_policy: this.config.authority.failurePolicy,
      routes: this.config.interception.routes.length,
      evidence: this.evidenceLabel,
      version: this.version,
    });
    this.report({
      event: "BOUNDARY_IDENTIFIED",
      at: new Date(this.clock()).toISOString(),
      boundary_id: this.boundary.boundaryId,
      boundary_source: this.boundary.boundarySource,
      deployment_type: this.boundary.deploymentType,
      environment: this.boundary.environment,
      protocol_version: this.boundary.protocolVersion,
      conformance_version: this.boundary.conformanceVersion,
    });
    if (this.workload !== null) {
      this.report({
        event: "WORKLOAD_RESOLVED",
        at: new Date(this.clock()).toISOString(),
        runtime: this.workload.runtime ?? null,
        artifact_type: this.workload.artifact_type ?? null,
        image: this.workload.image ?? null,
        digest: this.workload.digest ?? null,
        publisher: this.workload.publisher ?? null,
        source: this.workload.provenance.source,
        trust_level: this.workload.provenance.trust_level,
      });
    }
    this.link({
      event: "GATEWAY_STARTED",
      mode: this.config.authority.mode,
      authority: this.demo === null ? "decionis" : "local/demo",
    });
    this.activation.started({
      mode: this.config.authority.mode,
      authority: this.config.authority.kind,
      production: this.config.production,
    });
  }

  public stopped(signal: string): void {
    const at = new Date(this.clock()).toISOString();
    // A shadow run ends with its report: what enforcement would have changed,
    // and the one switch that turns it on for this configuration.
    if (this.shadow !== null) this.shadowReport(at);
    this.report({ event: "GATEWAY_STOPPED", at, signal });
  }

  /** The shadow report, now: the counts so far and the switch. */
  private shadowReport(at: string): void {
    this.report({
      event: "SHADOW_REPORT",
      at,
      shadow: this.ledger.summary(),
      enforce: enforcementSwitch(this.config),
    });
    this.lastShadowReportAt = this.clock();
  }

  /**
   * The report on its own cadence, so a gateway that runs for weeks is read
   * without being stopped: at each milestone in the count of observations,
   * and once a day has passed since the last report.
   */
  private shadowReportOnCadence(): void {
    const now = this.clock();
    if (
      SHADOW_REPORT_MILESTONES.includes(this.ledger.observed) ||
      now - this.lastShadowReportAt >= SHADOW_REPORT_INTERVAL_MS
    ) {
      this.shadowReport(new Date(now).toISOString());
    }
  }

  public plan(method: string, path: string): RoutePlan {
    return this.routes.plan(method, path);
  }

  public readiness(): { readonly ready: boolean; readonly body: Record<string, unknown> } {
    return {
      ready: true,
      body: {
        ready: true,
        mode: this.config.authority.mode,
        authority: this.demo === null ? "decionis" : "local/demo",
      },
    };
  }

  public status(): GatewayStatus {
    return {
      status: "ready",
      version: this.version,
      mode: this.config.authority.mode,
      authority: this.demo === null ? "decionis" : "local/demo",
      failure_policy: this.config.authority.failurePolicy,
      upstream: this.config.upstream.url,
      routes: this.config.interception.routes.length,
      held: this.held.size,
      counts: { ...this.counts },
      evidence: this.evidence.head,
      activation: this.activation.snapshot(),
      surface: this.surface,
      shadow: this.shadow === null ? null : this.ledger.summary(),
      hosted: this.config.hosted
        ? {
            tenant: this.config.hostedTenant,
            tenant_keys: this.admitted.map(shortDigest),
            registry: this.registry,
          }
        : null,
    };
  }

  /** The tenant keys the gateway admits now, as digests. */
  public get tenantKeys(): readonly string[] {
    return this.admitted;
  }

  /**
   * Replaces the tenant keys the gateway admits, at once and without a
   * rebuild, so a rotation or a revocation changes nothing else: not the
   * chains, the rate, the counts or what is in flight. The digests are held
   * to the configuration's rule; digests that break it are refused whole,
   * and the keys admitted stay as they were.
   */
  public admitKeys(digests: readonly string[]): void {
    this.admitted = GatewayConfigLoader.admittedKeys(digests, this.config.hosted);
  }

  /** The registry a host last loaded, and the entry this gateway was built from, for the status. */
  public builtFrom(source: RegistrySource): void {
    this.registry = source;
  }

  /** What the gateway built to replace this one takes up: its chains and its funnel. */
  public continuation(): GatewayContinuation {
    return {
      evidence: this.evidence,
      gateway: this.chain,
      security: this.security.chain,
      activation: this.activation,
    };
  }

  /**
   * Stops persisting the chains' heads, once the gateway that continues them
   * persists them itself. A replaced gateway still finishing its requests
   * links on the same chains, so its last checkpoint, at the end of its
   * drain, would otherwise land after the live one's.
   */
  public releaseJournal(): void {
    for (const stop of this.stopFollowing.splice(0)) stop();
  }

  /** The switch the shadow report ends with, for whoever renders the status elsewhere. */
  public get enforcementSwitch(): string {
    return enforcementSwitch(this.config);
  }

  public metricsText(): string {
    return this.metrics.registry.render();
  }

  /**
   * A request that is not consequential: forwarded unchanged, counted, not
   * evaluated, and relayed as `PASSTHROUGH`, so a caller can tell an answer
   * that came through the gateway from one that never reached it.
   */
  public async passthrough(request: InterceptedRequest): Promise<GatewayResponse> {
    return await this.forwardUnchanged(request, { "agentsafe-execution": "PASSTHROUGH" });
  }

  /** A consequential request, through the whole lifecycle. */
  public async govern(request: InterceptedRequest, action: string): Promise<GatewayResponse> {
    this.metrics.requests.inc({ kind: "governed" });
    this.count("governed");
    const startedAt = this.clock();
    let captured: CapturedIntent;
    try {
      captured = this.captureIntent(request, action);
    } catch (error) {
      const code = error instanceof Error ? error.message : "INTENT_INVALID";
      return this.own(code === "INTENT_TOO_LARGE" || code === "INTENT_TOO_COMPLEX" ? 413 : 400, {
        state: "ERROR",
        verdict: null,
        reason_codes: [code],
        execution: "NOT_FORWARDED",
      });
    }
    this.metrics.interceptions.inc({ action });
    this.count("interceptions");
    this.activation.intercepted();
    return await RequestContext.run({ principal: this.principalOf(captured) }, async () => {
      if (this.shadow !== null) return await this.observe(request, captured, startedAt);
      return await this.enforce(request, captured, startedAt);
    });
  }

  /**
   * Why a request's tenant key refuses it, or null when it admits it: always
   * admitted when the gateway has no keys; otherwise only a key that hashes
   * to one of them. Every configured digest is compared, in constant time,
   * whether or not an earlier one matched. A refusal is counted and put on
   * the security stream with its reason, never with the value presented:
   * one line each up to a bound per window, and a count of the rest, so a
   * flood without the key cannot grow the chained stream with its rate.
   */
  public keyRefusal(presented: string | undefined): TenantKeyRefusal | null {
    if (this.admitted.length === 0) return null;
    const candidate =
      presented === undefined || presented === ""
        ? null
        : createHash("sha256").update(presented, "utf8").digest();
    let admitted = false;
    for (const digest of this.admitted) {
      const expected = Buffer.from(digest.slice("sha256:".length), "hex");
      if (candidate !== null && timingSafeEqual(candidate, expected)) admitted = true;
    }
    if (admitted) return null;
    const refusal = candidate === null ? "TENANT_KEY_MISSING" : "TENANT_KEY_INVALID";
    this.metrics.requests.inc({ kind: "tenant_key_refused" });
    this.refusals.refuse(refusal);
    return refusal;
  }

  /**
   * Whether the gateway's rate admits one more request now. Taken after the
   * tenant key, so only the tenant's own traffic spends the tenant's rate; a
   * refusal is counted, and says when to try again.
   */
  public rate(): RateDecision {
    if (this.bucket === null) return { admitted: true };
    const decision = this.bucket.take();
    if (!decision.admitted) this.metrics.requests.inc({ kind: "rate_limited" });
    return decision;
  }

  /**
   * What a held escalation looks like from outside, to the caller holding its
   * resume token; otherwise why not. The intent id is a correlation id, written
   * to stdout and to evidence, so it is never enough on its own.
   */
  public escalation(
    intentId: string,
    resumeToken: string | null,
  ): Record<string, unknown> | HoldRefusal {
    const entry = this.heldFor(intentId, resumeToken);
    return typeof entry === "string" ? entry : this.holdBody(entry);
  }

  /**
   * Asks the authority again about a held intent. Only a fresh `ALLOW` with
   * a grant executes, once; anything else is still held or refused. The
   * gateway never turns the hold into permission on its own.
   */
  public async resume(intentId: string, resumeToken: string | null): Promise<GatewayResponse> {
    this.metrics.requests.inc({ kind: "control" });
    const entry = this.heldFor(intentId, resumeToken);
    if (typeof entry === "string") {
      // A wrong token leaves the hold where it is: its owner can still resume.
      return this.own(entry === "ESCALATION_NOT_HELD" ? 404 : 403, {
        state: "ERROR",
        verdict: null,
        reason_codes: [entry],
        execution: "NOT_FORWARDED",
      });
    }
    if (entry.handoff === null || this.resolver === null) {
      return this.own(409, {
        state: "ESCALATE",
        verdict: "ESCALATE",
        reason_codes: ["ESCALATION_NOT_RESUMABLE", "PRESENCE_NOT_CONFIGURED"],
        execution: "HELD",
        intent_id: intentId,
        decision_id: entry.decision.decisionId,
        dossier_id: entry.decision.dossierId,
      });
    }
    const startedAt = this.clock();
    const resolution = await this.resolver.resume(entry.captured, {
      ...entry.handoff,
      intent: entry.captured.intent,
    });
    if (resolution.kind === "PENDING") {
      return this.own(202, {
        state: "ESCALATE",
        verdict: "ESCALATE",
        reason_codes: resolution.reasonCodes,
        execution: "HELD",
        intent_id: intentId,
        decision_id: entry.decision.decisionId,
        dossier_id: entry.decision.dossierId,
        escalation: resolution.handoff,
      });
    }
    this.release(intentId);
    if (resolution.kind === "REFUSED") {
      const state: GatewayState = resolution.failClosed ? "AUTHORITY_UNAVAILABLE" : "BLOCK";
      this.link({
        event: "ESCALATION_REFUSED",
        intent_id: intentId,
        reason_codes: [...resolution.reasonCodes],
        fail_closed: resolution.failClosed,
      });
      return this.own(resolution.failClosed ? 503 : 403, {
        state,
        verdict: resolution.failClosed ? null : "BLOCK",
        reason_codes: resolution.reasonCodes,
        execution: "NOT_FORWARDED",
        intent_id: intentId,
      });
    }
    return await RequestContext.run({ principal: this.principalOf(entry.captured) }, () =>
      this.execute(entry.request, entry.captured, resolution.decision, startedAt, null),
    );
  }

  public async close(): Promise<void> {
    this.refusals.flush();
    this.releaseJournal();
    this.held.clear();
    if (this.demo !== null) await this.demo.stop();
    this.secrets?.close();
    this.upstream.close();
  }

  private captureIntent(request: InterceptedRequest, action: string): CapturedIntent {
    const normalized = normalizeRequest(request, action, {
      maxEmbeddedBodyBytes: this.config.interception.maxEmbeddedBodyBytes,
      principalHeader: this.config.interception.principalHeader,
    });
    const trusted: TrustedIntentContext = {
      tenantId: this.config.authority.tenantId,
      actor: this.config.actor,
      downstreamTarget: {
        system: this.config.upstream.system,
        operation: action,
        environment: this.config.upstream.environment,
        endpoint: this.config.upstream.url,
      },
      context: {
        ...normalized.context,
        ingress: "http",
        ...(normalized.principal === null ? {} : { claimed_principal: normalized.principal }),
      },
      idempotencyKey: normalized.idempotencyKey ?? randomUUID(),
      ...(normalized.correlationId === null ? {} : { correlationId: normalized.correlationId }),
      signals: {
        boundary: boundarySignal(this.boundary),
        ...(this.workload === null ? {} : { workload: this.workload }),
      },
    };
    return this.capture.capture(normalized.proposal, trusted);
  }

  private principalOf(captured: CapturedIntent): string {
    const claimed = captured.intent.context["claimed_principal"];
    return typeof claimed === "string" ? claimed : this.config.actor.id;
  }

  private async observe(
    request: InterceptedRequest,
    captured: CapturedIntent,
    startedAt: number,
  ): Promise<GatewayResponse> {
    const shadow = this.shadow;
    if (shadow === null) throw new Error("MODE_MISMATCH");
    const forwardStarted = this.clock();
    const run = await shadow.observe(captured, () =>
      this.upstream.send(
        request.method.toUpperCase(),
        request.path,
        request.search,
        this.upstream.headersFor(request, { "x-agent-safe-intent-hash": captured.intentHash }),
        request.body,
        this.upstream.signal(),
      ),
    );
    this.metrics.observeForwardLatency(this.clock() - forwardStarted);
    const production = run.production;
    const upstreamStatus = production.status === "COMPLETED" ? production.result.status : null;
    // The observation settles on its own bound and is reported when it does;
    // the client's response never waits for the authority.
    void run.observation.then((observation: ShadowObservation) => {
      this.metrics.shadowDecisions.inc({ verdict: observation.verdict ?? "NONE" });
      this.count("shadow");
      this.ledger.record(
        captured.intent.action,
        observation.verdict,
        new Date(this.clock()).toISOString(),
        upstreamStatus,
      );
      this.report({
        ...this.interception(request, captured, startedAt),
        state: "SHADOW",
        verdict: observation.verdict,
        reason_codes:
          observation.status === "OBSERVED"
            ? observation.reasonCodes
            : [observation.status, ...observation.reasonCodes],
        execution: "PASSTHROUGH",
        decision_id: observation.decisionId,
        dossier_id: observation.dossierId,
        upstream_status: upstreamStatus,
        finalization: null,
        authority_ms: observation.durationMs,
      });
      this.shadowReportOnCadence();
    });
    if (production.status === "FAILED") return this.upstreamFailure(production.error);
    return this.relay(production.result, {
      "agentsafe-mode": "SHADOW",
      "agentsafe-execution": "PASSTHROUGH",
    });
  }

  private async enforce(
    request: InterceptedRequest,
    captured: CapturedIntent,
    startedAt: number,
  ): Promise<GatewayResponse> {
    const escalation = this.resolver;
    if (escalation === null) throw new Error("MODE_MISMATCH");
    const authorityStarted = this.clock();
    const decision = await escalation.evaluate(captured);
    const authorityMs = this.clock() - authorityStarted;
    this.metrics.observeAuthorityLatency(authorityMs);
    if (decision.failClosed) {
      return await this.unavailable(request, captured, decision, startedAt, authorityMs);
    }
    this.metrics.decisions.inc({ verdict: decision.verdict });
    this.activation.governed();
    if (decision.verdict === "ALLOW") {
      this.metrics.allows.inc();
      this.count("allows");
      return await this.execute(request, captured, decision, startedAt, authorityMs);
    }
    // A BLOCK or an ESCALATE goes through the executor too, so the evidence
    // chain carries the refusal in the same shape as an execution.
    await this.executor.run(captured, decision);
    if (decision.verdict === "BLOCK") {
      this.metrics.blocks.inc();
      this.count("blocks");
      this.report({
        ...this.interception(request, captured, startedAt),
        state: "BLOCK",
        verdict: "BLOCK",
        reason_codes: decision.reasonCodes,
        execution: "NOT_FORWARDED",
        decision_id: decision.decisionId,
        dossier_id: decision.dossierId,
        upstream_status: null,
        finalization: null,
        authority_ms: authorityMs,
      });
      return this.own(403, {
        state: "BLOCK",
        verdict: "BLOCK",
        reason_codes: decision.reasonCodes,
        execution: "NOT_FORWARDED",
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
        decision_id: decision.decisionId,
        dossier_id: decision.dossierId,
      });
    }
    this.metrics.escalations.inc();
    this.count("escalations");
    const handoff = await escalation.handoff(captured, decision);
    const reasonCodes = [
      ...decision.reasonCodes,
      ...(handoff === null && this.config.escalation.mode !== "NONE"
        ? ["ESCALATION_HANDOFF_UNAVAILABLE"]
        : []),
    ];
    // The capability to see and resume this hold: handed to the caller whose
    // request it is, once, in this response, and written nowhere else.
    const resumeToken = randomBytes(32).toString("base64url");
    const entry: HeldEscalation = {
      captured,
      request,
      decision,
      handoff: handoff === null ? null : { ...handoff, intent: captured.intent },
      heldAt: new Date(this.clock()).toISOString(),
      expiresAt: Date.parse(captured.intent.expiresAt),
      resumeDigest: Gateway.resumeDigest(resumeToken),
    };
    const heldOk = this.hold(captured.intent.intentId, entry);
    this.link({
      event: "ESCALATION_HELD",
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      decision_id: decision.decisionId,
      dossier_id: decision.dossierId,
      resumable: handoff !== null,
      held: heldOk,
    });
    this.report({
      ...this.interception(request, captured, startedAt),
      state: "ESCALATE",
      verdict: "ESCALATE",
      reason_codes: reasonCodes,
      execution: "HELD",
      decision_id: decision.decisionId,
      dossier_id: decision.dossierId,
      upstream_status: null,
      finalization: null,
      authority_ms: authorityMs,
    });
    return this.own(202, {
      state: "ESCALATE",
      verdict: "ESCALATE",
      reason_codes: heldOk ? reasonCodes : [...reasonCodes, "HOLD_CAPACITY_EXCEEDED"],
      execution: "HELD",
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      decision_id: decision.decisionId,
      dossier_id: decision.dossierId,
      escalation: entry.handoff === null ? null : this.handoffBody(entry.handoff),
      resume: heldOk ? `${GATEWAY_PREFIX}/v1/escalations/${captured.intent.intentId}` : null,
      resume_token: heldOk ? resumeToken : null,
      expires_at: captured.intent.expiresAt,
    });
  }

  /** The authority could not be asked: its own state, and never a policy BLOCK. */
  private async unavailable(
    request: InterceptedRequest,
    captured: CapturedIntent,
    decision: GateDecision,
    startedAt: number,
    authorityMs: number,
  ): Promise<GatewayResponse> {
    const code = decision.reasonCodes[0] ?? "AUTHORITY_UNAVAILABLE";
    this.metrics.authorityErrors.inc({ code });
    this.count("authority_errors");
    // The refusal is evidence in the executor's own shape, fail-open or not.
    await this.executor.run(captured, decision);
    if (this.config.authority.failurePolicy === "FAIL_OPEN") {
      this.metrics.ungoverned.inc();
      this.count("ungoverned");
      this.link({
        event: "EXECUTION_UNGOVERNED",
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
        reason_codes: [...decision.reasonCodes],
        failure_policy: "FAIL_OPEN",
      });
      const forwarded = await this.forwardUnchanged(request, {
        "agentsafe-state": "AUTHORITY_UNAVAILABLE",
        "agentsafe-execution": "FORWARDED_UNGOVERNED",
      });
      this.report({
        ...this.interception(request, captured, startedAt),
        state: "AUTHORITY_UNAVAILABLE",
        verdict: null,
        reason_codes: decision.reasonCodes,
        execution: "FORWARDED_UNGOVERNED",
        decision_id: null,
        dossier_id: null,
        upstream_status: forwarded.status,
        finalization: null,
        authority_ms: authorityMs,
      });
      return forwarded;
    }
    this.report({
      ...this.interception(request, captured, startedAt),
      state: "AUTHORITY_UNAVAILABLE",
      verdict: null,
      reason_codes: decision.reasonCodes,
      execution: "NOT_FORWARDED",
      decision_id: null,
      dossier_id: null,
      upstream_status: null,
      finalization: null,
      authority_ms: authorityMs,
    });
    return this.own(
      503,
      {
        state: "AUTHORITY_UNAVAILABLE",
        verdict: null,
        reason_codes: decision.reasonCodes,
        execution: "NOT_FORWARDED",
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
      },
      { "retry-after": String(RETRY_AFTER_SECONDS) },
    );
  }

  /** An ALLOW: the grant claimed, the exact request sent once, the outcome finalized and relayed. */
  private async execute(
    request: InterceptedRequest,
    captured: CapturedIntent,
    decision: GateDecision,
    startedAt: number,
    authorityMs: number | null,
  ): Promise<GatewayResponse> {
    const intentId = captured.intent.intentId;
    this.holder.hold(intentId, request, {});
    const forwardStarted = this.clock();
    let outcome: SafeExecutionResult<UpstreamResult>;
    let forward: ForwardOutcome;
    try {
      outcome = await this.executor.run<UpstreamResult>(captured, decision);
    } finally {
      forward = this.holder.release(intentId);
    }
    this.metrics.observeForwardLatency(this.clock() - forwardStarted);
    const base = {
      ...this.interception(request, captured, startedAt),
      verdict: "ALLOW" as const,
      decision_id: decision.decisionId,
      dossier_id: decision.dossierId,
      authority_ms: authorityMs,
    };
    const finalization = "finalization" in outcome ? outcome.finalization : null;
    const evidenceHeaders = {
      "agentsafe-decision": "ALLOW",
      ...(decision.dossierId === null ? {} : { "agentsafe-dossier-id": decision.dossierId }),
      "agentsafe-intent-hash": captured.intentHash,
    };
    if (outcome.outcome === "COMPLETED") {
      this.report({
        ...base,
        state: "ALLOW",
        reason_codes: decision.reasonCodes,
        execution: "FORWARDED",
        upstream_status: outcome.result.status,
        finalization,
      });
      return this.relay(outcome.result, { ...evidenceHeaders, "agentsafe-execution": "FORWARDED" });
    }
    if (outcome.outcome === "DEFINITELY_NOT_EXECUTED" && forward.response !== null) {
      this.report({
        ...base,
        state: "EXECUTION_FAILED",
        reason_codes: [outcome.reason],
        execution: "FAILED",
        upstream_status: forward.response.status,
        finalization,
      });
      return this.relay(forward.response, { ...evidenceHeaders, "agentsafe-execution": "FAILED" });
    }
    if (outcome.outcome === "UNKNOWN_AFTER_DISPATCH") {
      this.metrics.indeterminate.inc();
      this.count("indeterminate");
      const codes = [outcome.reason, ...(forward.failure === null ? [] : [forward.failure])];
      this.report({
        ...base,
        state: "EXECUTION_INDETERMINATE",
        reason_codes: codes,
        execution: "INDETERMINATE",
        upstream_status: forward.response?.status ?? null,
        finalization,
      });
      if (forward.response !== null) {
        return this.relay(forward.response, {
          ...evidenceHeaders,
          "agentsafe-execution": "INDETERMINATE",
        });
      }
      return this.own(502, {
        state: "EXECUTION_INDETERMINATE",
        verdict: "ALLOW",
        reason_codes: codes,
        execution: "INDETERMINATE",
        intent_id: intentId,
        intent_hash: captured.intentHash,
        decision_id: decision.decisionId,
        dossier_id: decision.dossierId,
        finalization,
      });
    }
    // Blocked at the claim, or failed before anything was sent: nothing reached the upstream.
    const reason = "reason" in outcome ? outcome.reason : "EXECUTION_BLOCKED";
    // A handler's own refusal code follows the category (PAYLOAD_BINDING_MISMATCH).
    const reasonCodes =
      outcome.outcome === "FAILED_BEFORE_DISPATCH" && outcome.code !== undefined
        ? [reason, outcome.code]
        : [reason];
    const state: GatewayState = outcome.outcome === "BLOCKED" ? "ERROR" : "EXECUTION_FAILED";
    this.report({
      ...base,
      state,
      reason_codes: reasonCodes,
      execution: "NOT_FORWARDED",
      upstream_status: null,
      finalization,
    });
    return this.own(outcome.outcome === "BLOCKED" ? 503 : 502, {
      state,
      verdict: "ALLOW",
      reason_codes: reasonCodes,
      execution: "NOT_FORWARDED",
      intent_id: intentId,
      intent_hash: captured.intentHash,
      decision_id: decision.decisionId,
      dossier_id: decision.dossierId,
      finalization,
    });
  }

  private hold(intentId: string, entry: HeldEscalation): boolean {
    this.expireHeld();
    if (this.held.size >= MAX_HELD) return false;
    this.held.set(intentId, entry);
    this.metrics.held.set(this.held.size);
    return true;
  }

  /**
   * The hold under an id, for the caller presenting its token. A refusal is
   * linked to the evidence stream, because a wrong token for a live hold is
   * someone who read an intent id and is not its caller.
   */
  private heldFor(intentId: string, resumeToken: string | null): HeldEscalation | HoldRefusal {
    this.expireHeld();
    const entry = this.held.get(intentId);
    if (entry === undefined) return "ESCALATION_NOT_HELD";
    if (
      resumeToken === null ||
      !timingSafeEqual(Gateway.resumeDigest(resumeToken), entry.resumeDigest)
    ) {
      this.link({
        event: "ESCALATION_RESUME_REFUSED",
        intent_id: intentId,
        reason_codes: ["RESUME_TOKEN_INVALID"],
      });
      return "RESUME_TOKEN_INVALID";
    }
    return entry;
  }

  private static resumeDigest(resumeToken: string): Buffer {
    return createHash("sha256").update(resumeToken, "utf8").digest();
  }

  private release(intentId: string): void {
    this.held.delete(intentId);
    this.metrics.held.set(this.held.size);
  }

  private expireHeld(): void {
    const now = this.clock();
    for (const [id, entry] of this.held) {
      if (entry.expiresAt <= now) this.held.delete(id);
    }
    this.metrics.held.set(this.held.size);
  }

  private holdBody(entry: HeldEscalation): Record<string, unknown> {
    return {
      version: GATEWAY_RESPONSE_VERSION,
      state: "ESCALATE",
      verdict: "ESCALATE",
      execution: "HELD",
      intent_id: entry.captured.intent.intentId,
      intent_hash: entry.captured.intentHash,
      decision_id: entry.decision.decisionId,
      dossier_id: entry.decision.dossierId,
      reason_codes: entry.decision.reasonCodes,
      held_at: entry.heldAt,
      expires_at: entry.captured.intent.expiresAt,
      resumable: entry.handoff !== null,
      escalation: entry.handoff === null ? null : this.handoffBody(entry.handoff),
    };
  }

  /** The handoff without the intent, which the gateway holds itself. */
  private handoffBody(handoff: EscalationHandoff): Record<string, unknown> {
    const { intent: _intent, ...rest } = handoff;
    void _intent;
    return rest;
  }

  private interception(
    request: InterceptedRequest,
    captured: CapturedIntent,
    startedAt: number,
  ): Omit<
    InterceptionReport,
    | "state"
    | "verdict"
    | "reason_codes"
    | "execution"
    | "decision_id"
    | "dossier_id"
    | "upstream_status"
    | "finalization"
    | "authority_ms"
  > {
    return {
      event: "INTERCEPTED",
      at: new Date(this.clock()).toISOString(),
      method: request.method.toUpperCase(),
      path: request.path,
      action: captured.intent.action,
      mode: this.config.authority.mode,
      authority: this.demo === null ? "decionis" : "local/demo",
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      latency_ms: Math.max(this.clock() - startedAt, 0),
    };
  }

  /**
   * Forwards a request as it came, counted as a passthrough, and relays the
   * answer with the gateway's own headers; a failure is the gateway's own
   * response, which carries its own.
   */
  private async forwardUnchanged(
    request: InterceptedRequest,
    extra: Readonly<Record<string, string>>,
  ): Promise<GatewayResponse> {
    this.metrics.requests.inc({ kind: "passthrough" });
    this.count("passthrough");
    const startedAt = this.clock();
    try {
      const result = await this.upstream.send(
        request.method.toUpperCase(),
        request.path,
        request.search,
        this.upstream.headersFor(request),
        request.body,
        this.upstream.signal(),
      );
      this.metrics.observeForwardLatency(this.clock() - startedAt);
      return this.relay(result, extra);
    } catch (error) {
      return this.upstreamFailure(error);
    }
  }

  private relay(result: UpstreamResult, extra: Readonly<Record<string, string>>): GatewayResponse {
    return {
      status: result.status,
      headers: [...result.headers, ...Object.entries(extra)],
      body: result.body,
    };
  }

  private upstreamFailure(error: unknown): GatewayResponse {
    // A public-only upstream that resolved inward was never connected to.
    if (error instanceof EgressError && error.code === "EGRESS_ADDRESS_REFUSED") {
      return this.own(502, {
        state: "ERROR",
        verdict: null,
        reason_codes: ["UPSTREAM_ADDRESS_REFUSED"],
        execution: "NOT_FORWARDED",
      });
    }
    // Nor was one that did not resolve or would not take a connection.
    if (BEFORE_CONNECTION.has(Gateway.transportCode(error))) {
      return this.own(502, {
        state: "ERROR",
        verdict: null,
        reason_codes: ["UPSTREAM_UNREACHABLE"],
        execution: "NOT_FORWARDED",
      });
    }
    // Anything else may have come after the request was written, and the
    // upstream may have acted on it, so it is never a refusal a caller may
    // retry. A timeout is one wherever the send was when it ran out: the
    // send cannot say whether it had written the request. Too large is the
    // relay's own bound or the guarded egress's just outside it, whichever
    // reader saw it first.
    const tooLarge =
      (error instanceof Error && error.name === "UpstreamResponseTooLarge") ||
      (error instanceof EgressError && error.code === "EGRESS_BODY_TOO_LARGE");
    const timedOut =
      (error instanceof Error && error.name === "TimeoutError") ||
      (error instanceof EgressError && error.code === "EGRESS_TIMEOUT");
    return this.own(502, {
      state: "ERROR",
      verdict: null,
      reason_codes: [
        tooLarge
          ? "UPSTREAM_RESPONSE_TOO_LARGE"
          : timedOut
            ? "UPSTREAM_TIMEOUT"
            : "UPSTREAM_TRANSPORT_FAILED",
      ],
      execution: "INDETERMINATE",
    });
  }

  /** A failed send's transport code: its own, as `node:http` raises it, or its cause's, as `fetch` wraps it. */
  private static transportCode(error: unknown): string {
    const own = (error as { code?: unknown } | null)?.code;
    if (typeof own === "string") return own;
    const cause = (error as { cause?: { code?: unknown } | null } | null)?.cause?.code;
    return typeof cause === "string" ? cause : "";
  }

  /** A response the gateway itself makes: JSON, protective headers, the wire version. */
  private own(
    status: number,
    body: Record<string, unknown> & {
      readonly state: GatewayState;
      readonly verdict: "ALLOW" | "ESCALATE" | "BLOCK" | null;
      readonly reason_codes: readonly string[];
      readonly execution: ExecutionDisposition;
    },
    headers: Readonly<Record<string, string>> = {},
  ): GatewayResponse {
    return {
      status,
      headers: [
        ["content-type", "application/json; charset=utf-8"],
        ["cache-control", "no-store"],
        ["x-content-type-options", "nosniff"],
        ["content-security-policy", "default-src 'none'; frame-ancestors 'none'"],
        ["x-frame-options", "DENY"],
        ["agentsafe-state", body.state],
        ["agentsafe-execution", body.execution],
        ...Object.entries(headers),
      ],
      body: Buffer.from(JSON.stringify({ version: GATEWAY_RESPONSE_VERSION, ...body }), "utf8"),
    };
  }

  private report(report: GatewayReport): void {
    if (this.config.output.format === "JSON") this.io.stdout(renderJson(report));
    else this.io.stdout(renderHuman(report, { color: this.io.color }));
  }

  /** One chained line on the gateway's own stream. */
  private link(fields: Record<string, string | number | boolean | null | string[]>): void {
    this.chain.link({ at: new Date(this.clock()).toISOString(), ...fields }, this.emitLine);
  }

  private count(name: string): void {
    this.counts[name] = (this.counts[name] ?? 0) + 1;
  }
}
