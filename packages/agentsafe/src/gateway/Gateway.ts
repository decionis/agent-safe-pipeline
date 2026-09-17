import { randomUUID } from "node:crypto";
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
} from "@decionis/agent-safe-pipeline";
import { ChainJournal } from "../audit/ChainJournal.js";
import { HashChain } from "../audit/HashChain.js";
import { EVIDENCE_STREAM, HashChainedAuditSink } from "../audit/HashChainedAuditSink.js";
import type { LineWriter } from "../audit/LineAuditSink.js";
import { EgressPolicy } from "../egress/EgressPolicy.js";
import { GuardedFetch } from "../egress/GuardedFetch.js";
import type { FetchLike } from "../handlers/HandlerRegistration.js";
import { RequestContext } from "../http/RequestContext.js";
import { SECURITY_STREAM, SecurityEvents } from "../incident/SecurityEvents.js";
import { LineEmitter } from "../logging/LineEmitter.js";
import { CompositeSecretStore } from "../secrets/CompositeSecretStore.js";
import { Redactor } from "../secrets/Redactor.js";
import type { SecretStore } from "../secrets/SecretStore.js";
import { EscalationResolver, type EscalationHandoff } from "../service/EscalationResolver.js";
import { startDemoAuthority, type DemoAuthorityHandle } from "./DemoAuthority.js";
import {
  httpForwardHandler,
  registerHttpActions,
  RequestHolder,
  type ForwardOutcome,
} from "./ForwardHandler.js";
import type { GatewayConfig } from "./GatewayConfig.js";
import { gatewayMetrics, type GatewayMetrics } from "./GatewayMetrics.js";
import {
  renderHuman,
  renderJson,
  type ExecutionDisposition,
  type GatewayReport,
  type GatewayState,
  type InterceptionReport,
} from "./GatewayReport.js";
import { normalizeRequest, type InterceptedRequest } from "./InterceptedRequest.js";
import { RouteTable, type RoutePlan } from "./RouteTable.js";
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
  /** The transport to the upstream; the global fetch when absent. */
  readonly upstreamFetch?: FetchLike;
  readonly secrets?: SecretStore;
  readonly demoAuthority?: () => Promise<DemoAuthorityHandle>;
  readonly clock?: () => number;
  readonly version?: string;
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
}

interface HeldEscalation {
  readonly captured: CapturedIntent;
  readonly request: InterceptedRequest;
  readonly decision: GateDecision;
  readonly handoff: EscalationHandoff | null;
  readonly heldAt: string;
  readonly expiresAt: number;
}

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
  private readonly stopFollowing: readonly (() => void)[];
  private readonly counts: Record<string, number> = {};

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
    security: SecurityEvents,
    private readonly secrets: SecretStore | null,
    private readonly demo: DemoAuthorityHandle | null,
    journal: ChainJournal | null,
    private readonly evidence: HashChain,
    private readonly chain: HashChain,
    private readonly clock: () => number,
    private readonly version: string,
  ) {
    this.capture = new IntentCapture({ audit, ttlSeconds: config.intentTtlSeconds });
    const registry = registerHttpActions(
      new ActionRegistry(),
      routes.actions(),
      httpForwardHandler(upstream, this.holder),
    );
    this.executor = new SafeExecutor(registry, verifier, audit);
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
   * pipeline objects built over it, the evidence chains restored. Nothing
   * listens; the listener is the caller's.
   */
  public static async create(
    config: GatewayConfig,
    dependencies: GatewayDependencies = {},
  ): Promise<Gateway> {
    const env = dependencies.env ?? process.env;
    const clock = dependencies.clock ?? (() => Date.now());
    const version = dependencies.version ?? "0.0.0";
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
    const security = new SecurityEvents(emitter.security, {
      chain: new HashChain(SECURITY_STREAM, journal?.restore(SECURITY_STREAM) ?? null),
    });
    emitter.reportRedactions((patterns) =>
      security.emit({ event: "LEAK_SUSPECTED", patterns: [...patterns] }),
    );
    if (store === null && config.secrets.required.length > 0) {
      store = CompositeSecretStore.fromEnvironment(env, config.secrets.required, {
        events: security,
        production: config.production,
        enforcePermissions: config.production,
        watch: false,
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
    const gate = new DecionisGate({
      ...connection,
      mode: config.authority.mode,
      source: { example: `agentsafe-gateway@${version}` },
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
    const upstream = new Upstream({
      url: config.upstream.url,
      timeoutMs: config.upstream.timeoutMs,
      maxResponseBytes: config.upstream.maxResponseBytes,
      fetch: dependencies.upstreamFetch ?? fetch,
    });
    const routes = new RouteTable(
      config.interception.routes,
      config.interception.unmatched,
      config.interception.http,
    );
    const evidence = new HashChain(EVIDENCE_STREAM, journal?.restore(EVIDENCE_STREAM) ?? null);
    const chain = new HashChain(GATEWAY_STREAM, journal?.restore(GATEWAY_STREAM) ?? null);
    const audit = new AuditRecorder({
      sink: new HashChainedAuditSink(emitLine, evidence),
      failurePolicy: config.evidence.enabled ? "REQUIRE_BEFORE_EXECUTION" : "BEST_EFFORT",
    });
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
    this.link({
      event: "GATEWAY_STARTED",
      mode: this.config.authority.mode,
      authority: this.demo === null ? "decionis" : "local/demo",
    });
  }

  public stopped(signal: string): void {
    this.report({ event: "GATEWAY_STOPPED", at: new Date(this.clock()).toISOString(), signal });
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
    };
  }

  public metricsText(): string {
    return this.metrics.registry.render();
  }

  /** A request that is not consequential: forwarded unchanged, counted, not evaluated. */
  public async passthrough(request: InterceptedRequest): Promise<GatewayResponse> {
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
      return { status: result.status, headers: result.headers, body: result.body };
    } catch (error) {
      return this.upstreamFailure(error);
    }
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
    return await RequestContext.run({ principal: this.principalOf(captured) }, async () => {
      if (this.shadow !== null) return await this.observe(request, captured, startedAt);
      return await this.enforce(request, captured, startedAt);
    });
  }

  /** What a held escalation looks like from outside; null when nothing is held under the id. */
  public escalation(intentId: string): Record<string, unknown> | null {
    const entry = this.held.get(intentId);
    if (entry === undefined) return null;
    return this.holdBody(entry);
  }

  /**
   * Asks the authority again about a held intent. Only a fresh `ALLOW` with
   * a grant executes, once; anything else is still held or refused. The
   * gateway never turns the hold into permission on its own.
   */
  public async resume(intentId: string): Promise<GatewayResponse> {
    this.metrics.requests.inc({ kind: "control" });
    const entry = this.held.get(intentId);
    if (entry === undefined) {
      return this.own(404, {
        state: "ERROR",
        verdict: null,
        reason_codes: ["ESCALATION_NOT_HELD"],
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
    for (const stop of this.stopFollowing) stop();
    this.held.clear();
    if (this.demo !== null) await this.demo.stop();
    this.secrets?.close();
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
    const entry: HeldEscalation = {
      captured,
      request,
      decision,
      handoff: handoff === null ? null : { ...handoff, intent: captured.intent },
      heldAt: new Date(this.clock()).toISOString(),
      expiresAt: Date.parse(captured.intent.expiresAt),
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
      const forwarded = await this.passthrough(request);
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
      return {
        ...forwarded,
        headers: [
          ...forwarded.headers,
          ["agentsafe-state", "AUTHORITY_UNAVAILABLE"],
          ["agentsafe-execution", "FORWARDED_UNGOVERNED"],
        ],
      };
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
    const state: GatewayState = outcome.outcome === "BLOCKED" ? "ERROR" : "EXECUTION_FAILED";
    this.report({
      ...base,
      state,
      reason_codes: [reason],
      execution: "NOT_FORWARDED",
      upstream_status: null,
      finalization,
    });
    return this.own(outcome.outcome === "BLOCKED" ? 503 : 502, {
      state,
      verdict: "ALLOW",
      reason_codes: [reason],
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

  private relay(result: UpstreamResult, extra: Readonly<Record<string, string>>): GatewayResponse {
    return {
      status: result.status,
      headers: [...result.headers, ...Object.entries(extra)],
      body: result.body,
    };
  }

  private upstreamFailure(error: unknown): GatewayResponse {
    const tooLarge = error instanceof Error && error.name === "UpstreamResponseTooLarge";
    return this.own(502, {
      state: "ERROR",
      verdict: null,
      reason_codes: [tooLarge ? "UPSTREAM_RESPONSE_TOO_LARGE" : "UPSTREAM_UNREACHABLE"],
      execution: tooLarge ? "INDETERMINATE" : "NOT_FORWARDED",
    });
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
