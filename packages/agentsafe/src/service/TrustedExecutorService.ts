import {
  AuditRecorder,
  CanonicalIntentHasher,
  ExecutionIntentSchema,
  IntentCapture,
  type ActionRegistry,
  type CapturedIntent,
  type GateDecision,
  type JsonObject,
  type SafeExecutionResult,
  type TrustedIntentContext,
} from "@decionis/agent-safe-pipeline";
import { readFileSync } from "node:fs";
import { HashChain } from "../audit/HashChain.js";
import { EVIDENCE_STREAM, HashChainedAuditSink } from "../audit/HashChainedAuditSink.js";
import type { LineWriter } from "../audit/LineAuditSink.js";
import type { EscalationMode, ExecutorConfig, ExecutorMode } from "../config/ExecutorConfig.js";
import { HaltSwitch, type HaltState } from "../incident/HaltSwitch.js";
import { InMemoryExecutionJournal } from "../journal/InMemoryExecutionJournal.js";
import type { ExecutionJournal } from "../journal/ExecutionJournal.js";
import { StartupReconciler, type RecoveryReport } from "../journal/StartupReconciler.js";
import { HardLimits } from "../limits/HardLimits.js";
import { callerPrincipal, JournaledRegistry } from "../handlers/JournaledActionHandler.js";
import type { OperatorScope } from "../identity/PrincipalsFile.js";
import { clockSkewGuard } from "../time/ClockSkewGuard.js";
import type { DownstreamCredential } from "../credential/DownstreamCredential.js";
import { PrivateKeyJwtCredential } from "../credential/PrivateKeyJwtCredential.js";
import { SignedRequestCredential } from "../credential/SignedRequestCredential.js";
import { StaticHeaderCredential } from "../credential/StaticHeaderCredential.js";
import { EgressPolicy } from "../egress/EgressPolicy.js";
import { GuardedFetch, type AddressResolver } from "../egress/GuardedFetch.js";
import type { FetchLike, HandlerRegistration } from "../handlers/HandlerRegistration.js";
import { PrincipalRegistry, type Principal } from "../identity/PrincipalRegistry.js";
import { parsePrincipalsFile } from "../identity/PrincipalsFile.js";
import { assertSeparationOfDuties, separationViolated } from "../identity/SeparationOfDuties.js";
import { WorkloadJwtVerifier } from "../identity/WorkloadJwtVerifier.js";
import { executorMetrics, type ExecutorMetrics } from "../incident/Metrics.js";
import { SecurityEvents } from "../incident/SecurityEvents.js";
import { RequestContext } from "../http/RequestContext.js";
import type { PostureState } from "../posture/HostPosture.js";
import type { ReloadReport, SecretStore } from "../secrets/SecretStore.js";
import { AuthorityClients } from "./AuthorityClients.js";
import {
  EscalationHandoffSchema,
  type EscalationDependencies,
  type EscalationHandoff,
  type EscalationState,
} from "./EscalationResolver.js";
import {
  ProposalRequestSchema,
  ReconciliationRequestSchema,
  type ActionResponse,
  type AuthorizationBinding,
  type ProposalRequest,
  type ReconciliationResponse,
} from "./Requests.js";
import { HaltRequestSchema, ResumeRequestSchema } from "./Requests.js";
import { ServiceError } from "./ServiceError.js";

export interface ServiceDependencies extends Omit<EscalationDependencies, "fetch"> {
  /** Where audit lines go; stdout in the process, an array in the proof. */
  readonly emit?: LineWriter;
  /** The transport under the guard; `node:https` when absent. An injected one is still policy-checked. */
  readonly fetch?: FetchLike;
  /** Name resolution for the guard; the system resolver when absent. */
  readonly resolve?: AddressResolver;
  /** Reads a CA bundle the configuration names; the filesystem when absent. */
  readonly readFile?: (path: string) => string;
  /** Where security events go; stderr in the process. */
  readonly security?: SecurityEvents;
  /** Whether a posture drift is standing; an enforcement request is refused while it is. */
  readonly posture?: PostureState;
  /** The evidence chain to link audit lines on; a fresh one from genesis when absent. */
  readonly chain?: HashChain;
  readonly metrics?: ExecutorMetrics;
  /** The principals, when trusted startup code built them; the file or the legacy caller otherwise. */
  readonly principals?: PrincipalRegistry;
  /** Where attempts are journaled; the configured directory unless one is given. */
  readonly journal?: ExecutionJournal;
  /** The stop; one is built from the configuration unless a test hands in its own. */
  readonly halt?: HaltSwitch;
  readonly clock?: () => number;
}

/** What `/v1/control/status` reports: identifiers, counts, and heads, never a value. */
export interface ExecutorStatus {
  readonly status: "ready";
  readonly mode: ExecutorMode;
  readonly escalation: EscalationMode;
  readonly actions: readonly string[];
  readonly posture: { readonly degraded: boolean };
  readonly principals: { readonly mode: "PRINCIPALS" | "LEGACY"; readonly count: number };
  readonly evidence: { readonly seq: number; readonly hash: string };
  readonly secrets: readonly string[];
  readonly halt: HaltState;
  readonly attempts: { readonly open: number; readonly unknown: number };
  readonly limits: {
    readonly currencies: readonly string[];
    readonly windowSeconds: number | null;
  } | null;
}

/** What `/ready` answers, and whether it is ready at all. */
export interface Readiness {
  readonly ready: boolean;
  readonly body: Readonly<Record<string, unknown>>;
}

/**
 * The execution boundary as one process. In `ENFORCEMENT` it asks Decionis,
 * and on an `ALLOW` claims the grant and executes once through the sealed
 * registry; on anything else it answers with the verdict and no grant. An
 * `ESCALATE` is handed back with what the caller needs to resume once a
 * person has answered, in whichever shape the adopter configured. In
 * `SHADOW` it asks what the authority would have decided about an action the
 * caller runs itself, records the observation, and never executes. The grant
 * token, the API keys, the caller token and the downstream credential never
 * appear in a response or an audit line.
 */
export class TrustedExecutorService {
  private readonly hasher = new CanonicalIntentHasher();
  private recovery: RecoveryReport | null = null;

  private constructor(
    private readonly config: ExecutorConfig,
    private readonly secrets: SecretStore,
    private readonly capture: IntentCapture,
    private readonly registry: ActionRegistry,
    private readonly registered: readonly string[],
    private readonly clients: AuthorityClients,
    private readonly posture: PostureState,
    private readonly egress: GuardedFetch,
    /** The security stream this service writes to; a test drives the halt through it. */
    public readonly events: SecurityEvents,
    private readonly chain: HashChain,
    public readonly metrics: ExecutorMetrics,
    public readonly principals: PrincipalRegistry,
    /** The workload token verifier, when the configuration names a JWKS; the door uses it. */
    public readonly jwt: WorkloadJwtVerifier | null,
    private readonly credential: DownstreamCredential,
    private readonly audit: AuditRecorder,
    private readonly journal: ExecutionJournal,
    public readonly haltSwitch: HaltSwitch,
    private readonly limits: HardLimits | null,
    private readonly unsubscribeMetrics: () => void,
  ) {}

  /**
   * Wires the boundary. `handlers` is the adopter's seam: it registers what
   * this process can run, and the registry is sealed the moment it returns.
   * Every credential is read from `secrets` at the moment of use.
   */
  public static create(
    config: ExecutorConfig,
    secrets: SecretStore,
    handlers: HandlerRegistration,
    dependencies: ServiceDependencies = {},
  ): TrustedExecutorService {
    const emit =
      dependencies.emit ??
      ((line: string): void => {
        process.stdout.write(`${line}\n`);
      });
    const events =
      dependencies.security ??
      new SecurityEvents((line) => {
        process.stderr.write(`${line}\n`);
      });
    const chain = dependencies.chain ?? new HashChain(EVIDENCE_STREAM);
    const audit = new AuditRecorder({
      sink: new HashChainedAuditSink(emit, chain),
      failurePolicy: "REQUIRE_BEFORE_EXECUTION",
    });
    // Every connection this process opens, the authority's and the Presence
    // service's included, goes through the one guarded fetch.
    const readFile =
      dependencies.readFile ?? ((path: string): string => readFileSync(path, "utf8"));
    const egress = new GuardedFetch({
      policy: EgressPolicy.fromConfig(config, readFile),
      events,
      maxResponseBytes: config.egress.maxResponseBytes,
      ...(dependencies.fetch === undefined ? {} : { transport: dependencies.fetch }),
      ...(dependencies.resolve === undefined ? {} : { resolve: dependencies.resolve }),
    });
    const credential = TrustedExecutorService.credential(config, secrets, egress.fetch);
    const metrics = dependencies.metrics ?? executorMetrics();
    const journal = dependencies.journal ?? new InMemoryExecutionJournal();
    const halt =
      dependencies.halt ??
      new HaltSwitch({
        events,
        haltFile: config.halt.file,
        authFailures: config.halt.authFailures,
        egressRefusals: config.halt.egressRefusals,
        posture: dependencies.posture ?? { degraded: false },
      });
    // Every handler the registration accepts is wrapped, so the durable
    // claim is not something an adopter can forget to write.
    const registry = new JournaledRegistry(() => journal);
    const registered = handlers({
      registry,
      downstream: config.downstream,
      credential,
      fetch: egress.fetch,
    });
    registry.seal();
    const principals =
      dependencies.principals ??
      TrustedExecutorService.principals(
        config,
        secrets,
        readFile,
        registered,
        config.identity.jwt !== null,
      );
    const jwt = TrustedExecutorService.jwtVerifier(
      config,
      readFile,
      egress.fetch,
      events,
      principals.audiences(),
    );
    assertSeparationOfDuties(
      principals.all,
      config.escalation.mode === "NONE" ? null : config.escalation.approverId,
    );
    if (principals.legacy) events.emit({ event: "LEGACY_PRINCIPAL_MODE" });
    else {
      events.emit({
        event: "PRINCIPALS_LOADED",
        principals: principals.size,
        proposers: principals.proposers.length,
        operators: principals.operators.length,
      });
      if (config.production) {
        for (const principal of principals.all) {
          if (principal.credential.kind === "BEARER") {
            events.emit({ event: "BEARER_PRINCIPAL_CONFIGURED", principal: principal.id });
          }
        }
      }
    }
    // The authority's own answers carry the clock this boundary is bound to,
    // so its fetch, and only its fetch, is measured.
    const authorityFetch = clockSkewGuard(egress.fetch, {
      maxSkewMs: config.maxClockSkewMs,
      events,
      observe: (skew) => metrics.clockSkew.set(skew),
      onExceeded: (skew) => halt.halt("CLOCK_SKEW", `${skew}ms from the authority`),
    });
    const clients = new AuthorityClients({
      config,
      secrets,
      registry,
      audit,
      events,
      fetch: authorityFetch,
      ...(dependencies.presence === undefined ? {} : { presence: dependencies.presence }),
    });
    return new TrustedExecutorService(
      config,
      secrets,
      new IntentCapture({ ttlSeconds: config.intentTtlSeconds }),
      registry,
      registered,
      clients,
      dependencies.posture ?? { degraded: false },
      egress,
      events,
      chain,
      metrics,
      principals,
      jwt,
      credential,
      audit,
      journal,
      halt,
      config.limits === null ? null : new HardLimits(config.limits, dependencies.clock),
      events.subscribe((event) => {
        metrics.observe(event);
        if (event.event === "AUTH_FAILED") halt.recordAuthFailure();
        if (event.event === "EGRESS_REFUSED") halt.recordEgressRefusal();
        if (event.event === "POSTURE_DRIFT") halt.halt("POSTURE_DRIFT", `check ${event.check}`);
      }),
    );
  }

  /** The credential the configuration's kind names, over the secret store and the guarded fetch. */
  private static credential(
    config: ExecutorConfig,
    secrets: SecretStore,
    fetchImpl: FetchLike,
  ): DownstreamCredential {
    const kind = config.downstream.credential;
    switch (kind.kind) {
      case "STATIC_HEADER":
        return new StaticHeaderCredential(kind.header, () => secrets.get("DOWNSTREAM_CREDENTIAL"));
      case "PRIVATE_KEY_JWT":
        return new PrivateKeyJwtCredential(
          { ...kind, timeoutMs: config.downstream.timeoutMs },
          () => secrets.get("DOWNSTREAM_PRIVATE_KEY"),
          fetchImpl,
        );
      case "SIGNED_REQUEST":
        return new SignedRequestCredential(kind, () => secrets.get("DOWNSTREAM_SIGNING_KEY"));
    }
  }

  private static jwtVerifier(
    config: ExecutorConfig,
    readFile: (path: string) => string,
    fetchImpl: FetchLike,
    events: SecurityEvents,
    named: readonly string[],
  ): WorkloadJwtVerifier | null {
    const jwt = config.identity.jwt;
    if (jwt === null) return null;
    let text: string;
    try {
      text = readFile(jwt.jwksFile);
    } catch {
      throw new Error("JWKS_UNAVAILABLE: EXECUTOR_JWKS_FILE");
    }
    return new WorkloadJwtVerifier({
      audiences: [jwt.audience, ...named],
      keys: WorkloadJwtVerifier.parseJwks(text),
      clockToleranceSeconds: jwt.clockToleranceSeconds,
      ...(jwt.jwksUrl === null
        ? {}
        : {
            refresh: {
              url: jwt.jwksUrl,
              fetch: fetchImpl,
              intervalSeconds: jwt.refreshSeconds,
              events,
            },
          }),
    });
  }

  /** The principals file, or the legacy caller; either way checked against what this process runs. */
  private static principals(
    config: ExecutorConfig,
    secrets: SecretStore,
    readFile: (path: string) => string,
    registered: readonly string[],
    jwtConfigured: boolean,
  ): PrincipalRegistry {
    const legacy = config.identity.legacy;
    if (config.identity.principalsFile === null && legacy !== null) {
      return PrincipalRegistry.legacy({
        tenantId: legacy.tenantId,
        actor: legacy.actor,
        registeredActions: registered,
        callerToken: () => secrets.get("EXECUTOR_CALLER_TOKEN").digestBytes(),
      });
    }
    let text: string;
    try {
      text = readFile(config.identity.principalsFile ?? "");
    } catch {
      throw new Error("PRINCIPALS_UNREADABLE: EXECUTOR_PRINCIPALS_FILE");
    }
    return PrincipalRegistry.fromEntries(parsePrincipalsFile(text), {
      registeredActions: registered,
      jwtConfigured,
      mutualTls: config.listener.tls?.clientCaFile != null,
    });
  }

  public get mode(): ExecutorMode {
    return this.config.mode;
  }

  public get escalationMode(): EscalationMode {
    return this.config.escalation.mode;
  }

  /** The actions this process can run, for `/ready`. */
  public get actions(): readonly string[] {
    return this.registered.filter((action) => this.registry.has(action));
  }

  /** Stops following credential rotation and closes every outbound connection; the service answers nothing new after this. */
  public close(): void {
    this.clients.close();
    this.egress.close();
    this.jwt?.stop();
    if (this.credential instanceof PrivateKeyJwtCredential) this.credential.close();
    this.unsubscribeMetrics();
  }

  /** Identifiers, counts and heads for an operator; never a value. */
  public status(caller?: Principal): ExecutorStatus {
    const operator = this.operator(caller, "status");
    this.events.emit({ event: "OPERATOR_ACTION", principal: operator.id, action: "status" });
    return {
      status: "ready",
      mode: this.config.mode,
      escalation: this.config.escalation.mode,
      actions: this.actions,
      posture: { degraded: this.posture.degraded },
      principals: {
        mode: this.principals.legacy ? "LEGACY" : "PRINCIPALS",
        count: this.principals.size,
      },
      evidence: this.chain.head,
      secrets: [...this.config.secrets.required],
      halt: this.haltSwitch.current,
      attempts: {
        open: this.recovery?.attempts.length ?? 0,
        unknown: this.recovery?.unknown ?? 0,
      },
      limits:
        this.limits === null
          ? null
          : {
              currencies: [...this.limits.settings.singleMinor.keys()],
              windowSeconds:
                this.limits.settings.windowCount === null &&
                this.limits.settings.windowSumMinor === null
                  ? null
                  : this.limits.settings.windowSeconds,
            },
    };
  }

  /**
   * What the last process left open, resolved before this one takes a
   * request. Read-only: the provider is asked what it did, never told to do
   * it again.
   */
  public async recover(): Promise<RecoveryReport> {
    const report = await new StartupReconciler({
      journal: this.journal,
      registry: this.registry,
      events: this.events,
    }).recover();
    this.recovery = report;
    this.metrics.openAttempts.set(report.unknown, { state: "UNKNOWN" });
    return report;
  }

  /**
   * Readiness, which is not liveness: a halted executor is alive and
   * deliberately not ready, and so is one that still does not know how an
   * attempt ended when the deployment asked to wait for that.
   */
  public readiness(): Readiness {
    const halt = this.haltSwitch.current;
    const unknown = this.recovery?.unknown ?? 0;
    const waiting = this.config.evidence.readyRequiresNoUnknownAttempts && unknown > 0;
    return {
      ready: !halt.halted && !waiting,
      body: {
        status: halt.halted ? "halted" : waiting ? "recovering" : "ready",
        mode: this.config.mode,
        escalation: this.config.escalation.mode,
        actions: this.actions,
        open_attempts: unknown,
        ...(halt.halted ? { halt: { trigger: halt.trigger, since: halt.since } } : {}),
      },
    };
  }

  /** Stops the executor taking new work, on an operator's word and with a reason. */
  public halt(input: unknown, caller?: Principal): HaltState {
    const operator = this.operator(caller, "halt");
    const parsed = HaltRequestSchema.safeParse(input);
    if (!parsed.success) throw new ServiceError(400, "REQUEST_INVALID");
    this.events.emit({ event: "OPERATOR_ACTION", principal: operator.id, action: "halt" });
    return this.haltSwitch.halt("OPERATOR", parsed.data.reason);
  }

  /** Lets work through again; refused while the cause of the halt still stands. */
  public resumeWork(input: unknown, caller?: Principal): HaltState {
    const operator = this.operator(caller, "resume");
    const parsed = ResumeRequestSchema.safeParse(input);
    if (!parsed.success) throw new ServiceError(400, "REQUEST_INVALID");
    this.events.emit({ event: "OPERATOR_ACTION", principal: operator.id, action: "resume" });
    const resumed = this.haltSwitch.resume(parsed.data.reason);
    if (!resumed.resumed) throw new ServiceError(409, resumed.code ?? "NOT_HALTED");
    return this.haltSwitch.current;
  }

  /** The attempts this process does not know the outcome of: identifiers and states only. */
  public openAttempts(caller?: Principal): {
    readonly attempts: RecoveryReport["attempts"];
    readonly unknown: number;
  } {
    const operator = this.operator(caller, "status");
    this.events.emit({ event: "OPERATOR_ACTION", principal: operator.id, action: "status" });
    return { attempts: this.recovery?.attempts ?? [], unknown: this.recovery?.unknown ?? 0 };
  }

  /** Re-reads every secret file now, on an operator's word; the report names files, never values. */
  public async reloadSecrets(caller?: Principal): Promise<ReloadReport> {
    const operator = this.operator(caller, "secrets.reload");
    this.events.emit({
      event: "OPERATOR_ACTION",
      principal: operator.id,
      action: "secrets.reload",
    });
    return await this.secrets.reload("OPERATOR");
  }

  public metricsText(caller?: Principal): string {
    const operator = this.operator(caller, "metrics");
    this.events.emit({ event: "OPERATOR_ACTION", principal: operator.id, action: "metrics" });
    return this.metrics.registry.render();
  }

  public async propose(input: unknown, caller?: Principal): Promise<ActionResponse> {
    const proposer = this.proposer(caller);
    const parsed = ProposalRequestSchema.safeParse(input);
    if (!parsed.success) throw new ServiceError(400, "REQUEST_INVALID");
    const request = parsed.data;
    // An action this process cannot run is refused before any authority is
    // asked: no dossier, no grant, for something that could never execute;
    // then an action this principal may not propose, before it is captured.
    if (!this.registry.has(request.proposal.action)) {
      throw new ServiceError(422, "ACTION_NOT_REGISTERED");
    }
    if (!proposer.allowedActions.has(request.proposal.action)) {
      throw new ServiceError(403, "ACTION_NOT_PERMITTED_FOR_PRINCIPAL");
    }
    if (
      separationViolated(
        proposer,
        this.config.escalation.mode === "NONE" ? null : this.config.escalation.approverId,
        this.principals.operators,
      )
    ) {
      throw new ServiceError(422, "SEPARATION_OF_DUTIES_VIOLATED");
    }
    const captured = this.captureIntent(request, proposer);
    // Every line this proposal causes names the proposer, whichever
    // transport asked; the door's own scope, when there is one, agrees.
    return await RequestContext.run({ principal: proposer.id }, async () => {
      if (this.config.mode === "SHADOW") {
        const observed = await this.observe(captured);
        this.metrics.proposals.inc({ verdict: observed.verdict ?? "NONE" });
        return observed;
      }
      // A halt and a ceiling are refusals this host makes on its own. Both
      // are recorded as evidence and both happen before the authority is
      // asked, so a refusal costs no dossier and no grant.
      try {
        this.assertNotHalted(captured);
        this.assertWithinLimits(captured, "CHECK");
      } catch (error) {
        if (error instanceof ServiceError) await this.recordRefusal(captured, error.code);
        throw error;
      }
      const answer = await this.enforceAfterPosture(captured);
      this.metrics.proposals.inc({ verdict: answer.verdict ?? "NONE" });
      return answer;
    });
  }

  private async enforceAfterPosture(captured: CapturedIntent): Promise<ActionResponse> {
    this.assertPosture();
    return await this.enforce(captured);
  }

  /** The stop, checked after the intent is captured and before any authority is asked. */
  private assertNotHalted(captured: CapturedIntent): void {
    const halt = this.haltSwitch.current;
    if (!halt.halted) return;
    throw new ServiceError(
      503,
      "EXECUTOR_HALTED",
      {
        mode: this.config.mode,
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
        verdict: "BLOCK",
        decision_id: null,
        dossier_id: null,
        reason_codes: ["EXECUTOR_HALTED"],
        fail_closed: true,
        outcome: "BLOCKED",
        executed: false,
        authorization: null,
        finalization: null,
        result: null,
        recovery: null,
        escalation: null,
      } satisfies ActionResponse,
      30,
    );
  }

  /** The refusal itself is evidence: the same shape the executor uses for a blocked run. */
  private async recordRefusal(captured: CapturedIntent, reason: string): Promise<void> {
    await this.audit.record({
      eventType: "EXECUTION_BLOCKED",
      captured,
      reasonCodes: [reason],
    });
  }

  /** The host's own ceilings, before the authority is asked and again before the run. */
  private assertWithinLimits(captured: CapturedIntent, stage: "CHECK" | "COMMIT"): void {
    if (this.limits === null) return;
    const parameters = captured.intent.parameters;
    const decision =
      stage === "CHECK" ? this.limits.check(parameters) : this.limits.commit(parameters);
    if (decision.allowed) return;
    const value = HardLimits.monetaryValue(parameters);
    this.events.emit({
      event: "HARD_LIMIT_REFUSED",
      code: decision.code,
      currency: value === null || value === "INVALID" ? null : value.currency,
    });
    throw new ServiceError(422, decision.code);
  }

  public async reconcile(input: unknown, caller?: Principal): Promise<ReconciliationResponse> {
    const proposer = this.proposer(caller);
    const parsed = ReconciliationRequestSchema.safeParse(input);
    if (!parsed.success) throw new ServiceError(400, "REQUEST_INVALID");
    // The caller presents the intent it was given; the hash is recomputed
    // here, so a changed intent no longer matches its recovery reference,
    // and the intent must be this principal's own.
    const captured = this.presented(parsed.data.intent);
    this.assertOwn(captured, proposer);
    const outcome = await RequestContext.run({ principal: proposer.id }, () =>
      this.clients.current().executor.reconcile(captured, parsed.data.reference),
    );
    // A resolved attempt is closed in the journal, so the next start does not
    // ask the provider about it again.
    if (outcome.outcome !== "UNKNOWN_AFTER_DISPATCH") {
      try {
        await this.journal.append({
          record: "RECONCILED",
          at: new Date().toISOString(),
          intent_id: captured.intent.intentId,
          intent_hash: captured.intentHash,
          status: outcome.outcome,
          source: "CALLER",
        });
      } catch {
        this.events.emit({ event: "JOURNAL_WRITE_FAILED", record: "RECONCILED" });
      }
    }
    return {
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      outcome: outcome.outcome,
      executed: outcome.executed,
      recovered: "recovered" in outcome ? outcome.recovered : false,
      reason_codes: "reason" in outcome ? [outcome.reason] : [],
      authorization: TrustedExecutorService.binding(outcome.authorization),
      result: outcome.result,
    };
  }

  /**
   * Resumes an open escalation. One bounded lookup: if the person has
   * answered, the authority evaluates the exact intent again and an `ALLOW`
   * executes once; if not, the state comes back to be presented later. An
   * intent past its lifetime is refused before anything is asked.
   */
  public async resume(input: unknown, caller?: Principal): Promise<ActionResponse> {
    const proposer = this.proposer(caller);
    const parsed = EscalationHandoffSchema.safeParse(input);
    if (!parsed.success) throw new ServiceError(400, "REQUEST_INVALID");
    if (this.config.mode === "SHADOW" || this.config.escalation.mode === "NONE") {
      throw new ServiceError(409, "ESCALATION_NOT_CONFIGURED");
    }
    const captured = this.presented(parsed.data.intent);
    this.assertOwn(captured, proposer);
    if (Date.parse(captured.intent.expiresAt) <= Date.now()) {
      throw new ServiceError(409, "INTENT_EXPIRED");
    }
    if (!this.registry.has(captured.intent.action)) {
      throw new ServiceError(422, "ACTION_NOT_REGISTERED");
    }
    this.assertPosture();
    return await RequestContext.run({ principal: proposer.id }, async () => {
      try {
        this.assertNotHalted(captured);
      } catch (error) {
        if (error instanceof ServiceError) await this.recordRefusal(captured, error.code);
        throw error;
      }
      const { escalation, executor } = this.clients.current();
      const resolution = await escalation.resume(captured, parsed.data);
      if (resolution.kind === "DECISION") {
        if (resolution.decision.verdict === "ALLOW" && !resolution.decision.failClosed) {
          this.assertWithinLimits(captured, "COMMIT");
          await this.openAttempt(captured, resolution.decision);
        }
        const outcome = await executor.run(captured, resolution.decision);
        await this.closeAttempt(captured, resolution.decision, outcome);
        this.metrics.executions.inc({ outcome: outcome.outcome });
        return this.response(captured, resolution.decision, outcome, null);
      }
      if (resolution.kind === "PENDING") {
        return this.held(captured, "ESCALATE", resolution.reasonCodes, false, {
          ...resolution.handoff,
          intent: captured.intent,
        });
      }
      return this.held(captured, "BLOCK", resolution.reasonCodes, resolution.failClosed, null);
    });
  }

  /**
   * The attempt, on disk, before the executor may run it. A journal that
   * cannot take the record refuses the proposal rather than executing
   * something no one could reconcile afterwards; with
   * `EXECUTOR_JOURNAL_REQUIRED=false`, outside production, the refusal is
   * downgraded to an event so a developer can run without a volume.
   */
  private async openAttempt(captured: CapturedIntent, decision: GateDecision): Promise<void> {
    try {
      await this.journal.append({
        record: "ATTEMPT_OPENED",
        at: new Date().toISOString(),
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
        idempotency_key: captured.intent.idempotencyKey,
        decision_id: decision.decisionId ?? "",
        dossier_id: decision.dossierId ?? "",
        caller_principal: callerPrincipal(),
        intent: captured.intent as unknown as Record<string, unknown>,
      });
    } catch {
      this.events.emit({ event: "JOURNAL_WRITE_FAILED", record: "ATTEMPT_OPENED" });
      if (this.config.evidence.journalRequired) {
        throw new ServiceError(503, "JOURNAL_UNAVAILABLE");
      }
    }
  }

  /**
   * How the attempt ended, so the next start does not have to ask the
   * provider. An outcome that is unknown is exactly what must not be closed:
   * the attempt stays open, and the next start, or a caller's own
   * reconciliation, resolves it by reading the provider.
   */
  private async closeAttempt(
    captured: CapturedIntent,
    decision: GateDecision,
    outcome: SafeExecutionResult,
  ): Promise<void> {
    if (decision.verdict !== "ALLOW" || decision.failClosed) return;
    if (outcome.outcome === "UNKNOWN_AFTER_DISPATCH") return;
    try {
      await this.journal.append({
        record: "ATTEMPT_CLOSED",
        at: new Date().toISOString(),
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
        outcome: outcome.outcome,
        executed: outcome.executed,
        finalization: "finalization" in outcome ? outcome.finalization : null,
      });
    } catch {
      this.events.emit({ event: "JOURNAL_WRITE_FAILED", record: "ATTEMPT_CLOSED" });
    }
  }

  /** A standing posture drift refuses new enforcement work; nothing that has started is touched. */
  private assertPosture(): void {
    if (this.posture.degraded) throw new ServiceError(503, "POSTURE_DEGRADED");
  }

  /** The proposer a call is made as: the caller the door authenticated, or the legacy caller when the service is used directly. */
  private proposer(caller: Principal | undefined): Principal & {
    readonly tenantId: string;
    readonly actor: NonNullable<Principal["actor"]>;
  } {
    const principal = caller ?? (this.principals.legacy ? this.principals.proposers[0] : undefined);
    if (principal === undefined || principal.role !== "PROPOSER") {
      throw new ServiceError(403, "ROLE_FORBIDDEN");
    }
    if (principal.tenantId === null || principal.actor === null) {
      throw new ServiceError(403, "ROLE_FORBIDDEN");
    }
    return principal as Principal & { tenantId: string; actor: NonNullable<Principal["actor"]> };
  }

  private operator(caller: Principal | undefined, scope: OperatorScope): Principal {
    if (caller === undefined || caller.role !== "OPERATOR")
      throw new ServiceError(403, "ROLE_FORBIDDEN");
    if (!caller.scopes.has(scope)) throw new ServiceError(403, "SCOPE_FORBIDDEN");
    return caller;
  }

  /** An intent presented back must be the caller's own: same principal, tenant, and actor. */
  private assertOwn(
    captured: CapturedIntent,
    proposer: Principal & {
      readonly tenantId: string;
      readonly actor: NonNullable<Principal["actor"]>;
    },
  ): void {
    const intent = captured.intent;
    const own =
      intent.context["caller_principal"] === proposer.id &&
      intent.tenantId === proposer.tenantId &&
      intent.actor.id === proposer.actor.id &&
      intent.actor.type === proposer.actor.type;
    if (!own) throw new ServiceError(403, "INTENT_PRINCIPAL_MISMATCH");
  }

  private captureIntent(
    request: ProposalRequest,
    proposer: Principal & {
      readonly tenantId: string;
      readonly actor: NonNullable<Principal["actor"]>;
    },
  ): CapturedIntent {
    const trusted: TrustedIntentContext = {
      tenantId: proposer.tenantId,
      actor: proposer.actor,
      downstreamTarget: {
        system: this.config.downstream.system,
        operation: this.config.downstream.operation,
        environment: this.config.downstream.environment,
      },
      context: { caller_principal: proposer.id },
      idempotencyKey: request.idempotency_key,
      ...(request.correlation_id === undefined ? {} : { correlationId: request.correlation_id }),
    };
    const parameters: JsonObject = request.proposal.parameters ?? {};
    try {
      return this.capture.capture(
        { action: request.proposal.action, target: request.proposal.target, parameters },
        trusted,
      );
    } catch {
      throw new ServiceError(400, "PROPOSAL_INVALID");
    }
  }

  /** An intent the caller presents back, re-hashed rather than trusted. */
  private presented(intent: Record<string, unknown>): CapturedIntent {
    try {
      return this.hasher.capture(ExecutionIntentSchema.parse(intent));
    } catch {
      throw new ServiceError(400, "INTENT_INVALID");
    }
  }

  private async observe(captured: CapturedIntent): Promise<ActionResponse> {
    const shadow = this.clients.current().shadow;
    if (shadow === null) throw new ServiceError(500, "MODE_MISMATCH");
    // The production action, if any, runs in the caller. What this process
    // contributes in shadow is the observation and its evidence, never an
    // execution and never a grant.
    const comparison = await shadow.compare(captured, () => null);
    const observation = comparison.observation;
    return {
      mode: "SHADOW",
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      verdict: observation.verdict,
      decision_id: observation.decisionId,
      dossier_id: observation.dossierId,
      reason_codes: observation.reasonCodes,
      fail_closed: observation.status !== "OBSERVED",
      outcome: observation.status,
      executed: false,
      authorization: null,
      finalization: null,
      result: null,
      recovery: null,
      escalation: null,
    };
  }

  private async enforce(captured: CapturedIntent): Promise<ActionResponse> {
    const { escalation, executor } = this.clients.current();
    const decision = await escalation.evaluate(captured);
    // Every decision goes through the executor, an ESCALATE or BLOCK included,
    // so the audit stream carries the refusal as well as the execution.
    if (decision.verdict === "ALLOW" && !decision.failClosed) {
      this.assertWithinLimits(captured, "COMMIT");
      await this.openAttempt(captured, decision);
    }
    const outcome = await executor.run(captured, decision);
    await this.closeAttempt(captured, decision, outcome);
    this.metrics.executions.inc({ outcome: outcome.outcome });
    let handoff: EscalationHandoff | null = null;
    let unavailable = false;
    if (decision.verdict === "ESCALATE" && !decision.failClosed) {
      const state: EscalationState | null = await escalation.handoff(captured, decision);
      if (state !== null) handoff = { ...state, intent: captured.intent };
      else if (this.config.escalation.mode !== "NONE") unavailable = true;
    }
    return this.response(
      captured,
      decision,
      outcome,
      handoff,
      unavailable ? ["ESCALATION_HANDOFF_UNAVAILABLE"] : [],
    );
  }

  private response(
    captured: CapturedIntent,
    decision: GateDecision,
    outcome: SafeExecutionResult,
    handoff: EscalationHandoff | null,
    extraReasonCodes: readonly string[] = [],
  ): ActionResponse {
    return {
      mode: "ENFORCEMENT",
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      verdict: decision.verdict,
      decision_id: decision.failClosed ? null : decision.decisionId,
      dossier_id: decision.dossierId,
      reason_codes: [
        ...decision.reasonCodes,
        ...("reason" in outcome && outcome.reason !== "DECISION_NOT_ALLOW" ? [outcome.reason] : []),
        ...extraReasonCodes,
      ],
      fail_closed: decision.failClosed,
      outcome: handoff === null ? outcome.outcome : "ESCALATE_PENDING",
      executed: outcome.executed,
      authorization: TrustedExecutorService.binding(outcome.authorization),
      finalization: "finalization" in outcome ? outcome.finalization : null,
      result: outcome.result,
      recovery:
        outcome.outcome === "UNKNOWN_AFTER_DISPATCH"
          ? { intent: captured.intent, reference: outcome.recovery }
          : null,
      escalation: handoff,
    };
  }

  /** A resumption that produced no new decision: still held, or refused. */
  private held(
    captured: CapturedIntent,
    verdict: "ESCALATE" | "BLOCK",
    reasonCodes: readonly string[],
    failClosed: boolean,
    handoff: EscalationHandoff | null,
  ): ActionResponse {
    return {
      mode: "ENFORCEMENT",
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      verdict,
      decision_id: null,
      dossier_id: null,
      reason_codes: reasonCodes,
      fail_closed: failClosed,
      outcome: handoff === null ? "BLOCKED" : "ESCALATE_PENDING",
      executed: false,
      authorization: null,
      finalization: null,
      result: null,
      recovery: null,
      escalation: handoff,
    };
  }

  private static binding(
    authorization: {
      readonly decisionId: string;
      readonly dossierId: string;
      readonly grantId: string;
      readonly expiresAt: string;
    } | null,
  ): AuthorizationBinding | null {
    if (authorization === null) return null;
    return {
      decision_id: authorization.decisionId,
      dossier_id: authorization.dossierId,
      grant_id: authorization.grantId,
      expires_at: authorization.expiresAt,
    };
  }
}
