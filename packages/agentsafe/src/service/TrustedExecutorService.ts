import { createHash } from "node:crypto";
import {
  type DecisionEvidence,
  AuditRecorder,
  CanonicalIntentHasher,
  ExecutionIntentSchema,
  IntentCapture,
  type ActionRegistry,
  type CapturedIntent,
  type EdgeModule,
  type ExecutionBlockedResult,
  type DecisionGate,
  type JsonObject,
  type SafeExecutionResult,
  type SafeExecutor,
  type TrustedIntentContext,
} from "@decionis/agent-safe-pipeline";
import { readFileSync } from "node:fs";
import { EffectEvidenceRegister } from "../adapters/EffectEvidenceRegister.js";
import { effectBlock } from "../adapters/AdapterActionHandler.js";
import { bindBankingAction, BindingError } from "../adapters/banking/BankingIntentBinder.js";
import { BankingAdapter, BankingActionError } from "../adapters/banking/BankingAdapter.js";
import { isBankingActionName, type BankingAction } from "../adapters/banking/BankingAction.js";
import { matchCardAuthorization } from "../adapters/cards/CardAuthorizationMatcher.js";
import {
  cardExecutionResult,
  cardResultRecord,
  prepareCardPurchase,
} from "../adapters/cards/CardEffect.js";
import {
  bindCardPurchase,
  CardActionError,
  cardAuthorizationOf,
  cardAuthorizationResultOf,
  cardPurchaseOf,
  isCardActionName,
  isCardReference,
  CARD_PURCHASE_ACTION,
  cardTarget,
  type CardAuthorizationRequest,
  type CardPurchase,
} from "../adapters/cards/CardPurchase.js";
import { postgresCardHolds } from "../adapters/cards/CardHolds.js";
import { CardHoldSeal } from "../adapters/cards/CardHoldSeal.js";
import type {
  CardApproval,
  CardHoldStore,
  CardVelocity,
  ClaimedCardAuthorization,
} from "../adapters/cards/CardHoldStore.js";
import { HeldCardGrants } from "../adapters/cards/HeldCardGrants.js";
import { CardHoldStoreError } from "../adapters/cards/PostgresCardHolds.js";
import { jcsDigest } from "../adapters/JcsDigest.js";
import { HashChain } from "../audit/HashChain.js";
import { EVIDENCE_STREAM, HashChainedAuditSink } from "../audit/HashChainedAuditSink.js";
import type { LineWriter } from "../audit/LineAuditSink.js";
import type { EscalationMode, ExecutorConfig, ExecutorMode } from "../config/ExecutorConfig.js";
import { HaltSwitch, type HaltState } from "../incident/HaltSwitch.js";
import { InMemoryExecutionJournal } from "../journal/InMemoryExecutionJournal.js";
import type { ExecutionJournal } from "../journal/ExecutionJournal.js";
import { StartupReconciler, type RecoveryReport } from "../journal/StartupReconciler.js";
import { HardLimits } from "../limits/HardLimits.js";
import {
  callerPrincipal,
  JournaledRegistry,
  requestDigest,
} from "../handlers/JournaledActionHandler.js";
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
import {
  EvidenceError,
  EvidenceExport,
  LineWindow,
  type EvidenceBundle,
} from "../incident/EvidenceExport.js";
import { RequestContext } from "../http/RequestContext.js";
import type { PostureReport, PostureState } from "../posture/HostPosture.js";
import type { ReloadReport, SecretName, SecretStore } from "../secrets/SecretStore.js";
import { AuthorityClients } from "./AuthorityClients.js";
import { packageVersion } from "../Version.js";
import {
  EscalationResumeSchema,
  type AttestationHandoff,
  type AttestationRequirement,
  type EscalationDependencies,
  type EscalationHandoff,
  type EscalationState,
} from "./EscalationResolver.js";
import {
  ProposalRequestSchema,
  ReconciliationRequestSchema,
  type ActionResponse,
  type AuthorizationBinding,
  type CardAuthorizationAnswer,
  type CardResultResponse,
  type ProposalRequest,
  type ReconciliationResponse,
} from "./Requests.js";
import { HaltRequestSchema, ResumeRequestSchema } from "./Requests.js";
import type { LoadPg } from "../edge/EdgeReplay.js";
import { EdgeRuntime } from "./EdgeRuntime.js";
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
  /** Loads the edge evaluator; the configured file unless a test hands in its own. */
  readonly loadEdgeModule?: (path: string) => EdgeModule;
  /** Loads `pg` for the shared replay store; the installed package unless a test hands in its own. */
  readonly loadPg?: LoadPg;
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
/** This package's own version, for a bundle to name what produced it: the manifest's, never a copy of it. */
const PACKAGE_VERSION = packageVersion();

/** The posture as reported, or an empty report when a test injected only a state. */
function reportOf(posture: PostureState | undefined): PostureReport {
  const report = (posture as { readonly report?: PostureReport } | undefined)?.report;
  return report ?? { mode: "ENFORCED", findings: [], failed: [], waived: [] };
}

/**
 * What this process was told, minus every secret: addresses, modes, ceilings
 * and thresholds. A digest over it says two replicas were configured the same
 * way without putting the configuration itself in a bundle.
 */
function nonSecretConfiguration(config: ExecutorConfig): JsonObject {
  return {
    mode: config.mode,
    escalation: config.escalation.mode,
    posture: config.posture.mode,
    authority: config.authority.baseUrl,
    downstream: {
      url: config.downstream.url,
      system: config.downstream.system,
      operation: config.downstream.operation,
      environment: config.downstream.environment,
      credential_kind: config.downstream.credential.kind,
    },
    banking: {
      adapter: config.banking.adapterId,
      version: config.banking.adapterVersion,
      on_effect_mismatch: config.banking.onEffectMismatch,
    },
    journal: { required: config.evidence.journalRequired, dir: config.evidence.journalDir },
    halt: {
      file: config.halt.file,
      auth_failures:
        config.halt.authFailures === null
          ? null
          : `${config.halt.authFailures.count}/${config.halt.authFailures.windowSeconds}`,
      egress_refusals:
        config.halt.egressRefusals === null
          ? null
          : `${config.halt.egressRefusals.count}/${config.halt.egressRefusals.windowSeconds}`,
    },
    limits:
      config.limits === null
        ? null
        : {
            currencies: [...config.limits.singleMinor.keys()],
            window_seconds: config.limits.windowSeconds,
          },
    max_clock_skew_ms: config.maxClockSkewMs,
    decision: {
      authority: config.decision.authority,
      edge:
        config.edge === null
          ? null
          : {
              org_id: config.edge.orgId,
              bundle_source: config.edge.bundle.source,
              refresh_seconds: config.edge.refreshSeconds,
              on_unavailable: config.edge.onUnavailable,
              replay_store: config.edge.replay.store,
              usage_reports: config.edge.usage.signing,
              installation_id: config.edge.usage.installationId,
            },
    },
  };
}

/** An Ed25519 detached JWS over the manifest, from the configured key. */
async function signBundle(secrets: SecretStore, payload: Uint8Array): Promise<string> {
  const { importPKCS8, CompactSign } = await import("jose");
  const pem = secrets.get("EXECUTOR_EVIDENCE_SIGNING_KEY").use((value) => value.toString("utf8"));
  const key = await importPKCS8(pem, "EdDSA");
  return await new CompactSign(payload).setProtectedHeader({ alg: "EdDSA" }).sign(key);
}

/** The provider id an escalation requirement names for Decionis Presence. */
const DECIONIS_PRESENCE_PROVIDER = "decionis";

/** Whose intent a capture is: the principal that asked, and the tenant and actor it carries. */
interface CaptureIdentity {
  readonly id: string;
  readonly tenantId: string;
  readonly actor: NonNullable<Principal["actor"]>;
}

type PendingCardAnswer = Extract<CardAuthorizationAnswer, { readonly decision: "PENDING" }>;

export class TrustedExecutorService {
  private readonly hasher = new CanonicalIntentHasher();
  private recovery: RecoveryReport | null = null;
  /**
   * Authorizations evaluated at the commit boundary and escalated, by id:
   * answered the same way until their intent expires, so a platform that
   * re-presents one is told the same thing and nothing is evaluated twice.
   */
  private readonly pendingCommits = new Map<
    string,
    { readonly digest: string; readonly answer: PendingCardAnswer }
  >();
  /** Bound before any await: one authorization id may claim only one request. */
  private readonly cardClaims = new Map<
    string,
    {
      readonly digest: string;
      readonly answer: Promise<CardAuthorizationAnswer>;
    }
  >();

  private constructor(
    private readonly config: ExecutorConfig,
    private readonly secrets: SecretStore,
    private readonly capture: IntentCapture,
    private readonly registry: ActionRegistry,
    private readonly registered: readonly string[],
    private readonly clients: AuthorityClients,
    private readonly posture: PostureState,
    private readonly egress: GuardedFetch,
    /** Where an incident's evidence is written, when the configuration names a directory. */
    private readonly evidence: EvidenceExport,
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
    /** The effect observations the verifier finalizes with; the cards family registers into it. */
    private readonly effects: EffectEvidenceRegister,
    /** Card grants held for the issuer's authorization, and the authorizations that claimed one. */
    private readonly cards: CardHoldStore,
    /** The shared hold store's hourly sweep, while it runs. */
    private cardsTimer: ReturnType<typeof setInterval> | null = null,
    /** The edge evaluator, when the configuration asks for it. */
    private readonly edge: EdgeRuntime | null = null,
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
    // A bounded window of each stream, so an operator can take a bundle out
    // of a running process during an incident without first arranging log
    // export. The log pipeline is still the durable store, and the bundle
    // says how many lines it no longer held.
    const auditWindow = new LineWindow(config.evidence.windowLines);
    const securityWindow = new LineWindow(config.evidence.windowLines);
    events.tap((line) => securityWindow.push(line));
    const evidenceWriter = auditWindow.tee(emit);
    const audit = new AuditRecorder({
      sink: new HashChainedAuditSink(evidenceWriter, chain),
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
    const effects = new EffectEvidenceRegister();
    const registered = handlers({
      registry,
      downstream: config.downstream,
      credential,
      fetch: egress.fetch,
      effects,
      banking: config.banking,
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
    // The edge evaluator, built once: a module that is not a valid ABI 3
    // module refuses the start here, before anything listens.
    const edge = EdgeRuntime.create({
      config,
      secrets,
      apiKey: (): string => secrets.get("DECIONIS_API_KEY").use((value) => value.toString("utf8")),
      fetch: egress.fetch,
      events,
      chain,
      write: evidenceWriter,
      ...(dependencies.loadEdgeModule === undefined
        ? {}
        : { loadModule: dependencies.loadEdgeModule }),
      ...(dependencies.loadPg === undefined ? {} : { loadPg: dependencies.loadPg }),
      ...(dependencies.clock === undefined ? {} : { clock: dependencies.clock }),
    });
    const clients = new AuthorityClients({
      config,
      edge,
      secrets,
      registry,
      audit,
      events,
      fetch: authorityFetch,
      effects,
      observer: { id: config.banking.adapterId, version: config.banking.adapterVersion },
      // A recovery reference is the caller's claim; the journal is what this
      // process dispatched, so reconciliation is held against it.
      attempts: {
        authorizationsOf: async (captured) =>
          await journal.authorizationsOf(captured.intent.intentId),
      },
      ...(dependencies.presence === undefined ? {} : { presence: dependencies.presence }),
    });
    const posture = dependencies.posture ?? { degraded: false };
    // How many times each credential became current from a changed file.
    // During an incident "was this rotated inside the window?" is one of the
    // first questions, and the count answers it without naming a value.
    const rotations = new Map<SecretName, number>();
    const unsubscribeRotations = config.secrets.required
      .filter((name) => secrets.has(name))
      .map((name) =>
        secrets.onRotate(name, () => rotations.set(name, (rotations.get(name) ?? 0) + 1)),
      );
    const unsubscribeEvents = events.subscribe((event) => {
      metrics.observe(event);
      if (event.event === "AUTH_FAILED") halt.recordAuthFailure();
      if (event.event === "EGRESS_REFUSED") halt.recordEgressRefusal();
      if (event.event === "POSTURE_DRIFT") halt.halt("POSTURE_DRIFT", `check ${event.check}`);
    });
    const evidence = new EvidenceExport({
      dir: config.evidence.exportDir,
      audit: auditWindow,
      security: securityWindow,
      packageVersion: PACKAGE_VERSION,
      imageDigest: config.evidence.imageDigest,
      // The report the process verified at start, or an empty one when a test
      // injected a posture state rather than a checker.
      posture: () => reportOf(dependencies.posture),
      openAttempts: () => ({}),
      heads: () => ({ [chain.stream]: chain.head, [events.chain.stream]: events.chain.head }),
      configuration: () => nonSecretConfiguration(config),
      secrets: () =>
        config.secrets.required.map((name) => ({
          name,
          present: secrets.has(name),
          rotations: rotations.get(name) ?? 0,
        })),
      ...(secrets.has("EXECUTOR_EVIDENCE_SIGNING_KEY")
        ? { sign: async (payload) => await signBundle(secrets, payload) }
        : {}),
      ...(dependencies.clock === undefined
        ? {}
        : { clock: (): Date => new Date((dependencies.clock as () => number)()) }),
    });
    return new TrustedExecutorService(
      config,
      secrets,
      new IntentCapture({ ttlSeconds: config.intentTtlSeconds }),
      registry,
      registered,
      clients,
      posture,
      egress,
      evidence,
      events,
      chain,
      metrics,
      principals,
      jwt,
      credential,
      audit,
      journal,
      halt,
      config.limits === null
        ? null
        : new HardLimits(config.limits, dependencies.clock ?? (() => Date.now())),
      () => {
        for (const stop of unsubscribeRotations) stop();
        unsubscribeEvents();
      },
      effects,
      TrustedExecutorService.cardHolds(config, secrets, clients, dependencies),
      null,
      edge,
    );
  }

  /**
   * Where card holds live: this process, or the store every replica shares,
   * whose rows are sealed under the hold key. A hold or a claim another
   * replica made is admitted here through the executor's own checks, with
   * the claim material that replica sealed.
   */
  private static cardHolds(
    config: ExecutorConfig,
    secrets: SecretStore,
    clients: AuthorityClients,
    dependencies: ServiceDependencies,
  ): CardHoldStore {
    const clock = dependencies.clock;
    if (config.cards.holds.store === "memory") {
      return new HeldCardGrants(clock === undefined ? {} : { clock });
    }
    const { table, namespace } = config.cards.holds;
    return postgresCardHolds({
      databaseUrl: (): string =>
        secrets
          .get("EXECUTOR_CARD_HOLDS_DATABASE_URL")
          .use((value) => value.toString("utf8").trim()),
      seal: (): CardHoldSeal =>
        secrets
          .get("EXECUTOR_CARD_HOLDS_KEY")
          .use((value) => CardHoldSeal.fromText(value.toString("utf8"))),
      namespace,
      table,
      adopt: {
        hold: async (captured, decision) => {
          const { executor } = clients.current();
          const outcome = await executor.adoptHold(captured, decision);
          return outcome.outcome === "HELD" ? { held: outcome.held, executor } : null;
        },
        claim: (captured, decision, authorization, material) => {
          const { executor } = clients.current();
          try {
            return {
              held: executor.adoptClaim(captured, decision, authorization, material),
              executor,
            };
          } catch {
            return null;
          }
        },
      },
      ...(dependencies.loadPg === undefined ? {} : { load: dependencies.loadPg }),
      ...(clock === undefined ? {} : { clock }),
    });
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

  /**
   * Loads the edge evaluator's first bundle and starts its refresh schedule.
   * A first fetch that fails is not a refusal to start: until a bundle
   * loads, decisions follow the configured `onUnavailable`.
   */
  public async startEdge(): Promise<void> {
    await this.edge?.start();
  }

  /**
   * Probes the shared hold store, when there is one: a store that cannot be
   * reached is a refusal to start, since no authorization could then match,
   * and then sweeps it hourly for what lapsed.
   */
  public async startCards(): Promise<void> {
    if (this.cards.kind === "memory") return;
    await this.cards.ready();
    this.cardsTimer ??= setInterval(() => {
      void this.cards.cleanup().catch(() => undefined);
    }, 60 * 60_000);
    this.cardsTimer.unref();
  }

  /** The actions this process can run, for `/ready`. */
  public get actions(): readonly string[] {
    return this.registered.filter((action) => this.registry.has(action));
  }

  /** Stops following credential rotation and closes every outbound connection; the service answers nothing new after this. */
  public close(): void {
    this.edge?.stop();
    if (this.cardsTimer !== null) clearInterval(this.cardsTimer);
    this.cardsTimer = null;
    void this.cards.close().catch(() => undefined);
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
      this.events.emit({ event: "SEPARATION_OF_DUTIES_VIOLATED", principal: proposer.id });
      throw new ServiceError(422, "SEPARATION_OF_DUTIES_VIOLATED");
    }
    const velocity = await this.cardVelocity(request);
    const captured = this.captureIntent(request, proposer, velocity);
    // A producer's signed signals travel beside the intent as evidence, never
    // inside it: the authority verifies them and keeps their facts, and this
    // process keeps nothing of the tokens.
    const evidence: DecisionEvidence | undefined =
      request.signals === undefined ? undefined : { signals: request.signals };
    // Every line this proposal causes names the proposer, whichever
    // transport asked; the door's own scope, when there is one, agrees.
    return await RequestContext.run({ principal: proposer.id }, async () => {
      if (this.config.mode === "SHADOW") {
        const observed = await this.observe(captured, evidence);
        this.metrics.proposals.inc({ verdict: observed.verdict ?? "NONE" });
        return observed;
      }
      // A halt and a ceiling are refusals this host makes on its own. Both
      // are recorded as evidence and both happen before the authority is
      // asked, so a refusal costs no dossier and no grant.
      try {
        this.assertNotHalted(captured);
        this.assertWithinLimits(captured, "CHECK");
        await this.assertCardSpendable(captured);
      } catch (error) {
        if (error instanceof ServiceError) await this.recordRefusal(captured, error.code);
        throw error;
      }
      const answer = await this.enforceAfterPosture(captured, evidence);
      this.metrics.proposals.inc({ verdict: answer.verdict ?? "NONE" });
      return answer;
    });
  }

  private async enforceAfterPosture(
    captured: CapturedIntent,
    evidence?: DecisionEvidence,
  ): Promise<ActionResponse> {
    this.assertPosture();
    return await this.enforce(captured, evidence);
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
        effect: null,
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

  /**
   * One spendable hold per card and merchant: a purchase at a merchant where
   * the card already has one waits until it is authorised or expires,
   * refused before the authority is asked so the refusal costs no dossier
   * and no grant. The same card at another merchant holds in parallel.
   */
  private async assertCardSpendable(captured: CapturedIntent): Promise<void> {
    if (!isCardActionName(captured.intent.action)) return;
    // An intent presented back is re-read here, so a card number written into
    // one after capture is refused like one in a proposal.
    let purchase: CardPurchase;
    try {
      purchase = cardPurchaseOf(captured.intent.parameters);
    } catch (error) {
      throw new ServiceError(422, (error as CardActionError).code);
    }
    const key = { cardTokenRef: purchase.cardTokenRef, merchantId: purchase.merchantId };
    if (await this.cards.spendable(key)) {
      throw new ServiceError(409, "CARD_GRANT_ALREADY_HELD");
    }
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
    // ask the provider about it again. A refused reconciliation resolved
    // nothing: closing on it would let any presented reference, however
    // wrong, take a genuinely open attempt off the next start's list.
    if (outcome.outcome === "COMPLETED" || outcome.outcome === "DEFINITELY_NOT_EXECUTED") {
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
    const effect = this.effect(captured, outcome.result);
    return {
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      outcome: outcome.outcome,
      executed: outcome.executed,
      recovered: "recovered" in outcome ? outcome.recovered : false,
      reason_codes: [
        ...("reason" in outcome ? [outcome.reason] : []),
        ...TrustedExecutorService.effectReasons(effect),
      ],
      authorization: TrustedExecutorService.binding(outcome.authorization),
      result: outcome.result,
      effect,
    };
  }

  /**
   * Resumes an open escalation. One bounded lookup: if the person has
   * answered, the authority evaluates the exact intent again and an `ALLOW`
   * executes once; if not, the state comes back to be presented later. An
   * intent past its lifetime is refused before anything is asked.
   */
  public async resume(input: unknown, caller?: Principal): Promise<ActionResponse> {
    // The proposer that holds the intent resumes it. An operator holding
    // `escalations.resume` (the issuer app's backend, where a cardholder's
    // tap lands) may present a presence provider's attestation for an intent
    // it did not propose, and nothing else: the authority binds the
    // attestation to the intent hash, so the operator adds no authority.
    const proposer = caller?.role === "OPERATOR" ? null : this.proposer(caller);
    const presenter = proposer ?? TrustedExecutorService.presenter(caller as Principal);
    const parsed = EscalationResumeSchema.safeParse(input);
    if (!parsed.success) throw new ServiceError(400, "REQUEST_INVALID");
    const resume = parsed.data;
    // An attestation needs no escalation shape: it is evidence for a fresh
    // evaluation, which any enforcing executor can ask for.
    const attested = resume.mode === "ATTESTATION";
    if (proposer === null && !attested) throw new ServiceError(403, "ROLE_FORBIDDEN");
    if (this.config.mode === "SHADOW" || (!attested && this.config.escalation.mode === "NONE")) {
      throw new ServiceError(409, "ESCALATION_NOT_CONFIGURED");
    }
    const captured = this.presented(resume.intent);
    if (proposer !== null) this.assertOwn(captured, proposer);
    if (Date.parse(captured.intent.expiresAt) <= Date.now()) {
      throw new ServiceError(409, "INTENT_EXPIRED");
    }
    if (!this.registry.has(captured.intent.action)) {
      throw new ServiceError(422, "ACTION_NOT_REGISTERED");
    }
    this.assertPosture();
    return await RequestContext.run({ principal: presenter.id }, async () => {
      try {
        this.assertNotHalted(captured);
        await this.assertCardSpendable(captured);
      } catch (error) {
        if (error instanceof ServiceError) await this.recordRefusal(captured, error.code);
        throw error;
      }
      const { escalation, executor } = this.clients.current();
      if (resume.mode === "ATTESTATION") {
        const decision = await escalation.attest(captured, resume.attestation);
        return await this.decide(captured, decision, executor);
      }
      const resolution = await escalation.resume(captured, resume);
      if (resolution.kind === "DECISION") {
        return await this.decide(captured, resolution.decision, executor);
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
   * A fresh decision on a resumed escalation: a card purchase's grant is held
   * for the issuer, anything else runs once on an `ALLOW`.
   */
  private async decide(
    captured: CapturedIntent,
    decision: DecisionGate,
    executor: SafeExecutor,
  ): Promise<ActionResponse> {
    if (isCardActionName(captured.intent.action)) {
      const held = await this.holdCard(captured, decision, executor);
      if ("mode" in held) return held;
      return this.response(captured, decision, held, null);
    }
    if (decision.verdict === "ALLOW" && !decision.failClosed) {
      this.assertWithinLimits(captured, "COMMIT");
      await this.openAttempt(captured, decision);
    }
    const outcome = await executor.run(captured, decision);
    await this.closeAttempt(captured, decision, outcome);
    this.metrics.executions.inc({ outcome: outcome.outcome });
    return this.response(captured, decision, outcome, null);
  }

  /**
   * The attempt, on disk, before the executor may run it. A journal that
   * cannot take the record refuses the proposal rather than executing
   * something no one could reconcile afterwards; with
   * `EXECUTOR_JOURNAL_REQUIRED=false`, outside production, the refusal is
   * downgraded to an event so a developer can run without a volume.
   */
  private async openAttempt(captured: CapturedIntent, decision: DecisionGate): Promise<void> {
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
    decision: DecisionGate,
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

  /**
   * An operator may present an attestation only under `escalations.resume`;
   * without it the operator is no presenter at all, and the refusal is the
   * door's: a role the route does not admit.
   */
  private static presenter(caller: Principal): Principal {
    if (!caller.scopes.has("escalations.resume")) throw new ServiceError(403, "ROLE_FORBIDDEN");
    return caller;
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

  /**
   * The burst on this card, counted before capture because the store may be
   * shared and is asked asynchronously; a purchase the binder will refuse
   * is not counted, and the binder's own refusal follows.
   */
  private async cardVelocity(request: ProposalRequest): Promise<CardVelocity | null> {
    if (!isCardActionName(request.proposal.action)) return null;
    let purchase: CardPurchase;
    try {
      purchase = cardPurchaseOf(request.proposal.parameters);
    } catch {
      return null;
    }
    return await this.cards.velocity(purchase.cardTokenRef);
  }

  private captureIntent(
    request: ProposalRequest,
    proposer: CaptureIdentity,
    velocity: CardVelocity | null = null,
    extra: JsonObject = {},
  ): CapturedIntent {
    // A BEAP action carries its own canonical form in the parameters, so the
    // transport's name and target are derived from it rather than trusted,
    // and the digests the authority binds its grant to are computed here
    // from the action itself. The proposal schema already refuses a
    // caller-supplied context, so none of this can be presented from outside.
    const bound = isBankingActionName(request.proposal.action)
      ? this.bindBanking(request, proposer)
      : null;
    const card = isCardActionName(request.proposal.action) ? this.bindCard(request) : null;
    const context: JsonObject = {
      caller_principal: proposer.id,
      ...(bound === null ? {} : bound.context),
      ...extra,
    };
    // The burst on this card, counted here because policy counts nothing over
    // time: how many purchases were held for it and claimed lately. Numbers
    // only; the card reference stays in the parameters.
    if (card !== null && velocity !== null) context["card_velocity"] = { ...velocity };
    const trusted: TrustedIntentContext = {
      tenantId: proposer.tenantId,
      actor: proposer.actor,
      downstreamTarget: {
        system: this.config.downstream.system,
        operation: this.config.downstream.operation,
        environment: this.config.downstream.environment,
      },
      context,
      idempotencyKey: request.idempotency_key,
      ...(request.correlation_id === undefined ? {} : { correlationId: request.correlation_id }),
      ...(bound === null ? {} : { expectedEffectDigest: bound.expectedEffectDigest }),
      ...(card === null ? {} : { expectedEffectDigest: card.expectedEffectDigest }),
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

  /**
   * The banking binder. Every disagreement between what the caller said over
   * the transport and what the canonical action says is a refusal before the
   * authority is asked, so a mismatch costs no dossier and no grant.
   */
  private bindBanking(
    request: ProposalRequest,
    proposer: { readonly actor: NonNullable<Principal["actor"]> },
  ): { readonly context: JsonObject; readonly expectedEffectDigest: string } {
    try {
      const bound = bindBankingAction(
        {
          action: request.proposal.action,
          target: request.proposal.target,
          parameters: request.proposal.parameters ?? {},
          idempotencyKey: request.idempotency_key,
          downstream: this.config.downstream,
          actor: proposer.actor,
        },
        (action) => this.bankingDigests(action),
      );
      return { context: bound.context, expectedEffectDigest: bound.expectedEffectDigest };
    } catch (error) {
      if (error instanceof BindingError) throw new ServiceError(422, error.code);
      if (error instanceof BankingActionError) throw new ServiceError(422, error.code);
      throw new ServiceError(422, "BANKING_ACTION_INVALID");
    }
  }

  /**
   * The cards binder: the purchase is read and refused here, a card number
   * above all, and the target is derived from the card. What comes back is
   * the expected-effect digest the authority binds its grant to.
   */
  private bindCard(request: ProposalRequest): {
    readonly expectedEffectDigest: string;
    readonly cardTokenRef: string;
  } {
    try {
      const purchase = bindCardPurchase({
        target: request.proposal.target,
        parameters: request.proposal.parameters ?? {},
      });
      return {
        expectedEffectDigest: prepareCardPurchase(purchase).expectedEffectDigest,
        cardTokenRef: purchase.cardTokenRef,
      };
    } catch (error) {
      throw new ServiceError(422, (error as CardActionError).code);
    }
  }

  /** The hold's routing as the handoff carries it, from the decision when the authority said. */
  private static attestationRequirement(decision: DecisionGate): AttestationRequirement | null {
    const routing = decision.escalationRequirement;
    if (routing === undefined) return null;
    return {
      requirement_id: routing.requirementId,
      expires_at: routing.expiresAt,
      selector:
        routing.selector === null
          ? null
          : {
              kind: routing.selector.kind,
              ...(routing.selector.roleId === undefined
                ? {}
                : { role_id: routing.selector.roleId }),
            },
      verification:
        routing.verification === null
          ? null
          : {
              provider: routing.verification.provider,
              methods: [...routing.verification.methods],
              level: routing.verification.level,
            },
    };
  }

  /** Whether the policy sent the hold to a presence provider other than Decionis Presence. */
  private static routedToProvider(
    requirement: AttestationRequirement | null,
  ): requirement is AttestationRequirement {
    return (
      requirement !== null &&
      requirement.verification !== null &&
      requirement.verification.provider !== DECIONIS_PRESENCE_PROVIDER
    );
  }

  /**
   * The two digests a banking intent is bound to, taken from the profile's
   * own arithmetic. This reaches nothing: `prepare` is pure, which is why
   * the transport it is handed refuses to be used.
   */
  private bankingDigests(action: BankingAction): {
    readonly intentDigest: string;
    readonly expectedEffectDigest: string;
  } {
    const prepared = new BankingAdapter({
      id: this.config.banking.adapterId,
      version: this.config.banking.adapterVersion,
      transport: {
        execute: () => Promise.reject(new BankingActionError("BANKING_PREPARE_ONLY")),
        reconcile: () => Promise.reject(new BankingActionError("BANKING_PREPARE_ONLY")),
      },
    }).prepare(action);
    return {
      intentDigest: prepared.intentDigest,
      expectedEffectDigest: prepared.expectedEffectDigest,
    };
  }

  /**
   * What the adapter observed, for the response and for the stream. An
   * observation that does not match what was authorised is the institution's
   * exception: it is named in the evidence, counted, and by default it stops
   * the executor, because the next proposal would otherwise be made against
   * a state nobody has reconciled.
   */
  private effect(captured: CapturedIntent, result: unknown): JsonObject | null {
    const block = effectBlock(result);
    if (block === null) return null;
    const comparison = block["comparison"];
    const fields = Array.isArray(block["mismatched_fields"])
      ? block["mismatched_fields"].filter((field): field is string => typeof field === "string")
      : [];
    const receipt = block["receipt_comparison"];
    this.events.emit({
      event: "EFFECT_OBSERVED",
      intent_id: captured.intent.intentId,
      comparison: comparison === "MATCH" || comparison === "MISMATCH" ? comparison : "PENDING",
      confirmation: typeof block["confirmation"] === "string" ? block["confirmation"] : "UNKNOWN",
      receipt:
        receipt === "MATCH" || receipt === "MISMATCH" || receipt === "SILENT" ? receipt : "ABSENT",
    });
    if (receipt === "MISMATCH") {
      // The provider's own signed statement disagrees with this executor's
      // account: the same exception as an observation that does not match,
      // from the other witness.
      this.events.emit({
        event: "EFFECT_RECEIPT_MISMATCH",
        intent_id: captured.intent.intentId,
        receipt_status:
          typeof block["receipt_status"] === "string" ? block["receipt_status"] : "UNKNOWN",
      });
      if (this.config.banking.onEffectMismatch === "HALT") {
        this.haltSwitch.halt(
          "EFFECT_MISMATCH",
          "the provider's receipt contradicts the observation",
        );
      }
    }
    if (comparison === "PENDING") {
      // Committed, and nothing has read the effect back. Worth alerting on:
      // a provider that is always pending is a read-back that is not wired.
      this.events.emit({
        event: "EFFECT_PENDING_CONFIRMATION",
        intent_id: captured.intent.intentId,
        method:
          typeof block["observation_method"] === "string" ? block["observation_method"] : "UNKNOWN",
      });
    }
    if (block["outcome"] === "FAILED") {
      this.events.emit({
        event: "PROVIDER_REFUSED",
        intent_id: captured.intent.intentId,
        code: TrustedExecutorService.effectReasons(block)[0] ?? "PROVIDER_REFUSED",
      });
    }
    if (comparison !== "MISMATCH") return block;
    this.events.emit({
      event: "EFFECT_MISMATCH",
      intent_id: captured.intent.intentId,
      fields: fields.slice(0, 16),
    });
    if (this.config.banking.onEffectMismatch === "HALT") {
      this.haltSwitch.halt("EFFECT_MISMATCH", `${fields.length} field(s) differ from the grant`);
    }
    return block;
  }

  /** The reason codes an effect block contributes to the response. */
  private static effectReasons(effect: JsonObject | null): readonly string[] {
    const codes = effect?.["reason_codes"];
    if (!Array.isArray(codes)) return [];
    return codes.filter((code): code is string => typeof code === "string");
  }

  /** An intent the caller presents back, re-hashed rather than trusted. */
  private presented(intent: Record<string, unknown>): CapturedIntent {
    try {
      return this.hasher.capture(ExecutionIntentSchema.parse(intent));
    } catch {
      throw new ServiceError(400, "INTENT_INVALID");
    }
  }

  private async observe(
    captured: CapturedIntent,
    evidence?: DecisionEvidence,
  ): Promise<ActionResponse> {
    const shadow = this.clients.current().shadow;
    if (shadow === null) throw new ServiceError(500, "MODE_MISMATCH");
    // The production action, if any, runs in the caller. What this process
    // contributes in shadow is the observation and its evidence, never an
    // execution and never a grant.
    const comparison = await shadow.compare(
      captured,
      () => null,
      evidence === undefined ? {} : { evidence },
    );
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
      effect: null,
      recovery: null,
      escalation: null,
    };
  }

  private async enforce(
    captured: CapturedIntent,
    evidence?: DecisionEvidence,
  ): Promise<ActionResponse> {
    const { escalation, executor } = this.clients.current();
    const decision = await escalation.evaluate(captured, evidence);
    const card = isCardActionName(captured.intent.action);
    let outcome: SafeExecutionResult;
    if (card) {
      // A card purchase is answered before the issuer ever asks: on an ALLOW
      // the grant is held, not claimed, and the response says so.
      const held = await this.holdCard(captured, decision, executor);
      if ("mode" in held) return held;
      outcome = held;
    } else {
      // Every decision goes through the executor, an ESCALATE or BLOCK
      // included, so the audit stream carries the refusal as well as the
      // execution.
      if (decision.verdict === "ALLOW" && !decision.failClosed) {
        this.assertWithinLimits(captured, "COMMIT");
        await this.openAttempt(captured, decision);
      }
      outcome = await executor.run(captured, decision);
      await this.closeAttempt(captured, decision, outcome);
      this.metrics.executions.inc({ outcome: outcome.outcome });
    }
    let handoff: EscalationHandoff | AttestationHandoff | null = null;
    let unavailable = false;
    if (decision.verdict === "ESCALATE" && !decision.failClosed) {
      const requirement = TrustedExecutorService.attestationRequirement(decision);
      if (TrustedExecutorService.routedToProvider(requirement)) {
        // The policy sent this hold to a third-party presence provider (a
        // cardholder's tap through the issuer's app): no Presence ceremony
        // is asked for, and only that provider's attestation resumes it.
        handoff = { mode: "ATTESTATION", intent: captured.intent, requirement };
      } else {
        const state: EscalationState | null = await escalation.handoff(captured, decision);
        if (state !== null) handoff = { ...state, intent: captured.intent };
        // A cardholder's tap needs no Presence ceremony: whatever shape this
        // executor escalates in, a card purchase can be resumed with an
        // attestation over the intent it is handed here.
        else if (card) handoff = { mode: "ATTESTATION", intent: captured.intent, requirement };
        else if (this.config.escalation.mode !== "NONE") unavailable = true;
      }
    }
    return this.response(
      captured,
      decision,
      outcome,
      handoff,
      unavailable ? ["ESCALATION_HANDOFF_UNAVAILABLE"] : [],
    );
  }

  /**
   * Admits a card purchase's decision exactly as a run would and holds its
   * grant for the issuer's authorization, keyed by the card and the
   * merchant. Nothing is
   * claimed and nothing runs; the hard ceilings are committed now, because
   * this is the last moment this process decides anything about the amount.
   * A refusal comes back as the executor's own blocked result.
   */
  private async holdCard(
    captured: CapturedIntent,
    decision: DecisionGate,
    executor: SafeExecutor,
  ): Promise<ActionResponse | ExecutionBlockedResult> {
    if (decision.verdict === "ALLOW" && !decision.failClosed) {
      this.assertWithinLimits(captured, "COMMIT");
    }
    const outcome = await executor.hold(captured, decision);
    if (outcome.outcome !== "HELD") {
      this.metrics.executions.inc({ outcome: outcome.outcome });
      return outcome;
    }
    const purchase = cardPurchaseOf(captured.intent.parameters);
    const stored = await this.cards.hold({
      cardTokenRef: purchase.cardTokenRef,
      amountMinor: purchase.amountMinor,
      currency: purchase.currency,
      merchantId: purchase.merchantId,
      mcc: purchase.mcc ?? null,
      expiresAtMs: Date.parse(outcome.held.expiresAt),
      used: false,
      purchase,
      prepared: prepareCardPurchase(purchase),
      held: outcome.held,
      executor,
    });
    // A card that gained a spendable hold while this one was being decided,
    // or a full store: the grant is left unclaimed and expires with no effect.
    const status = stored ? "HELD_FOR_AUTHORIZATION" : "BLOCKED";
    this.metrics.executions.inc({ outcome: status });
    if (stored) this.events.emit({ event: "CARD_GRANT_HELD", intent_id: captured.intent.intentId });
    return {
      mode: "ENFORCEMENT",
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      verdict: decision.verdict,
      decision_id: decision.decisionId,
      dossier_id: decision.dossierId,
      reason_codes: stored
        ? [...decision.reasonCodes]
        : [...decision.reasonCodes, "CARD_HOLD_UNAVAILABLE"],
      fail_closed: false,
      outcome: status,
      executed: false,
      authorization: null,
      finalization: null,
      result: stored
        ? { status: "HELD_FOR_AUTHORIZATION", expires_at: outcome.held.expiresAt }
        : null,
      effect: null,
      recovery: null,
      escalation: null,
    };
  }

  /**
   * The issuer's real-time authorization hook. The answer has to come back in
   * milliseconds, so the only network call is the claim itself: the match is
   * pure, against a grant decided before the card was presented. A match
   * claims the grant once, and a second authorization for it is a
   * `NO_MATCH`; an issuer retrying the same authorization is given the same
   * answer, with no second claim. What `NO_MATCH` means for the purchase is
   * the issuer's policy, not this process's.
   */
  public async authorizeCard(input: unknown, caller?: Principal): Promise<CardAuthorizationAnswer> {
    const operator = this.operator(caller, "cards.authorize");
    const request = TrustedExecutorService.cardRequest(() => cardAuthorizationOf(input));
    let previous: ClaimedCardAuthorization | undefined;
    try {
      previous = await this.cards.claimed(request.authorization_id);
    } catch {
      return this.noMatch(null, "CARD_HOLDS_UNAVAILABLE");
    }
    if (previous !== undefined) {
      if (jcsDigest(previous.request as JsonObject) === jcsDigest(request as JsonObject)) {
        return previous.answer;
      }
      // An issuer that may present the same authorization for more, up to
      // the ceiling and before its result, is answered from the same claim:
      // nothing new is claimed, and the result records the final amount.
      if (
        this.config.cards.authorizations === "incremental" &&
        TrustedExecutorService.incrementOf(previous, request) &&
        (await this.cards.amend(request.authorization_id, request))
      ) {
        this.events.emit({
          event: "CARD_AUTHORIZATION_INCREMENTED",
          intent_id: previous.answer.intent_id,
        });
        return previous.answer;
      }
      return this.noMatch(null, "AUTHORIZATION_ID_REUSED");
    }
    const digest = jcsDigest(request as JsonObject);
    const pending = this.cardClaims.get(request.authorization_id);
    if (pending !== undefined) {
      return pending.digest === digest
        ? await pending.answer
        : this.noMatch(null, "AUTHORIZATION_ID_REUSED");
    }
    if (this.cardClaims.size >= 10_000) {
      return this.noMatch(null, "CARD_AUTHORIZATION_CAPACITY_EXCEEDED");
    }
    // Reserve the id synchronously, before journal/claim I/O can yield to a
    // conflicting request. Identical concurrent retries share the same result.
    const answer = Promise.resolve().then(() => this.claimCard(request, operator.id));
    this.cardClaims.set(request.authorization_id, { digest, answer });
    try {
      return await answer;
    } finally {
      this.cardClaims.delete(request.authorization_id);
    }
  }

  private async claimCard(
    request: CardAuthorizationRequest,
    callerId: string,
    evaluated = false,
  ): Promise<CardAuthorizationAnswer> {
    if (this.haltSwitch.current.halted) return this.noMatch(null, "EXECUTOR_HALTED");
    if (this.posture.degraded) return this.noMatch(null, "POSTURE_DEGRADED");
    let record;
    try {
      record = await this.cards.grant({
        cardTokenRef: request.card_token_ref,
        merchantId: request.merchant_id,
      });
    } catch {
      return this.noMatch(null, "CARD_HOLDS_UNAVAILABLE");
    }
    if (record === undefined) {
      // A hold the commit-boundary evaluation just made and the store cannot
      // show is not evaluated again: the answer says the hold was lost.
      if (evaluated) return this.noMatch(null, "CARD_HOLD_UNAVAILABLE");
      return await this.withoutGrant(request, callerId);
    }
    const match = matchCardAuthorization(
      record,
      TrustedExecutorService.cardView(request),
      Date.now(),
    );
    if (match.decision === "NO_MATCH") return this.noMatch(record.intentId, match.code);
    // The hold with a handle this process can claim; one another replica
    // made is admitted here first, through the executor's own checks.
    let matched;
    try {
      matched = await record.open();
    } catch {
      return this.noMatch(record.intentId, "CARD_HOLDS_UNAVAILABLE");
    }
    if (matched === null) return this.noMatch(record.intentId, "GRANT_CLAIM_REFUSED");
    // Spent before anything else is awaited, by the one rule every replica
    // shares, so a concurrent authorization for the same grant finds it used
    // rather than racing this one to the claim.
    let spent: boolean;
    try {
      spent = await this.cards.spend(matched);
    } catch {
      return this.noMatch(record.intentId, "CARD_HOLDS_UNAVAILABLE");
    }
    if (!spent) return this.noMatch(record.intentId, "GRANT_ALREADY_USED");
    const { captured, decision } = matched.held;
    const intentId = captured.intent.intentId;
    try {
      await this.openAttempt(captured, decision);
    } catch {
      return this.noMatch(intentId, "JOURNAL_UNAVAILABLE");
    }
    const claim = await matched.executor.claimHeld(matched.held);
    if (claim.outcome !== "CLAIMED") {
      await this.closeAttempt(captured, decision, claim);
      this.metrics.executions.inc({ outcome: claim.outcome });
      return this.noMatch(intentId, "GRANT_CLAIM_REFUSED");
    }
    const authorization = claim.authorization;
    // The claim is made durable before the issuer is told to approve: there is
    // no effect without a record a restart can find, exactly as for a run.
    try {
      await this.journal.append({
        record: "GRANT_CLAIMED",
        at: new Date().toISOString(),
        intent_id: intentId,
        intent_hash: captured.intentHash,
        idempotency_key: captured.intent.idempotencyKey,
        grant_id: authorization.grantId,
        expires_at: authorization.expiresAt,
        request_digest: requestDigest(captured.intent.parameters),
      });
    } catch {
      this.events.emit({ event: "JOURNAL_WRITE_FAILED", record: "GRANT_CLAIMED" });
      if (this.config.evidence.journalRequired) {
        const finalization = await matched.executor.settleHeld(matched.held, "FAILED");
        await this.closeCardAttempt(captured, "DEFINITELY_NOT_EXECUTED", false, finalization);
        return this.noMatch(intentId, "JOURNAL_UNAVAILABLE");
      }
    }
    const lease = authorization.leaseExpiresAt ?? authorization.expiresAt;
    const answer: CardApproval = {
      decision: "APPROVE",
      authorization_id: request.authorization_id,
      intent_id: intentId,
      intent_hash: captured.intentHash,
      decision_id: authorization.decisionId,
      dossier_id: authorization.dossierId,
      grant_id: authorization.grantId,
      lease_expires_at: lease,
    };
    try {
      await this.cards.recordClaim(request.authorization_id, {
        grant: matched,
        request,
        authorization,
        leaseExpiresAtMs: Date.parse(lease),
        answer,
        material: matched.executor.claimMaterial(authorization),
      });
    } catch {
      // The claim is journaled and the issuer is answered; a record the
      // shared store could not keep is a result this replica alone can
      // settle, which the journal's open attempt still shows.
      this.events.emit({ event: "CARD_CLAIM_RECORD_FAILED", intent_id: intentId });
    }
    this.metrics.executions.inc({ outcome: "CARD_AUTHORIZATION_MATCHED" });
    this.events.emit({ event: "CARD_AUTHORIZATION_MATCHED", intent_id: intentId });
    return answer;
  }

  /**
   * An authorization with no hold. By default it is `NO_MATCH`: nothing was
   * decided before the card was presented. A deployment that evaluates at
   * the commit boundary answers it from an evaluation made now, and one
   * already evaluated and escalated is answered the same way until its
   * intent expires, so a platform that re-presents it is told the same thing
   * and nothing is evaluated twice. Once the tap has resumed the hold, the
   * re-presented authorization finds it before it gets here.
   */
  private async withoutGrant(
    request: CardAuthorizationRequest,
    callerId: string,
  ): Promise<CardAuthorizationAnswer> {
    if (this.config.cards.noGrant !== "evaluate") return this.noMatch(null, "NO_GRANT");
    const pending = this.pendingCommits.get(request.authorization_id);
    if (pending !== undefined) {
      if (Date.parse(pending.answer.expires_at) <= Date.now()) {
        this.pendingCommits.delete(request.authorization_id);
      } else if (pending.digest === jcsDigest(request as JsonObject)) {
        return pending.answer;
      } else {
        return this.noMatch(pending.answer.intent_id, "AUTHORIZATION_ID_REUSED");
      }
    }
    return await this.evaluateAtCommit(request, callerId);
  }

  /**
   * The commit boundary: the authorization becomes the intent, captured as
   * the commit actor the deployment names and evaluated now, with the
   * authorization's id in the intent's context so the dossier says what it
   * decided about. An `ALLOW` is held and claimed in this same call. An
   * `ESCALATE` is `PENDING`, with the handoff: a platform that can pend keeps
   * the authorization waiting, the tap arrives through `POST /v1/escalations`
   * with the handoff's intent, and the re-presented authorization matches the
   * hold the tap left. A `BLOCK`, a refusal this host makes on its own, and
   * an authority that did not answer are `NO_MATCH` with their code. In
   * shadow the evaluation is observed and the authorization is `NO_MATCH`.
   */
  private async evaluateAtCommit(
    request: CardAuthorizationRequest,
    callerId: string,
  ): Promise<CardAuthorizationAnswer> {
    const commit = this.config.cards.commit;
    if (commit === null) return this.noMatch(null, "NO_GRANT");
    const parameters: JsonObject = {
      cardTokenRef: request.card_token_ref,
      amountMinor: request.amount_minor,
      currency: request.currency,
      merchantId: request.merchant_id,
      ...(request.mcc === undefined ? {} : { mcc: request.mcc }),
    };
    const proposal: ProposalRequest = {
      proposal: {
        action: CARD_PURCHASE_ACTION,
        target: cardTarget({ cardTokenRef: request.card_token_ref } as CardPurchase),
        parameters,
      },
      idempotency_key: TrustedExecutorService.commitIdempotencyKey(request.authorization_id),
    };
    const identity: CaptureIdentity = {
      id: callerId,
      tenantId: commit.tenantId,
      actor: commit.actor,
    };
    let captured: CapturedIntent;
    try {
      captured = this.captureIntent(
        proposal,
        identity,
        await this.cards.velocity(request.card_token_ref),
        {
          commit_boundary: "ISSUER_HOOK",
          card_authorization: { authorization_id: request.authorization_id },
        },
      );
    } catch (error) {
      return this.noMatch(null, error instanceof ServiceError ? error.code : "PROPOSAL_INVALID");
    }
    return await RequestContext.run({ principal: callerId }, async () => {
      if (this.config.mode === "SHADOW") {
        const observed = await this.observe(captured);
        this.metrics.proposals.inc({ verdict: observed.verdict ?? "NONE" });
        return this.noMatch(captured.intent.intentId, "SHADOW_OBSERVED");
      }
      try {
        this.assertNotHalted(captured);
        this.assertWithinLimits(captured, "CHECK");
      } catch (error) {
        if (!(error instanceof ServiceError)) throw error;
        await this.recordRefusal(captured, error.code);
        return this.noMatch(captured.intent.intentId, error.code);
      }
      let answer: ActionResponse;
      try {
        answer = await this.enforceAfterPosture(captured);
      } catch (error) {
        if (!(error instanceof ServiceError)) throw error;
        return this.noMatch(captured.intent.intentId, error.code);
      }
      this.metrics.proposals.inc({ verdict: answer.verdict ?? "NONE" });
      if (answer.outcome === "HELD_FOR_AUTHORIZATION") {
        return await this.claimCard(request, callerId, true);
      }
      if (answer.verdict === "ESCALATE" && answer.escalation !== null) {
        const pending: PendingCardAnswer = {
          decision: "PENDING",
          authorization_id: request.authorization_id,
          intent_id: answer.intent_id,
          intent_hash: answer.intent_hash,
          decision_id: answer.decision_id,
          dossier_id: answer.dossier_id,
          expires_at: captured.intent.expiresAt,
          escalation: answer.escalation,
        };
        this.rememberPending(request, pending);
        this.metrics.executions.inc({ outcome: "CARD_AUTHORIZATION_PENDING" });
        this.events.emit({ event: "CARD_AUTHORIZATION_PENDING", intent_id: answer.intent_id });
        return pending;
      }
      return this.noMatch(
        answer.intent_id,
        answer.fail_closed ? "AUTHORITY_UNAVAILABLE" : "POLICY_BLOCK",
      );
    });
  }

  /** Bounded like the claims: a full map forgets its oldest, whose intent is nearest its expiry. */
  private rememberPending(request: CardAuthorizationRequest, answer: PendingCardAnswer): void {
    if (this.pendingCommits.size >= 10_000) {
      const oldest = this.pendingCommits.keys().next().value as string;
      this.pendingCommits.delete(oldest);
    }
    this.pendingCommits.set(request.authorization_id, {
      digest: jcsDigest(request as JsonObject),
      answer,
    });
  }

  /** The intent's idempotency key names the authorization; one too long for the key is named by its digest. */
  private static commitIdempotencyKey(authorizationId: string): string {
    const key = `card-authorization:${authorizationId}`;
    if (key.length <= 180) return key;
    return `card-authorization:sha256:${createHash("sha256").update(authorizationId, "utf8").digest("hex")}`;
  }

  /**
   * What the issuer did with an authorization it was told to approve. An
   * approval is the effect, compared with what the grant authorised; a
   * decline is a refusal; and a result after the claim's lease is recorded
   * as indeterminate, because the authority no longer accepts a commit for
   * it. Recorded once.
   */
  public async settleCard(
    authorizationId: string,
    input: unknown,
    caller?: Principal,
  ): Promise<CardResultResponse> {
    this.operator(caller, "cards.authorize");
    if (!isCardReference(authorizationId)) throw new ServiceError(400, "REQUEST_INVALID");
    const result = TrustedExecutorService.cardRequest(() => cardAuthorizationResultOf(input));
    let claim: ClaimedCardAuthorization | undefined;
    try {
      claim = await this.cards.claimed(authorizationId);
    } catch (error) {
      if (error instanceof CardHoldStoreError) throw new ServiceError(503, error.code);
      throw new ServiceError(503, "CARD_HOLDS_UNAVAILABLE");
    }
    if (claim === undefined) throw new ServiceError(404, "CARD_AUTHORIZATION_UNKNOWN");
    // Settled once, by the one rule every replica shares.
    if (claim.settled || !(await this.cards.settle(authorizationId))) {
      throw new ServiceError(409, "CARD_RESULT_ALREADY_RECORDED");
    }
    const { grant, authorization } = claim;
    const { captured } = grant.held;
    const leaseExpired = Date.now() > claim.leaseExpiresAtMs;
    const record = cardResultRecord({
      purchase: grant.purchase,
      prepared: grant.prepared,
      authorization: claim.request,
      result,
      leaseExpired,
      observer: { id: this.config.banking.adapterId, version: this.config.banking.adapterVersion },
      correlationId: captured.intent.intentId,
      idempotencyKey: captured.intent.idempotencyKey,
      observedAt: new Date().toISOString(),
    });
    // The verifier finalizes with exactly this observation, by the
    // authorization it belongs to.
    this.effects.attach(authorization, record);
    const finalization = await grant.executor.settleHeld(grant.held, record.outcome);
    const executed =
      record.outcome === "COMMITTED" ? true : record.outcome === "FAILED" ? false : null;
    await this.closeCardAttempt(
      captured,
      record.outcome === "COMMITTED"
        ? "COMPLETED"
        : record.outcome === "FAILED"
          ? "DEFINITELY_NOT_EXECUTED"
          : "INDETERMINATE_AFTER_LEASE",
      executed,
      finalization,
    );
    this.metrics.executions.inc({ outcome: `CARD_${record.outcome}` });
    if (finalization === "PENDING") {
      this.events.emit({
        event: "FINALIZATION_PENDING",
        intent_id: captured.intent.intentId,
        outcome: record.outcome,
      });
    }
    this.metrics.finalizations.inc({ status: finalization });
    this.events.emit({
      event: "CARD_AUTHORIZATION_SETTLED",
      intent_id: captured.intent.intentId,
      outcome: record.outcome,
    });
    const effect = this.effect(captured, cardExecutionResult(record));
    return {
      authorization_id: authorizationId,
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      outcome: record.outcome,
      executed,
      finalization,
      reason_codes: [
        ...(leaseExpired ? ["CLAIM_LEASE_EXPIRED"] : []),
        ...TrustedExecutorService.effectReasons(effect),
      ],
      effect,
    };
  }

  /** A card attempt's end, in the journal, so a restart does not ask about it again. */
  private async closeCardAttempt(
    captured: CapturedIntent,
    outcome: string,
    executed: boolean | null,
    finalization: "RECORDED" | "PENDING" | "UNSUPPORTED",
  ): Promise<void> {
    try {
      await this.journal.append({
        record: "ATTEMPT_CLOSED",
        at: new Date().toISOString(),
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
        outcome,
        executed,
        finalization,
      });
    } catch {
      this.events.emit({ event: "JOURNAL_WRITE_FAILED", record: "ATTEMPT_CLOSED" });
    }
  }

  private noMatch(intentId: string | null, code: string): CardAuthorizationAnswer {
    this.events.emit({ event: "CARD_AUTHORIZATION_NO_MATCH", intent_id: intentId, code });
    return { decision: "NO_MATCH", code };
  }

  /** A card request read, or the refusal that names why; a card number is its own refusal. */
  private static cardRequest<T>(read: () => T): T {
    try {
      return read();
    } catch (error) {
      const code = error instanceof CardActionError ? error.code : "REQUEST_INVALID";
      throw new ServiceError(code === "CARD_PAN_REFUSED" ? 422 : 400, code);
    }
  }

  /**
   * Whether a re-presented authorization is an increment of the claim it
   * names: the same card, currency, merchant and category, for more than
   * before and no more than the grant's ceiling, while the claim is still
   * open and inside its lease.
   */
  private static incrementOf(
    previous: ClaimedCardAuthorization,
    request: CardAuthorizationRequest,
  ): boolean {
    const before = previous.request;
    return (
      !previous.settled &&
      Date.now() <= previous.leaseExpiresAtMs &&
      request.card_token_ref === before.card_token_ref &&
      request.currency === before.currency &&
      request.merchant_id === before.merchant_id &&
      (request.mcc ?? null) === (before.mcc ?? null) &&
      request.amount_minor > before.amount_minor &&
      request.amount_minor <= previous.grant.amountMinor
    );
  }

  private static cardView(request: CardAuthorizationRequest): {
    readonly cardTokenRef: string;
    readonly amountMinor: number;
    readonly currency: string;
    readonly merchantId: string;
    readonly mcc: string | null;
  } {
    return {
      cardTokenRef: request.card_token_ref,
      amountMinor: request.amount_minor,
      currency: request.currency,
      merchantId: request.merchant_id,
      mcc: request.mcc ?? null,
    };
  }

  private response(
    captured: CapturedIntent,
    decision: DecisionGate,
    outcome: SafeExecutionResult,
    handoff: EscalationHandoff | AttestationHandoff | null,
    extraReasonCodes: readonly string[] = [],
  ): ActionResponse {
    const effect = this.effect(captured, outcome.result);
    // A finalization the authority did not take is the authority's lease
    // recovery's problem now, and an operator should know it happened.
    if ("finalization" in outcome && outcome.finalization === "PENDING") {
      this.events.emit({
        event: "FINALIZATION_PENDING",
        intent_id: captured.intent.intentId,
        outcome: outcome.outcome,
      });
    }
    if ("finalization" in outcome && outcome.finalization !== null) {
      this.metrics.finalizations.inc({ status: outcome.finalization });
    }
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
        ...("code" in outcome && outcome.code !== undefined ? [outcome.code] : []),
        ...TrustedExecutorService.effectReasons(effect),
        ...extraReasonCodes,
      ],
      fail_closed: decision.failClosed,
      outcome: handoff === null ? outcome.outcome : "ESCALATE_PENDING",
      executed: outcome.executed,
      authorization: TrustedExecutorService.binding(outcome.authorization),
      finalization: "finalization" in outcome ? outcome.finalization : null,
      result: outcome.result,
      effect,
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
      effect: null,
      recovery: null,
      escalation: handoff,
    };
  }

  /**
   * The bundle: what this process can say about an incident, written where an
   * operator can pick it up. Only an operator holding the `evidence` scope
   * may ask, and the reason they give travels with it.
   */
  public async exportEvidence(input: unknown, caller?: Principal): Promise<EvidenceBundle> {
    const operator = this.operator(caller, "evidence");
    const parsed = HaltRequestSchema.safeParse(input);
    if (!parsed.success) throw new ServiceError(400, "REQUEST_INVALID");
    if (!this.evidence.configured) throw new ServiceError(409, "EVIDENCE_DIR_NOT_CONFIGURED");
    let bundle: EvidenceBundle;
    try {
      bundle = await this.evidence.export({
        principal: operator.id,
        reason: parsed.data.reason,
      });
    } catch (error) {
      throw new ServiceError(500, error instanceof EvidenceError ? error.code : "EVIDENCE_FAILED");
    }
    this.events.emit({
      event: "EVIDENCE_EXPORTED",
      principal: operator.id,
      files: bundle.manifest.files.length,
      signed: bundle.signature !== null,
    });
    return bundle;
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
