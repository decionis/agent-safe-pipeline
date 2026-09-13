import { z } from "zod";
import {
  ActionRegistry,
  AuditRecorder,
  CanonicalIntentHasher,
  DecionisGate,
  DecionisGrantVerifier,
  ExecutionIntentSchema,
  IntentCapture,
  JsonObjectSchema,
  SafeExecutor,
  ShadowPipeline,
  type CapturedIntent,
  type ExecutionRecoveryReference,
  type JsonObject,
  type TrustedIntentContext,
} from "@decionis/agent-safe-pipeline";
import { LineAuditSink, type LineWriter } from "./Audit.js";
import type { ExecutorConfig, ExecutorMode } from "./Config.js";
import { REGISTERED_ACTIONS, registerHandlers, type FetchLike } from "./Handlers.js";

const identifier = z.string().trim().min(1).max(200);

/**
 * What the caller sends. `proposal` is the agent's part and nothing else:
 * tenant, actor, downstream target and credentials come from the executor's
 * own configuration, and a request that tries to supply them is refused by
 * the strict schema. The idempotency key and correlation id are the caller's,
 * derived from its own record of the work, never from the model.
 */
export const ProposalRequestSchema = z.strictObject({
  proposal: z.strictObject({
    action: z.string().trim().min(1).max(120),
    target: z.string().trim().min(1).max(500),
    parameters: JsonObjectSchema.optional(),
  }),
  idempotency_key: z.string().trim().min(1).max(180),
  correlation_id: identifier.optional(),
});

export type ProposalRequest = z.infer<typeof ProposalRequestSchema>;

/** The recovery reference the executor returned, presented back verbatim with the intent. */
export const ReconciliationRequestSchema = z.strictObject({
  intent: z.record(z.string(), z.unknown()),
  reference: z.strictObject({
    version: z.literal("agent-safe.recovery/1"),
    decisionId: identifier,
    dossierId: identifier,
    grantId: identifier,
    intentHash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    expiresAt: z.string().datetime(),
    idempotencyKey: z.string().trim().min(1).max(180),
  }),
});

export type ReconciliationRequest = z.infer<typeof ReconciliationRequestSchema>;

/** The consumed binding, as evidence. The token itself never leaves the process. */
export interface AuthorizationBinding {
  readonly decision_id: string;
  readonly dossier_id: string;
  readonly grant_id: string;
  readonly expires_at: string;
}

export interface ActionResponse {
  readonly mode: ExecutorMode;
  readonly intent_id: string;
  readonly intent_hash: string;
  readonly verdict: "ALLOW" | "ESCALATE" | "BLOCK" | null;
  readonly decision_id: string | null;
  readonly dossier_id: string | null;
  readonly reason_codes: readonly string[];
  readonly fail_closed: boolean;
  /** Shadow: the observation status. Enforcement: the executor outcome. */
  readonly outcome: string;
  readonly executed: boolean | null;
  readonly authorization: AuthorizationBinding | null;
  readonly finalization: "RECORDED" | "PENDING" | "UNSUPPORTED" | null;
  readonly result: unknown;
  /** Present only for `UNKNOWN_AFTER_DISPATCH`: what to present to reconcile. */
  readonly recovery: {
    readonly intent: CapturedIntent["intent"];
    readonly reference: ExecutionRecoveryReference;
  } | null;
}

export interface ReconciliationResponse {
  readonly intent_id: string;
  readonly intent_hash: string;
  readonly outcome: string;
  readonly executed: boolean | null;
  readonly recovered: boolean;
  readonly reason_codes: readonly string[];
  readonly authorization: AuthorizationBinding | null;
  readonly result: unknown;
}

/** A refusal the service meant: a status and a stable code, nothing echoed. */
export class ServiceError extends Error {
  public constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(code);
    this.name = "ServiceError";
  }
}

export interface ServiceDependencies {
  /** Where audit lines go; stdout in the process, an array in the proof. */
  readonly emit?: LineWriter;
  readonly fetch?: FetchLike;
}

/**
 * The execution boundary as one process. In `ENFORCEMENT` it asks Decionis,
 * and on an `ALLOW` claims the grant and executes once through the sealed
 * registry; on anything else it answers with the verdict and no grant. In
 * `SHADOW` it asks what the authority would have decided about an action the
 * caller runs itself, records the observation, and never executes. The grant
 * token, the API key, the caller token and the downstream credential never
 * appear in a response or an audit line.
 */
export class TrustedExecutorService {
  private readonly hasher = new CanonicalIntentHasher();

  private constructor(
    private readonly config: ExecutorConfig,
    private readonly capture: IntentCapture,
    private readonly gate: DecionisGate,
    private readonly registry: ActionRegistry,
    private readonly executor: SafeExecutor,
    private readonly shadow: ShadowPipeline | null,
  ) {}

  public static create(
    config: ExecutorConfig,
    dependencies: ServiceDependencies = {},
  ): TrustedExecutorService {
    const emit =
      dependencies.emit ??
      ((line: string): void => {
        process.stdout.write(`${line}\n`);
      });
    const audit = new AuditRecorder({
      sink: new LineAuditSink(emit),
      failurePolicy: "REQUIRE_BEFORE_EXECUTION",
    });
    const authority = {
      baseUrl: config.authority.baseUrl,
      apiKey: config.authority.apiKey,
      allowInsecureLoopback: config.authority.allowInsecureLoopback,
    };
    const gate = new DecionisGate({ ...authority, mode: config.mode });
    const verifier = new DecionisGrantVerifier(authority);
    const registry = registerHandlers(
      new ActionRegistry(),
      config.downstream,
      dependencies.fetch ?? fetch,
    ).seal();
    return new TrustedExecutorService(
      config,
      new IntentCapture(),
      gate,
      registry,
      new SafeExecutor(registry, verifier, audit),
      config.mode === "SHADOW" ? new ShadowPipeline(gate, { audit }) : null,
    );
  }

  public get mode(): ExecutorMode {
    return this.config.mode;
  }

  /** The actions this process can run, for `/ready`. */
  public get actions(): readonly string[] {
    return REGISTERED_ACTIONS.filter((action) => this.registry.has(action));
  }

  public async propose(input: unknown): Promise<ActionResponse> {
    const parsed = ProposalRequestSchema.safeParse(input);
    if (!parsed.success) throw new ServiceError(400, "REQUEST_INVALID");
    const request = parsed.data;
    // An action this process cannot run is refused before any authority is
    // asked: no dossier, no grant, for something that could never execute.
    if (!this.registry.has(request.proposal.action)) {
      throw new ServiceError(422, "ACTION_NOT_REGISTERED");
    }
    const captured = this.captureIntent(request);
    if (this.shadow !== null) return await this.observe(captured);
    return await this.enforce(captured);
  }

  public async reconcile(input: unknown): Promise<ReconciliationResponse> {
    const parsed = ReconciliationRequestSchema.safeParse(input);
    if (!parsed.success) throw new ServiceError(400, "REQUEST_INVALID");
    let captured: CapturedIntent;
    try {
      // The caller presents the intent it was given; the hash is recomputed
      // here, so a changed intent no longer matches its recovery reference.
      captured = this.hasher.capture(ExecutionIntentSchema.parse(parsed.data.intent));
    } catch {
      throw new ServiceError(400, "INTENT_INVALID");
    }
    const outcome = await this.executor.reconcile(captured, parsed.data.reference);
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

  private captureIntent(request: ProposalRequest): CapturedIntent {
    const trusted: TrustedIntentContext = {
      tenantId: this.config.tenantId,
      actor: this.config.actor,
      downstreamTarget: {
        system: this.config.downstream.system,
        operation: this.config.downstream.operation,
        environment: this.config.downstream.environment,
      },
      context: {},
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

  private async observe(captured: CapturedIntent): Promise<ActionResponse> {
    const shadow = this.shadow;
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
    };
  }

  private async enforce(captured: CapturedIntent): Promise<ActionResponse> {
    const decision = await this.gate.evaluate(captured);
    // Every decision goes through the executor, an ESCALATE or BLOCK included,
    // so the audit stream carries the refusal as well as the execution.
    const outcome = await this.executor.run(captured, decision);
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
      ],
      fail_closed: decision.failClosed,
      outcome: outcome.outcome,
      executed: outcome.executed,
      authorization: TrustedExecutorService.binding(outcome.authorization),
      finalization: "finalization" in outcome ? outcome.finalization : null,
      result: outcome.result,
      recovery:
        outcome.outcome === "UNKNOWN_AFTER_DISPATCH"
          ? { intent: captured.intent, reference: outcome.recovery }
          : null,
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
