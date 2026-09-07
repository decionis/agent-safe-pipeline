import type { z } from "zod";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import type { VerifiedAuthorization } from "./AuthorizationVerifier.js";

export interface ActionExecutionContext<TParameters> {
  readonly intent: CapturedIntent;
  readonly parameters: TParameters;
  readonly authorization: VerifiedAuthorization;
  /**
   * Trusted handlers must place the provider side effect inside `dispatch.run`.
   * This records the point after which a transport error has an unknown outcome
   * and exposes only the intent-bound idempotency key, never an execution token.
   */
  readonly dispatch: ProviderDispatch;
}

export interface ProviderDispatch {
  readonly idempotencyKey: string;
  run<TResult>(operation: (idempotencyKey: string) => Promise<TResult> | TResult): Promise<TResult>;
}

export interface ActionReconciliationContext<TParameters> {
  readonly intent: CapturedIntent;
  readonly parameters: TParameters;
  readonly idempotencyKey: string;
}

export type ProviderReconciliation<TResult> =
  | { readonly status: "COMPLETED"; readonly result: TResult }
  | { readonly status: "NOT_EXECUTED" }
  | { readonly status: "UNKNOWN" };

export interface ActionHandler<TParameters, TResult> {
  readonly parametersSchema: z.ZodType<TParameters>;
  execute(context: ActionExecutionContext<TParameters>): Promise<TResult> | TResult;
  /** Read-only provider lookup. It must never initiate or retry a side effect. */
  reconcile?(
    context: ActionReconciliationContext<TParameters>,
  ): Promise<ProviderReconciliation<TResult>> | ProviderReconciliation<TResult>;
}

interface RegisteredAction {
  readonly parametersSchema: z.ZodType<unknown>;
  execute(context: ActionExecutionContext<unknown>): Promise<unknown> | unknown;
  reconcile?(
    context: ActionReconciliationContext<unknown>,
  ): Promise<ProviderReconciliation<unknown>> | ProviderReconciliation<unknown>;
}

export type ActionExecutionAttempt =
  | { readonly status: "COMPLETED"; readonly result: unknown }
  | { readonly status: "FAILED_BEFORE_DISPATCH" }
  | { readonly status: "UNKNOWN_AFTER_DISPATCH" };

export class ActionRegistry {
  private readonly actions = new Map<string, RegisteredAction>();
  private readonly pendingReconciliations = new Map<
    string,
    Promise<ProviderReconciliation<unknown>>
  >();
  private sealed = false;

  public register<TParameters, TResult>(
    action: string,
    handler: ActionHandler<TParameters, TResult>,
  ): this {
    if (this.sealed) throw new Error("ACTION_REGISTRY_SEALED");
    if (this.actions.has(action)) throw new Error("ACTION_ALREADY_REGISTERED");
    this.actions.set(action, handler as RegisteredAction);
    return this;
  }

  public seal(): this {
    this.sealed = true;
    return this;
  }

  public has(action: string): boolean {
    return this.actions.has(action);
  }

  public validate(captured: CapturedIntent): void {
    if (!this.sealed) throw new Error("ACTION_REGISTRY_NOT_SEALED");
    const handler = this.actions.get(captured.intent.action);
    if (!handler) throw new Error("ACTION_NOT_REGISTERED");
    if (!handler.parametersSchema.safeParse(captured.intent.parameters).success) {
      throw new Error("ACTION_PARAMETERS_INVALID");
    }
  }

  public async execute(
    captured: CapturedIntent,
    authorization: VerifiedAuthorization,
  ): Promise<unknown> {
    const attempt = await this.executeTracked(captured, authorization);
    if (attempt.status === "COMPLETED") return attempt.result;
    throw new Error(attempt.status);
  }

  public async executeTracked(
    captured: CapturedIntent,
    authorization: VerifiedAuthorization,
  ): Promise<ActionExecutionAttempt> {
    if (!this.sealed) throw new Error("ACTION_REGISTRY_NOT_SEALED");
    const handler = this.actions.get(captured.intent.action);
    if (!handler) throw new Error("ACTION_NOT_REGISTERED");
    const result = handler.parametersSchema.safeParse(captured.intent.parameters);
    if (!result.success) throw new Error("ACTION_PARAMETERS_INVALID");
    let dispatched = false;
    const dispatch: ProviderDispatch = Object.freeze({
      idempotencyKey: captured.intent.idempotencyKey,
      run: async <TResult>(
        operation: (idempotencyKey: string) => Promise<TResult> | TResult,
      ): Promise<TResult> => {
        if (dispatched) throw new Error("PROVIDER_DISPATCH_ALREADY_STARTED");
        dispatched = true;
        return await operation(captured.intent.idempotencyKey);
      },
    });

    try {
      return {
        status: "COMPLETED",
        result: await handler.execute({
          intent: captured,
          parameters: result.data,
          authorization,
          dispatch,
        }),
      };
    } catch {
      return { status: dispatched ? "UNKNOWN_AFTER_DISPATCH" : "FAILED_BEFORE_DISPATCH" };
    }
  }

  public async reconcile(
    captured: CapturedIntent,
    idempotencyKey: string,
  ): Promise<ProviderReconciliation<unknown>> {
    if (!this.sealed) throw new Error("ACTION_REGISTRY_NOT_SEALED");
    if (idempotencyKey !== captured.intent.idempotencyKey) {
      throw new Error("RECONCILIATION_BINDING_MISMATCH");
    }
    const handler = this.actions.get(captured.intent.action);
    if (!handler) throw new Error("ACTION_NOT_REGISTERED");
    const parameters = handler.parametersSchema.safeParse(captured.intent.parameters);
    if (!parameters.success) throw new Error("ACTION_PARAMETERS_INVALID");
    if (handler.reconcile === undefined) return { status: "UNKNOWN" };

    const key = `${captured.intentHash}\u0000${idempotencyKey}`;
    const pending = this.pendingReconciliations.get(key);
    if (pending !== undefined) return await pending;

    const reconciliation = Promise.resolve()
      .then(async () =>
        this.validReconciliation(
          await handler.reconcile?.({
            intent: captured,
            parameters: parameters.data,
            idempotencyKey,
          }),
        ),
      )
      .catch((): ProviderReconciliation<unknown> => ({ status: "UNKNOWN" }))
      .finally(() => this.pendingReconciliations.delete(key));
    this.pendingReconciliations.set(key, reconciliation);
    return await reconciliation;
  }

  private validReconciliation(value: unknown): ProviderReconciliation<unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return { status: "UNKNOWN" };
    }
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record);
    if (record["status"] === "COMPLETED" && keys.length === 2 && "result" in record) {
      return { status: "COMPLETED", result: record["result"] };
    }
    if (
      (record["status"] === "NOT_EXECUTED" || record["status"] === "UNKNOWN") &&
      keys.length === 1
    ) {
      return { status: record["status"] };
    }
    return { status: "UNKNOWN" };
  }
}
