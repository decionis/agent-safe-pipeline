import type { z } from "zod";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import type { VerifiedAuthorization } from "./AuthorizationVerifier.js";

export interface ActionExecutionContext<TParameters> {
  readonly intent: CapturedIntent;
  readonly parameters: TParameters;
  readonly authorization: VerifiedAuthorization;
}

export interface ActionHandler<TParameters, TResult> {
  readonly parametersSchema: z.ZodType<TParameters>;
  execute(context: ActionExecutionContext<TParameters>): Promise<TResult> | TResult;
}

interface RegisteredAction {
  readonly parametersSchema: z.ZodType<unknown>;
  execute(context: ActionExecutionContext<unknown>): Promise<unknown> | unknown;
}

export class ActionRegistry {
  private readonly actions = new Map<string, RegisteredAction>();
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
    if (!this.sealed) throw new Error("ACTION_REGISTRY_NOT_SEALED");
    const handler = this.actions.get(captured.intent.action);
    if (!handler) throw new Error("ACTION_NOT_REGISTERED");
    const result = handler.parametersSchema.safeParse(captured.intent.parameters);
    if (!result.success) throw new Error("ACTION_PARAMETERS_INVALID");
    return handler.execute({ intent: captured, parameters: result.data, authorization });
  }
}
