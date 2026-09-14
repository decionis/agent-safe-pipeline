import type { ActionRegistry } from "@decionis/agent-safe-pipeline";
import type { DownstreamConfig } from "../config/ExecutorConfig.js";
import type { DownstreamCredential } from "../credential/DownstreamCredential.js";

export type FetchLike = typeof fetch;

/**
 * What a registration receives: the registry to fill, the downstream it
 * targets, the credential that proves this process to the downstream, and
 * the fetch it may use. A handler asks the credential for headers at the
 * moment of dispatch and never holds a value of its own.
 */
export interface HandlerRegistrationContext {
  readonly registry: ActionRegistry;
  readonly downstream: DownstreamConfig;
  readonly credential: DownstreamCredential;
  readonly fetch: FetchLike;
}

/**
 * The seam an adopter fills. It registers every action this process can run
 * on the registry it is given and returns their names, in the order `/ready`
 * reports them. The registry is sealed the moment it returns: nothing
 * registered later, and nothing the agent names, can run.
 */
export type HandlerRegistration = (context: HandlerRegistrationContext) => readonly string[];
