/**
 * The dispatch deadline moved into `@decionis/agent-safe-pipeline` with the
 * runner that owns deadlines (`GovernedExecutionRunner`). Re-exported here so
 * every existing import keeps resolving to the one implementation.
 */
export { dispatchBudgetMs, MonotonicDeadline } from "@decionis/agent-safe-pipeline";
