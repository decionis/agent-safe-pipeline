/**
 * The effect-adapter contract moved into `@decionis/agent-safe-pipeline`,
 * where it is the dispatch style of `agent-safe.executors.native/1` under its
 * earlier name (`EffectAdapterExecutor` runs one as a `NativeExecutor`).
 * Re-exported here, unchanged, so every adapter and import written against
 * this module keeps working.
 *
 * @deprecated Implement the pipeline's `NativeExecutor` with `style: "dispatch"`.
 */
export {
  IndeterminateOutcome,
  type AdapterExecution,
  type AdapterReconciliation,
  type EffectAdapter,
  type EffectPreparedAction as PreparedAction,
  type ObservationMethod,
  type ProjectionValue,
  type ProviderReconciliationResult,
  type ProviderResult,
} from "@decionis/agent-safe-pipeline";
