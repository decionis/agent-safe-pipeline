import { EgressError } from "./EgressError.js";

/** Whatever holds a `fetch`: the global object in the process, a plain object in tests. */
export interface FetchHolder {
  fetch?: unknown;
}

const LOCKED = Symbol.for("agent-safe.fetch-locked");

/**
 * Replaces the global `fetch` with one that refuses, and makes the property
 * neither writable nor configurable, so that every request this process
 * makes goes through the fetch it was handed: the guarded one. It is the
 * second of three layers; the wiring is the first and the import rule on
 * socket modules is the third. It cannot stop code that imports `node:http`
 * itself; the import rule and review do that.
 */
export function lockGlobalFetch(target: FetchHolder = globalThis as FetchHolder): void {
  if (isGlobalFetchLocked(target)) return;
  const refuse = (): never => {
    throw new EgressError("EGRESS_GLOBAL_FETCH_LOCKED");
  };
  Object.defineProperty(refuse, LOCKED, { value: true, writable: false, configurable: false });
  Object.freeze(refuse);
  Object.defineProperty(target, "fetch", {
    value: refuse,
    writable: false,
    configurable: false,
    enumerable: false,
  });
}

/** Whether the lock stands: the marked function, and a property nothing can replace. */
export function isGlobalFetchLocked(target: FetchHolder = globalThis as FetchHolder): boolean {
  const descriptor = Object.getOwnPropertyDescriptor(target, "fetch");
  if (descriptor === undefined) return false;
  const marked = (descriptor.value as { [LOCKED]?: boolean } | undefined)?.[LOCKED] === true;
  return marked && descriptor.writable === false && descriptor.configurable === false;
}
