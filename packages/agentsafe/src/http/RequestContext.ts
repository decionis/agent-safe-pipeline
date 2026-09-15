import { AsyncLocalStorage } from "node:async_hooks";

/** What every line written while a request is handled may say about who asked. */
export interface RequestScope {
  readonly principal: string;
}

/** The one caller a configuration without a principals file has: the holder of the caller token. */
export const LEGACY_CALLER_PRINCIPAL = "legacy-caller";

const storage = new AsyncLocalStorage<RequestScope>();

/**
 * The request scope, carried through every await of a request so the
 * evidence sink can name the principal without the service threading it
 * through each call. Outside a request there is no scope, and a line says
 * so with `null`.
 */
export const RequestContext = {
  run<T>(scope: RequestScope, fn: () => T): T {
    return storage.run(scope, fn);
  },
  current(): RequestScope | null {
    return storage.getStore() ?? null;
  },
};
