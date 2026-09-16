import {
  DecionisGrantVerifier,
  type AuthorizationVerifier,
} from "../execution/AuthorizationVerifier.js";
import type { ClientSource } from "../http/ClientIdentification.js";
import { DecionisGate } from "./DecionisGate.js";
import type { DecisionAuthority, DecisionEvaluationMode } from "./DecisionAuthority.js";
import { ShadowGate } from "./ShadowGate.js";

export type GateMode = "LOCAL" | DecisionEvaluationMode;

/** An authority and the verifier that can claim the grants it issues. */
export interface AuthorityPair {
  readonly authority: DecisionAuthority;
  readonly verifier: AuthorizationVerifier;
}

export interface SelectedGate extends AuthorityPair {
  readonly mode: GateMode;
  /**
   * The tenant a captured intent must name. In a hosted mode this is the
   * key's own organization, because Decionis binds every intent to it; in
   * `LOCAL` mode it is the `tenantId` the caller passed.
   */
  readonly tenantId: string;
}

export interface CreateGateOptions {
  /**
   * The pair that runs when no key is set. It keeps governing execution in
   * `SHADOW` mode, and in `ENFORCEMENT` mode its authority can only tighten
   * the hosted decision.
   */
  readonly local: AuthorityPair;
  /** The tenant used when no key is set. */
  readonly tenantId: string;
  /** Defaults to `process.env`. */
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly fetch?: typeof fetch;
  /** Carried in the `User-Agent` of hosted calls only; never sent without a key. */
  readonly source?: ClientSource;
}

const DEFAULT_API_URL = "https://api.decionis.com";
const TIMEOUT_PATTERN = /^\d{1,6}$/;

/**
 * Selects the gate from the environment.
 *
 * `DECIONIS_API_KEY` unset: returns `local` itself, the same authority and
 * verifier objects, with no client constructed and no network call. A caller
 * that sets nothing gets exactly what it gets today.
 *
 * `DECIONIS_API_KEY` set: `DecionisGate` runs beside `local` through
 * `ShadowGate`, in `DECIONIS_MODE` (`SHADOW` by default, `ENFORCEMENT` on
 * request). `DECIONIS_TENANT_ID` is then required, because Decionis binds
 * every intent to the key's own organization and refuses any other tenant.
 * `DECIONIS_API_URL`, `DECIONIS_TIMEOUT_MS` and `DECIONIS_ALLOW_INSECURE_LOOPBACK`
 * configure the connection the way the trusted executor's do.
 */
export function createGate(options: CreateGateOptions): SelectedGate {
  const env = options.env ?? process.env;
  const apiKey = env["DECIONIS_API_KEY"]?.trim();
  if (apiKey === undefined || apiKey === "") {
    return { ...options.local, mode: "LOCAL", tenantId: options.tenantId };
  }

  const mode = evaluationMode(env["DECIONIS_MODE"]);
  const tenantId = env["DECIONIS_TENANT_ID"]?.trim();
  if (tenantId === undefined || tenantId === "") {
    throw new Error("DECIONIS_TENANT_ID_MISSING");
  }
  const timeoutMs = timeout(env["DECIONIS_TIMEOUT_MS"]);
  const connection = {
    baseUrl: env["DECIONIS_API_URL"]?.trim() || DEFAULT_API_URL,
    apiKey,
    allowInsecureLoopback: env["DECIONIS_ALLOW_INSECURE_LOOPBACK"]?.trim() === "true",
    ...(timeoutMs === undefined ? {} : { timeoutMs }),
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
  };
  const hosted = new DecionisGate({
    ...connection,
    mode,
    ...(options.source === undefined ? {} : { source: options.source }),
  });
  return {
    mode,
    tenantId,
    authority: new ShadowGate(options.local.authority, hosted, mode),
    // Only an ENFORCEMENT decision carries a grant Decionis will let a
    // verifier claim; a SHADOW decision keeps the local verifier and grant.
    verifier:
      mode === "ENFORCEMENT" ? new DecionisGrantVerifier(connection) : options.local.verifier,
  };
}

function evaluationMode(raw: string | undefined): DecisionEvaluationMode {
  const value = raw?.trim().toUpperCase();
  if (value === undefined || value === "" || value === "SHADOW") return "SHADOW";
  if (value === "ENFORCE" || value === "ENFORCEMENT") return "ENFORCEMENT";
  throw new Error("DECIONIS_MODE_INVALID");
}

function timeout(raw: string | undefined): number | undefined {
  const value = raw?.trim();
  if (value === undefined || value === "") return undefined;
  if (!TIMEOUT_PATTERN.test(value)) throw new Error("DECIONIS_TIMEOUT_MS_INVALID");
  return Number(value);
}
