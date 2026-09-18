import {
  DecionisGrantVerifier,
  type AuthorizationVerifier,
} from "../execution/AuthorizationVerifier.js";
import type { ClientSource } from "../http/ClientIdentification.js";
import {
  credentialsPath,
  readStoredCredentials,
  writeStoredCredentials,
  type CredentialFiles,
} from "../http/StoredCredentials.js";
import { DecionisGate } from "./DecionisGate.js";
import type { DecisionAuthority, DecisionEvaluationMode } from "./DecisionAuthority.js";
import { fetchSignedDossier, type SignedDossierSummary } from "../report/DossierReport.js";
import {
  provisionWorkspace,
  type ProvisionOptions,
  type ProvisionedWorkspace,
} from "./Provision.js";
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

export type HostedCredentialSource = "environment" | "stored" | "provisioned";

/** Where the hosted key came from, for the run to say so; null when the gate is local. */
export interface HostedCredentials {
  readonly source: HostedCredentialSource;
  readonly tenantId: string;
  readonly endpoint: string;
  /** The file the key is kept in, when it is kept. */
  readonly path: string | null;
  readonly provisional: boolean;
  /** How a person claims a provisioned workspace, as the authority stated it. */
  readonly claim: Readonly<Record<string, unknown>> | null;
}

export interface HostedGate extends SelectedGate {
  readonly credentials: HostedCredentials | null;
  /**
   * Fetches a dossier this gate's key minted and summarizes its proof; null
   * when the gate is local. The key stays inside the closure.
   */
  readonly fetchDossier:
    | ((
        dossierId: string,
      ) => Promise<{ readonly summary: SignedDossierSummary; readonly body: unknown }>)
    | null;
}

export interface CreateHostedGateOptions
  extends CreateGateOptions, ResolveHostedCredentialsOptions {}

const HOSTED_VALUES: ReadonlySet<string> = new Set(["1", "true", "yes", "on"]);

/** Whether `DECIONIS_HOSTED` asks for the hosted gate. */
export function hostedRequested(env: Readonly<Record<string, string | undefined>>): boolean {
  const value = env["DECIONIS_HOSTED"]?.trim().toLowerCase();
  return value !== undefined && HOSTED_VALUES.has(value);
}

export interface ResolveHostedCredentialsOptions {
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly fetch?: typeof fetch;
  readonly source?: ClientSource;
  /**
   * Where a provisioned key is kept between runs, so a second run reuses the
   * workspace instead of minting another: the user's `agentsafe` credential
   * file by default; `false` keeps nothing.
   */
  readonly store?: { readonly home?: string; readonly files?: CredentialFiles } | false;
  /** Mints the workspace; the authority's own route by default. */
  readonly provision?: (options: ProvisionOptions) => Promise<ProvisionedWorkspace>;
  /** Where the one-time note about a provisioned workspace goes; standard error by default. */
  readonly notice?: (line: string) => void;
}

/** The credentials a hosted run uses, and the environment overlay that carries them. */
export interface ResolvedHostedCredentials {
  readonly credentials: HostedCredentials;
  /** The key, for the one place that must hold it: the environment of the gate or process. */
  readonly apiKey: string;
  readonly env: Readonly<Record<string, string | undefined>>;
}

/**
 * Where a hosted run's key comes from, in order: the environment, the
 * credential this user keeps for this authority, and when there is none and
 * `DECIONIS_HOSTED` asks, a free provisional workspace minted now, kept for
 * the next run and named on standard error once. Null when nothing asks for
 * the hosted path at all.
 */
export async function resolveHostedCredentials(
  options: ResolveHostedCredentialsOptions = {},
): Promise<ResolvedHostedCredentials | null> {
  const env = options.env ?? process.env;
  const endpoint = env["DECIONIS_API_URL"]?.trim() || DEFAULT_API_URL;
  const keyInEnvironment = env["DECIONIS_API_KEY"]?.trim() ?? "";
  if (keyInEnvironment !== "") {
    const tenantId = env["DECIONIS_TENANT_ID"]?.trim();
    if (tenantId === undefined || tenantId === "") throw new Error("DECIONIS_TENANT_ID_MISSING");
    return {
      credentials: {
        source: "environment",
        tenantId,
        endpoint,
        path: null,
        provisional: false,
        claim: null,
      },
      apiKey: keyInEnvironment,
      env,
    };
  }
  if (!hostedRequested(env)) return null;
  if (env["NODE_ENV"] === "production") throw new Error("DECIONIS_HOSTED_REFUSED_IN_PRODUCTION");

  const storeOptions =
    options.store === false
      ? null
      : {
          env,
          ...(options.store?.home === undefined ? {} : { home: options.store.home }),
          ...(options.store?.files === undefined ? {} : { files: options.store.files }),
        };
  const stored = storeOptions === null ? null : readStoredCredentials(storeOptions);
  if (
    stored !== null &&
    stored.tenantId !== null &&
    (stored.endpoint ?? DEFAULT_API_URL) === endpoint
  ) {
    return {
      credentials: {
        source: "stored",
        tenantId: stored.tenantId,
        endpoint,
        path: storeOptions === null ? null : credentialsPath(storeOptions),
        provisional: stored.provisional === true,
        claim: null,
      },
      apiKey: stored.apiKey,
      env: { ...env, DECIONIS_API_KEY: stored.apiKey, DECIONIS_TENANT_ID: stored.tenantId },
    };
  }
  const workspace = await (options.provision ?? provisionWorkspace)({
    baseUrl: endpoint,
    allowInsecureLoopback: env["DECIONIS_ALLOW_INSECURE_LOOPBACK"]?.trim() === "true",
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    ...(options.source === undefined ? {} : { source: options.source }),
    ...(options.source?.example === undefined
      ? {}
      : { agentName: `agent-safe-pipeline ${options.source.example}` }),
  });
  const path =
    storeOptions === null
      ? null
      : writeStoredCredentials(storeOptions, {
          apiKey: workspace.rawKey,
          tenantId: workspace.orgId,
          endpoint,
          provisional: true,
        });
  const notice =
    options.notice ??
    ((line: string): void => {
      process.stderr.write(`${line}\n`);
    });
  const decisions = workspace.limits["governed_decisions_per_month"];
  notice(
    `decionis: provisioned a free workspace ${workspace.orgId} (provisional, no account${
      typeof decisions === "number" ? `; ${String(decisions)} governed decisions a month` : ""
    })`,
  );
  notice(
    path === null
      ? "decionis: the key was not stored; the next run mints another workspace"
      : `decionis: key stored at ${path}; the next run reuses this workspace`,
  );
  const note = workspace.claim["note"];
  if (typeof note === "string" && note.length <= 500) notice(`decionis: ${note}`);
  return {
    credentials: {
      source: "provisioned",
      tenantId: workspace.orgId,
      endpoint,
      path,
      provisional: true,
      claim: workspace.claim,
    },
    apiKey: workspace.rawKey,
    env: { ...env, DECIONIS_API_KEY: workspace.rawKey, DECIONIS_TENANT_ID: workspace.orgId },
  };
}

/**
 * The gate `createGate` selects, with one more way onto Decionis: a single
 * variable. `DECIONIS_HOSTED=1` with no key means the key this user already
 * keeps for this authority, and when there is none, a free provisional
 * workspace minted now, kept for the next run, and named on standard error
 * once. A key in the environment still wins, and no variable at all is
 * still the local pair. A provisional key evaluates in `SHADOW` only:
 * recorded beside the local verdict, with a signed dossier, never governing
 * execution; an owned key set in the environment takes the mode asked for.
 */
export async function createHostedGate(options: CreateHostedGateOptions): Promise<HostedGate> {
  const env = options.env ?? process.env;
  const resolved = await resolveHostedCredentials(options);
  if (resolved === null) {
    return { ...createGate(options), credentials: null, fetchDossier: null };
  }
  const { credentials, apiKey } = resolved;
  const gate = createGate({
    ...options,
    env: credentials.provisional ? { ...resolved.env, DECIONIS_MODE: "SHADOW" } : resolved.env,
  });
  return {
    ...gate,
    credentials,
    fetchDossier: (dossierId) =>
      fetchSignedDossier({
        baseUrl: credentials.endpoint,
        apiKey,
        tenantId: credentials.tenantId,
        dossierId,
        allowInsecureLoopback: env["DECIONIS_ALLOW_INSECURE_LOOPBACK"]?.trim() === "true",
        ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
        ...(options.source === undefined ? {} : { source: options.source }),
      }),
  };
}
