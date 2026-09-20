/**
 * `agentsafe test --hosted`: the boundary test with Decionis deciding. The
 * same fixed requests as the local test, sent two ways at the same synthetic
 * loopback target: directly, and through the gateway in shadow against the
 * Decionis workspace this machine is logged into. Nothing real is called and
 * nothing is enforced; what the run produces is what the local test cannot:
 * a first governed action against Decionis for this workspace, one signed
 * Decision Dossier per consequential request, and the record itself,
 * fetched with the run's own key and shown by its proof.
 *
 * This is the one test that reads the stored login and the `DECIONIS_*`
 * variables, and it says so; the local test reads neither. A provisional
 * workspace evaluates in shadow only, which is the one lane this test runs,
 * so the free workspace `agentsafe login --provision` mints is enough.
 */
import {
  DossierFetchError,
  fetchSignedDossier,
  type SignedDossierSummary,
} from "@decionis/agent-safe-pipeline";
import { GatewayHttpServer } from "../http/GatewayHttpServer.js";
import { RecordingTarget } from "../http/RecordingTarget.js";
import {
  awaitObservation,
  BOUNDARY_CASES,
  closeLane,
  send,
  type BoundaryCase,
  type Lane,
  type PassOutcome,
} from "./BoundaryTest.js";
import { Gateway, type GatewayDependencies } from "./Gateway.js";
import {
  GatewayConfigError,
  GatewayConfigLoader,
  type GatewayConfig,
  type StoredCredentials,
} from "./GatewayConfig.js";
import type { GatewayState } from "./GatewayReport.js";
import type { InstallSurface } from "./InstallSurface.js";

export const HOSTED_BOUNDARY_TEST_VERSION = "agent-safe.hosted-boundary-test/1";

/** What Decionis said about one request sent through the shadow lane. */
export interface HostedDecision {
  /** Whether the gateway captured the request as an intent and asked; a read is not consequential. */
  readonly consequential: boolean;
  readonly status: number | null;
  /** The gateway's own state on the answer: `SHADOW` when forwarded and asked, `ERROR` when it refused the request itself, null when passed through. */
  readonly state: GatewayState | null;
  readonly verdict: "ALLOW" | "ESCALATE" | "BLOCK" | null;
  readonly reason_codes: readonly string[];
  readonly decision_id: string | null;
  readonly dossier_id: string | null;
}

export interface HostedCaseResult {
  readonly id: string;
  readonly title: string;
  readonly adversarial: boolean;
  readonly request: {
    readonly method: string;
    readonly path: string;
    readonly body: string | null;
  };
  readonly direct: PassOutcome;
  readonly decionis: HostedDecision;
}

export interface HostedBoundaryTestReport {
  readonly version: typeof HOSTED_BOUNDARY_TEST_VERSION;
  readonly at: string;
  readonly runtime: string;
  readonly authority: {
    readonly kind: "decionis";
    readonly endpoint: string;
    readonly tenant: string;
    /** A workspace minted without an account, which decides in shadow only. */
    readonly provisional: boolean;
    readonly mode: "SHADOW";
  };
  readonly target: "synthetic loopback";
  readonly cases: readonly HostedCaseResult[];
  /** Of the consequential requests, what Decionis would have decided. */
  readonly decided: {
    readonly consequential: number;
    readonly would: {
      readonly ALLOW: number;
      readonly ESCALATE: number;
      readonly BLOCK: number;
      readonly NONE: number;
    };
  };
  /** The Decision Dossiers the run left, in the order they were minted. */
  readonly dossiers: readonly string[];
  /** The first dossier as fetched with the run's key: signed, by whom, under which issuer tier. */
  readonly signed: SignedDossierSummary | null;
  /** Why the record could not be fetched, when it could not. */
  readonly signedUnavailable: string | null;
  /** The adoption milestones the shadow lane reported, in order. */
  readonly milestones: readonly string[];
  /**
   * `DECIONIS_DECIDED`: every consequential request got a verdict.
   * `AUTHORITY_UNREACHABLE`: none did. `PARTLY_DECIDED`: some did.
   */
  readonly verdict: "DECIONIS_DECIDED" | "AUTHORITY_UNREACHABLE" | "PARTLY_DECIDED";
}

export class HostedTestError extends Error {
  public constructor(
    public readonly code: "NO_LOGIN" | "CONFIG_INVALID",
    public readonly detail: string,
  ) {
    super(`${code}: ${detail}`);
    this.name = "HostedTestError";
  }
}

export interface HostedBoundaryTestOptions {
  readonly version: string;
  /** The stored login, when there is one; the environment's key wins over it as it does for `proxy`. */
  readonly credentials: StoredCredentials | null;
  /** The process environment; only the `DECIONIS_*` variables and `NODE_ENV` are read from it. */
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly surface: InstallSurface | null;
  readonly cases?: readonly BoundaryCase[];
  readonly clock?: () => number;
  /** How long to wait for Decionis's observation of one request. */
  readonly observationTimeoutMs?: number;
  readonly gateway?: Pick<GatewayDependencies, "authorityFetch" | "upstreamFetch">;
  readonly fetchDossier?: typeof fetchSignedDossier;
}

/** The variables the hosted test reads from the environment, and no others. */
export const HOSTED_TEST_ENVIRONMENT = [
  "DECIONIS_API_KEY",
  "DECIONIS_API_KEY_FILE",
  "DECIONIS_API_URL",
  "DECIONIS_TENANT_ID",
  "DECIONIS_TIMEOUT_MS",
  "DECIONIS_ALLOW_INSECURE_LOOPBACK",
  "NODE_ENV",
] as const;

const DEFAULT_OBSERVATION_TIMEOUT_MS = 15_000;

/**
 * The configuration of the shadow lane: the synthetic target as upstream,
 * shadow mode, and the authority from the stored login and the `DECIONIS_*`
 * variables alone. No file, no `AGENTSAFE_*` variable, so nothing of the
 * operator's own gateway is in play; a provisional login is shadow by rule.
 */
export function hostedConfig(
  options: Pick<HostedBoundaryTestOptions, "credentials" | "env" | "version">,
  target: string,
): { readonly config: GatewayConfig; readonly env: Record<string, string | undefined> } {
  const env: Record<string, string | undefined> = {};
  for (const name of HOSTED_TEST_ENVIRONMENT) {
    if (options.env[name] !== undefined) env[name] = options.env[name];
  }
  let config: GatewayConfig;
  try {
    config = GatewayConfigLoader.load({
      flags: { upstream: target, mode: "shadow", json: true },
      env,
      file: null,
      credentials: options.credentials,
      version: options.version,
    });
  } catch (error) {
    if (error instanceof GatewayConfigError && error.setting === "DECIONIS_API_KEY") {
      throw new HostedTestError("NO_LOGIN", error.message);
    }
    throw new HostedTestError(
      "CONFIG_INVALID",
      error instanceof Error ? error.message : "CONFIG_INVALID",
    );
  }
  if (config.authority.kind !== "DECIONIS") {
    throw new HostedTestError(
      "NO_LOGIN",
      "no Decionis key: run `agentsafe login --provision` for a free workspace, or `agentsafe login` with your organization's key",
    );
  }
  const login = options.credentials;
  const keyFromLogin =
    login !== null &&
    env["DECIONIS_API_KEY"] === undefined &&
    env["DECIONIS_API_KEY_FILE"] === undefined;
  return {
    config,
    env: keyFromLogin ? { ...env, DECIONIS_API_KEY: login.apiKey } : env,
  };
}

function milestonesOf(lines: readonly string[]): string[] {
  const milestones: string[] = [];
  for (const line of lines) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    if (typeof parsed !== "object" || parsed === null) continue;
    const report = parsed as { event?: unknown; milestone?: unknown };
    if (report.event === "ACTIVATION" && typeof report.milestone === "string") {
      milestones.push(report.milestone);
    }
  }
  return milestones;
}

/** Runs the hosted test and returns the report; nothing is printed here. */
export async function runHostedBoundaryTest(
  options: HostedBoundaryTestOptions,
): Promise<HostedBoundaryTestReport> {
  const clock = options.clock ?? ((): number => Date.now());
  const cases = (options.cases ?? BOUNDARY_CASES).filter((testCase) => !testCase.outage);
  const observationTimeoutMs = options.observationTimeoutMs ?? DEFAULT_OBSERVATION_TIMEOUT_MS;
  const target = new RecordingTarget();
  await target.start();
  let lane: Lane | null = null;
  try {
    const resolved = hostedConfig(options, target.baseUrl);
    const lines: string[] = [];
    const example = `agentsafe-test@${options.version}`;
    const gateway = await Gateway.create(resolved.config, {
      env: resolved.env,
      version: options.version,
      clock,
      surface: options.surface,
      clientExample: example,
      ...(options.gateway ?? {}),
      io: {
        stdout: (line) => {
          lines.push(line);
        },
        stderr: (line) => {
          lines.push(line);
        },
        color: false,
      },
    });
    const server = new GatewayHttpServer(gateway);
    const address = await server.listen(0, "127.0.0.1");
    lane = { gateway, server, url: `http://127.0.0.1:${String(address.port)}`, lines };
    gateway.started(lane.url);

    const results: HostedCaseResult[] = [];
    let observed = 0;
    for (const testCase of cases) {
      const direct = await send(target.baseUrl, testCase, target);
      const sent = await send(lane.url, testCase, target);
      // A request the gateway forwarded in shadow was captured as an intent
      // and asked about; one it answered itself (a read it passed through
      // untouched, or a body it could not read as an intent) was not.
      const consequential = sent.state === "SHADOW";
      let decision: HostedDecision = {
        consequential,
        status: sent.status,
        state: sent.state,
        verdict: null,
        reason_codes: [],
        decision_id: null,
        dossier_id: null,
      };
      if (consequential) {
        observed += 1;
        const observation = await awaitObservation(lane, observed, observationTimeoutMs, clock);
        decision = {
          ...decision,
          verdict: observation.verdict,
          reason_codes: observation.reasonCodes,
          decision_id: observation.decisionId,
          dossier_id: observation.dossierId,
        };
      }
      results.push({
        id: testCase.id,
        title: testCase.title,
        adversarial: testCase.adversarial,
        request: { method: testCase.method, path: testCase.path, body: testCase.body },
        direct,
        decionis: decision,
      });
    }
    const consequential = results.filter((result) => result.decionis.consequential);
    const would = { ALLOW: 0, ESCALATE: 0, BLOCK: 0, NONE: 0 };
    for (const result of consequential) would[result.decionis.verdict ?? "NONE"] += 1;
    const dossiers = consequential
      .map((result) => result.decionis.dossier_id)
      .filter((id): id is string => id !== null);
    const decidedCount = consequential.length - would.NONE;
    const verdict =
      consequential.length > 0 && decidedCount === consequential.length
        ? "DECIONIS_DECIDED"
        : decidedCount === 0
          ? "AUTHORITY_UNREACHABLE"
          : "PARTLY_DECIDED";

    let signed: SignedDossierSummary | null = null;
    let signedUnavailable: string | null = null;
    const first = dossiers[0];
    if (first !== undefined) {
      try {
        const fetched = await (options.fetchDossier ?? fetchSignedDossier)({
          baseUrl: resolved.config.authority.endpoint,
          apiKey: resolved.env["DECIONIS_API_KEY"] ?? "",
          tenantId: resolved.config.authority.tenantId,
          dossierId: first,
          allowInsecureLoopback: resolved.config.authority.allowInsecureLoopback,
          timeoutMs: resolved.config.authority.timeoutMs,
          source: { example, ...(options.surface === null ? {} : { surface: options.surface }) },
        });
        signed = fetched.summary;
      } catch (error) {
        signedUnavailable = error instanceof DossierFetchError ? error.code : "DOSSIER_UNAVAILABLE";
      }
    }
    gateway.stopped("test");
    return {
      version: HOSTED_BOUNDARY_TEST_VERSION,
      at: new Date(clock()).toISOString(),
      runtime: options.version,
      authority: {
        kind: "decionis",
        endpoint: resolved.config.authority.endpoint,
        tenant: resolved.config.authority.tenantId,
        provisional: resolved.config.authority.provisional,
        mode: "SHADOW",
      },
      target: "synthetic loopback",
      cases: results,
      decided: { consequential: consequential.length, would },
      dossiers,
      signed,
      signedUnavailable,
      milestones: milestonesOf(lines),
      verdict,
    };
  } finally {
    if (lane !== null) await closeLane(lane);
    await target.stop();
  }
}
