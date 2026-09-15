import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import process from "node:process";
import { ChainJournal } from "./audit/ChainJournal.js";
import { FileExecutionJournal } from "./journal/FileExecutionJournal.js";
import { InMemoryExecutionJournal } from "./journal/InMemoryExecutionJournal.js";
import type { ExecutionJournal } from "./journal/ExecutionJournal.js";
import type { HaltSwitch } from "./incident/HaltSwitch.js";
import { HashChain } from "./audit/HashChain.js";
import { EVIDENCE_STREAM } from "./audit/HashChainedAuditSink.js";
import type { LineWriter } from "./audit/LineAuditSink.js";
import type { ExecutorConfig } from "./config/ExecutorConfig.js";
import { forwardRequestHandlers } from "./handlers/ForwardRequestHandler.js";
import type { HandlerRegistration } from "./handlers/HandlerRegistration.js";
import { ExecutorHttpServer } from "./http/ExecutorHttpServer.js";
import { TlsListener } from "./http/TlsListener.js";
import { Authenticator } from "./identity/Authenticator.js";
import type { PrincipalRegistry } from "./identity/PrincipalRegistry.js";
import { RateLimiter } from "./identity/RateLimiter.js";
import { executorMetrics, type ExecutorMetrics } from "./incident/Metrics.js";
import { SECURITY_STREAM, SecurityEvents } from "./incident/SecurityEvents.js";
import { LineEmitter } from "./logging/LineEmitter.js";
import { HostPosture, type PostureReport } from "./posture/HostPosture.js";
import { Redactor } from "./secrets/Redactor.js";
import type { SecretStore } from "./secrets/SecretStore.js";
import {
  TrustedExecutorService,
  type ServiceDependencies,
} from "./service/TrustedExecutorService.js";

export interface TrustedExecutorDependencies extends Omit<
  ServiceDependencies,
  "posture" | "chain" | "metrics"
> {
  /** The posture to verify and follow; the real host unless a fixture is given. */
  readonly posture?: HostPosture;
  /** Where chain heads persist; built from the configuration when absent, none when null. */
  readonly chainJournal?: ChainJournal | null;
  /** Where attempts are journaled; the configured directory unless one is given. */
  readonly attempts?: ExecutionJournal;
  /** The stop; built from the configuration unless a test hands in its own. */
  readonly halt?: HaltSwitch;
  readonly metrics?: ExecutorMetrics;
  /** The windows and locks the door keeps; a fresh one unless a test injects a clock through its own. */
  readonly limits?: RateLimiter;
}

export interface TrustedExecutorOptions {
  /** `ExecutorConfigLoader.load(env)`, or a configuration built by trusted startup code. */
  readonly config: ExecutorConfig;
  /** Every secret the configuration names; the executor owns the store from here on. */
  readonly secrets: SecretStore;
  /** The seam: what this process can run. Defaults to the reference forwarding handler. */
  readonly handlers?: HandlerRegistration;
  readonly dependencies?: TrustedExecutorDependencies;
}

export interface TrustedExecutor {
  readonly service: TrustedExecutorService;
  /** The attempt journal this process writes to; the file journal unless one was given. */
  readonly attempts: ExecutionJournal;
  /** The stop, for a test or an embedding process that halts without HTTP. */
  readonly halt: HaltSwitch;
  /** What was verified at start, and what development posture waived. */
  readonly posture: PostureReport;
  readonly metrics: ExecutorMetrics;
  /** Who may call, as loaded at start. */
  readonly principals: PrincipalRegistry;
  /** The one chokepoint the door calls; exposed so a test can drive it directly. */
  readonly authenticator: Authenticator;
  /** The evidence chain's head: the sequence and hash of the last line written. */
  readonly evidence: HashChain;
  /** Binds the listener and starts following posture drift; the configured port and address unless overridden. */
  listen(port?: number, address?: string): Promise<AddressInfo>;
  close(): Promise<void>;
}

/**
 * The trusted executor, assembled: the host posture verified first, then the
 * evidence chains restored from the journal, the service behind its one
 * listener with the adopter's handlers registered and the registry sealed,
 * every outbound connection through the guarded fetch, every credential
 * read through the store. Nothing listens until `listen()` is called, and
 * nothing here reads the process environment except to write lines; that
 * is `serve()`.
 */
export async function createTrustedExecutor(
  options: TrustedExecutorOptions,
): Promise<TrustedExecutor> {
  const dependencies = options.dependencies ?? {};
  const config = options.config;
  const readFile = dependencies.readFile ?? ((path: string): string => readFileSync(path, "utf8"));
  const journal =
    dependencies.chainJournal === undefined
      ? config.evidence.journalDir === null
        ? null
        : new ChainJournal(config.evidence.journalDir, {
            checkpointLines: config.evidence.checkpointLines,
          })
      : dependencies.chainJournal;
  // The attempt journal is the durable one: an execution nobody could
  // reconcile afterwards is worse than a refusal, so in enforcement the
  // configuration requires a directory for it.
  const attempts =
    dependencies.attempts ??
    (config.evidence.journalDir === null
      ? new InMemoryExecutionJournal()
      : new FileExecutionJournal(join(config.evidence.journalDir, "attempts"), {
          retainDays: config.evidence.journalRetainDays,
        }));
  const { emit, security } = lines(options, dependencies, journal);
  const posture =
    dependencies.posture ??
    new HostPosture(
      {
        mode: config.posture.mode,
        intervalSeconds: config.posture.intervalSeconds,
        config: config.posture,
      },
      security,
    );
  const report = posture.report ?? posture.assertAtStartup();
  const metrics = dependencies.metrics ?? executorMetrics();
  const evidenceHead = journal?.restore(EVIDENCE_STREAM) ?? null;
  const evidence = new HashChain(EVIDENCE_STREAM, evidenceHead);
  if (evidenceHead !== null) {
    security.emit({ event: "CHAIN_RESUMED", chain: EVIDENCE_STREAM, head: evidenceHead.seq });
  }
  evidence.onLink(() => metrics.auditLines.inc({ chain: EVIDENCE_STREAM }));
  security.chain.onLink(() => metrics.auditLines.inc({ chain: SECURITY_STREAM }));
  const service = TrustedExecutorService.create(
    config,
    options.secrets,
    options.handlers ?? forwardRequestHandlers(),
    {
      ...dependencies,
      emit,
      security,
      posture,
      chain: evidence,
      metrics,
      readFile,
      journal: attempts,
      ...(dependencies.halt === undefined ? {} : { halt: dependencies.halt }),
    },
  );
  const tls =
    config.listener.tls === null
      ? null
      : new TlsListener({
          minVersion: config.listener.tls.minVersion,
          material: () => ({
            cert: readFile(config.listener.tls?.certFile ?? ""),
            key: options.secrets.get("EXECUTOR_TLS_KEY"),
            clientCa:
              config.listener.tls?.clientCaFile == null
                ? null
                : readFile(config.listener.tls.clientCaFile),
          }),
          events: security,
        });
  const authenticator = new Authenticator({
    registry: service.principals,
    jwt: service.jwt,
    audience: config.identity.jwt?.audience ?? null,
    limits: dependencies.limits ?? new RateLimiter(),
    unauthenticated: config.identity.unauthenticated,
    lockout: config.identity.lockout,
    requireCertificate: service.principals.legacy && tls?.mutual === true,
    events: security,
  });
  service.jwt?.start();
  const server = new ExecutorHttpServer(service, authenticator, { tls });
  const stopRotation =
    tls !== null && options.secrets.has("EXECUTOR_TLS_KEY")
      ? options.secrets.onRotate("EXECUTOR_TLS_KEY", () => server.rotateTls())
      : (): void => undefined;
  const following =
    journal === null
      ? []
      : [journal.follow(evidence, security), journal.follow(security.chain, security)];
  let stopPosture: (() => void) | null = null;
  const haltSwitch = service.haltSwitch;
  haltSwitch.assertAtStartup();
  let stopHalt: (() => void) | null = null;
  return {
    service,
    attempts,
    halt: haltSwitch,
    posture: report,
    metrics,
    principals: service.principals,
    authenticator,
    evidence,
    listen: async (port = config.port, address = config.bindAddress) => {
      // What the last process left open is resolved before this one can be
      // asked to do anything new, and read-only: the provider is asked what
      // it did, never told to do it again.
      await service.recover();
      const bound = await server.listen(port, address);
      stopPosture = posture.start();
      stopHalt = haltSwitch.start();
      return bound;
    },
    close: async () => {
      stopPosture?.();
      stopHalt?.();
      stopRotation();
      await server.close();
      service.close();
      for (const stop of following) stop();
      attempts.close();
      options.secrets.close();
    },
  };
}

/** The writers the executor uses when none were injected: the process streams, through the redactor. */
function lines(
  options: TrustedExecutorOptions,
  dependencies: TrustedExecutorDependencies,
  journal: ChainJournal | null,
): { readonly emit: LineWriter; readonly security: SecurityEvents } {
  if (dependencies.emit !== undefined && dependencies.security !== undefined) {
    return { emit: dependencies.emit, security: dependencies.security };
  }
  const emitter = new LineEmitter(
    {
      stdout: (line) => {
        process.stdout.write(`${line}\n`);
      },
      stderr: (line) => {
        process.stderr.write(`${line}\n`);
      },
    },
    new Redactor(
      () => options.config.secrets.required.map((name) => options.secrets.get(name).digest()),
      () => options.config.downstream.redactedHeaders,
    ),
  );
  let security = dependencies.security;
  if (security === undefined) {
    const head = journal?.restore(SECURITY_STREAM) ?? null;
    security = new SecurityEvents(emitter.security, {
      chain: new HashChain(SECURITY_STREAM, head),
    });
    if (head !== null) {
      security.emit({ event: "CHAIN_RESUMED", chain: SECURITY_STREAM, head: head.seq });
    }
  }
  const events = security;
  emitter.reportRedactions((patterns) =>
    events.emit({ event: "LEAK_SUSPECTED", patterns: [...patterns] }),
  );
  return { emit: dependencies.emit ?? emitter.audit, security: events };
}
