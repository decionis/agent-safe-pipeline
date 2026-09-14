import type { AddressInfo } from "node:net";
import process from "node:process";
import type { LineWriter } from "./audit/LineAuditSink.js";
import type { ExecutorConfig } from "./config/ExecutorConfig.js";
import { forwardRequestHandlers } from "./handlers/ForwardRequestHandler.js";
import type { HandlerRegistration } from "./handlers/HandlerRegistration.js";
import { ExecutorHttpServer } from "./http/ExecutorHttpServer.js";
import { SecurityEvents } from "./incident/SecurityEvents.js";
import { LineEmitter } from "./logging/LineEmitter.js";
import { HostPosture, type PostureReport } from "./posture/HostPosture.js";
import { Redactor } from "./secrets/Redactor.js";
import type { SecretStore } from "./secrets/SecretStore.js";
import {
  TrustedExecutorService,
  type ServiceDependencies,
} from "./service/TrustedExecutorService.js";

export interface TrustedExecutorDependencies extends Omit<ServiceDependencies, "posture"> {
  /** The posture to verify and follow; the real host unless a fixture is given. */
  readonly posture?: HostPosture;
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
  /** What was verified at start, and what development posture waived. */
  readonly posture: PostureReport;
  /** Binds the listener and starts following posture drift; the configured port and address unless overridden. */
  listen(port?: number, address?: string): Promise<AddressInfo>;
  close(): Promise<void>;
}

/**
 * The trusted executor, assembled: the host posture verified first, then the
 * service behind its one listener, with the adopter's handlers registered,
 * the registry sealed, and every credential read through the store. Nothing
 * listens until `listen()` is called, and nothing here reads the process
 * environment except to write lines; that is `serve()`.
 */
export async function createTrustedExecutor(
  options: TrustedExecutorOptions,
): Promise<TrustedExecutor> {
  const dependencies = options.dependencies ?? {};
  const { emit, security } = lines(options, dependencies);
  const posture =
    dependencies.posture ??
    new HostPosture(
      {
        mode: options.config.posture.mode,
        intervalSeconds: options.config.posture.intervalSeconds,
        config: options.config.posture,
      },
      security,
    );
  const report = posture.report ?? posture.assertAtStartup();
  const service = TrustedExecutorService.create(
    options.config,
    options.secrets,
    options.handlers ?? forwardRequestHandlers(),
    { ...dependencies, emit, security, posture },
  );
  const server = new ExecutorHttpServer(service, () =>
    options.secrets.get("EXECUTOR_CALLER_TOKEN"),
  );
  let stopPosture: (() => void) | null = null;
  return {
    service,
    posture: report,
    listen: async (port = options.config.port, address = options.config.bindAddress) => {
      const bound = await server.listen(port, address);
      stopPosture = posture.start();
      return bound;
    },
    close: async () => {
      stopPosture?.();
      await server.close();
      service.close();
      options.secrets.close();
    },
  };
}

/** The writers the executor uses when none were injected: the process streams, through the redactor. */
function lines(
  options: TrustedExecutorOptions,
  dependencies: TrustedExecutorDependencies,
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
      () => [options.config.downstream.credentialHeader],
    ),
  );
  const security = dependencies.security ?? new SecurityEvents(emitter.security);
  emitter.reportRedactions((patterns) =>
    security.emit({ event: "LEAK_SUSPECTED", patterns: [...patterns] }),
  );
  return { emit: dependencies.emit ?? emitter.audit, security };
}
