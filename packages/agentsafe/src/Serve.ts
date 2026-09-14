import process from "node:process";
import { ExecutorConfigLoader, type ExecutorConfig } from "./config/ExecutorConfig.js";
import { forwardRequestHandlers } from "./handlers/ForwardRequestHandler.js";
import type { HandlerRegistration } from "./handlers/HandlerRegistration.js";
import { SecurityEvents } from "./incident/SecurityEvents.js";
import { LineEmitter } from "./logging/LineEmitter.js";
import { HostPosture, PostureError } from "./posture/HostPosture.js";
import { CompositeSecretStore } from "./secrets/CompositeSecretStore.js";
import { Redactor } from "./secrets/Redactor.js";
import { SecretError } from "./secrets/SecretStore.js";
import { createTrustedExecutor } from "./TrustedExecutor.js";

/** The process around the executor: where configuration comes from, where lines go, how it ends. */
export interface ServeProcess {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly stdout: (line: string) => void;
  readonly stderr: (line: string) => void;
  readonly exit: (code: number) => void;
  readonly onSignal: (signal: "SIGTERM" | "SIGINT" | "SIGHUP", handler: () => void) => void;
}

/** The real process. */
export function nodeProcess(): ServeProcess {
  return {
    env: process.env,
    stdout: (line) => {
      process.stdout.write(`${line}\n`);
    },
    stderr: (line) => {
      process.stderr.write(`${line}\n`);
    },
    exit: (code) => process.exit(code),
    onSignal: (signal, handler) => {
      process.once(signal, handler);
    },
  };
}

/**
 * The process entry the container runs, in the order that keeps secrets
 * unread until the host is known to be fit to hold them: configuration from
 * the environment; the host posture, verified or refused; the secrets, from
 * mounted files (or, outside production, variables); the executor; the
 * listener. Every refusal to start names a variable or a check, never a
 * value. `SIGHUP` re-reads the secret files; `SIGTERM` and `SIGINT` close
 * the listener and exit.
 */
export async function serve(
  handlers: HandlerRegistration = forwardRequestHandlers(),
  io: ServeProcess = nodeProcess(),
): Promise<void> {
  const refuse = (reason: string): void => {
    io.stderr(JSON.stringify({ event: "REFUSED_TO_START", reason }));
    io.exit(1);
  };
  let config: ExecutorConfig;
  try {
    config = ExecutorConfigLoader.load(io.env);
  } catch (error) {
    refuse(error instanceof Error ? error.message : "CONFIG_INVALID");
    return;
  }
  // The redactor learns the secrets' digests once the store exists; until
  // then every line is still shape-checked.
  let store: CompositeSecretStore | null = null;
  const emitter = new LineEmitter(
    { stdout: io.stdout, stderr: io.stderr },
    new Redactor(
      () => (store === null ? [] : store.names().map((name) => store?.get(name).digest() ?? "")),
      () => [config.downstream.credentialHeader],
    ),
  );
  const security = new SecurityEvents(emitter.security);
  emitter.reportRedactions((patterns) =>
    security.emit({ event: "LEAK_SUSPECTED", patterns: [...patterns] }),
  );
  const posture = new HostPosture(
    {
      mode: config.posture.mode,
      intervalSeconds: config.posture.intervalSeconds,
      config: config.posture,
    },
    security,
  );
  try {
    posture.assertAtStartup();
  } catch (error) {
    refuse(error instanceof PostureError ? error.message : "POSTURE_UNVERIFIABLE");
    return;
  }
  try {
    store = CompositeSecretStore.fromEnvironment(io.env, config.secrets.required, {
      events: security,
      production: config.production,
      enforcePermissions: config.posture.mode === "ENFORCED",
    });
  } catch (error) {
    refuse(error instanceof SecretError ? error.message : "CONFIG_SECRET_UNREADABLE");
    return;
  }
  const secrets = store;
  const executor = await createTrustedExecutor({
    config,
    secrets,
    handlers,
    dependencies: { emit: emitter.audit, security, posture },
  });
  const address = await executor.listen();
  emitter.process(
    JSON.stringify({
      event: "POSTURE_VERIFIED",
      mode: config.posture.mode,
      checks: executor.posture.findings.length,
      waived: executor.posture.waived.map((finding) => finding.id),
    }),
  );
  emitter.process(
    JSON.stringify({
      event: "LISTENING",
      mode: config.mode,
      address: address.address,
      port: address.port,
      actions: executor.service.actions,
    }),
  );
  const shutdown = (): void => {
    void executor.close().then(() => io.exit(0));
  };
  io.onSignal("SIGTERM", shutdown);
  io.onSignal("SIGINT", shutdown);
  io.onSignal("SIGHUP", () => {
    void secrets.reload("SIGHUP");
  });
}
