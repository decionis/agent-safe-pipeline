import process from "node:process";
import { ExecutorConfigLoader, type ExecutorConfig } from "./config/ExecutorConfig.js";
import { forwardRequestHandlers } from "./handlers/ForwardRequestHandler.js";
import type { HandlerRegistration } from "./handlers/HandlerRegistration.js";
import { createTrustedExecutor } from "./TrustedExecutor.js";

/** The process around the executor: where configuration comes from, where lines go, how it ends. */
export interface ServeProcess {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly stdout: (line: string) => void;
  readonly stderr: (line: string) => void;
  readonly exit: (code: number) => void;
  readonly onSignal: (signal: "SIGTERM" | "SIGINT", handler: () => void) => void;
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
 * The process entry the container runs. Configuration comes from the
 * environment and mounted files; a missing or invalid value is a refusal to
 * start that names the variable. Nothing is defaulted that identifies a
 * tenant, a system, a person, or a network path.
 */
export async function serve(
  handlers: HandlerRegistration = forwardRequestHandlers(),
  io: ServeProcess = nodeProcess(),
): Promise<void> {
  let config: ExecutorConfig;
  try {
    config = ExecutorConfigLoader.load(io.env);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "CONFIG_INVALID";
    io.stderr(JSON.stringify({ event: "REFUSED_TO_START", reason }));
    io.exit(1);
    return;
  }
  const executor = await createTrustedExecutor({ config, handlers });
  const address = await executor.listen();
  io.stdout(
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
}
