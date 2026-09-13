/**
 * The process entry the container runs. Configuration comes from the
 * environment and mounted files; a missing or invalid value is a refusal to
 * start that names the variable. Nothing is defaulted that identifies a
 * tenant, a system, a person, or a network path.
 */
import process from "node:process";
import { ExecutorConfigLoader, type ExecutorConfig } from "./Config.js";
import { ExecutorHttpServer } from "./Http.js";
import { TrustedExecutorService } from "./Service.js";

function loadOrRefuse(): ExecutorConfig {
  try {
    return ExecutorConfigLoader.load(process.env);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "CONFIG_INVALID";
    process.stderr.write(`${JSON.stringify({ event: "REFUSED_TO_START", reason })}\n`);
    return process.exit(1);
  }
}

const config = loadOrRefuse();
const service = TrustedExecutorService.create(config);
const server = new ExecutorHttpServer(service, config.callerToken);
const address = await server.listen(config.port, config.bindAddress);
process.stdout.write(
  `${JSON.stringify({
    event: "LISTENING",
    mode: config.mode,
    address: address.address,
    port: address.port,
    actions: service.actions,
  })}\n`,
);

const shutdown = (): void => {
  void server.close().then(() => process.exit(0));
};
process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
