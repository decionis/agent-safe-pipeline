import { Gateway, type GatewayDependencies } from "../gateway/Gateway.js";
import {
  GatewayConfigError,
  GatewayConfigLoader,
  type GatewayConfig,
  type GatewayFlags,
} from "../gateway/GatewayConfig.js";
import { GatewayHttpServer } from "../http/GatewayHttpServer.js";
import { packageVersion } from "../Version.js";
import { optionPort, optionValue, parseArguments, type ParsedArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import { ConfigFileError, loadConfigFile } from "./ConfigFile.js";
import { readCredentials } from "./Credentials.js";

export const PROXY_ARGUMENTS = {
  valued: ["upstream", "port", "listen", "mode", "failure-policy", "authority", "config"],
  flags: ["verbose", "json"],
} as const;

/** The flags `proxy` and `run` share, in the loader's shape. */
export function gatewayFlags(parsed: ParsedArguments): GatewayFlags {
  const upstream = optionValue(parsed, "upstream");
  const port = optionPort(parsed, "port");
  const listen = optionValue(parsed, "listen");
  const mode = optionValue(parsed, "mode");
  const failurePolicy = optionValue(parsed, "failure-policy");
  const authority = optionValue(parsed, "authority");
  return {
    ...(upstream === undefined ? {} : { upstream }),
    ...(port === undefined ? {} : { port }),
    ...(listen === undefined ? {} : { listen }),
    ...(mode === undefined ? {} : { mode }),
    ...(failurePolicy === undefined ? {} : { failurePolicy }),
    ...(authority === undefined ? {} : { authority }),
    ...(parsed.options.get("verbose") === true ? { verbose: true } : {}),
    ...(parsed.options.get("json") === true ? { json: true } : {}),
  };
}

/** The resolved configuration and the environment the gateway opens its secrets from. */
export interface ResolvedGateway {
  readonly config: GatewayConfig;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly configPath: string | null;
}

/**
 * Resolves the configuration the way every gateway command does: the flags,
 * the environment, the file, the stored login. A stored key is handed to the
 * gateway as if it were in the environment, which is the one place the
 * secret store reads a value from outside production.
 */
export function resolveGateway(io: CliProcess, parsed: ParsedArguments): ResolvedGateway {
  const file = loadConfigFile(io, optionValue(parsed, "config"));
  const credentials = readCredentials(io);
  const config = GatewayConfigLoader.load({
    flags: gatewayFlags(parsed),
    env: io.env,
    file: file.document,
    credentials,
    version: packageVersion(),
  });
  const keyFromLogin =
    credentials !== null &&
    config.authority.kind === "DECIONIS" &&
    io.env["DECIONIS_API_KEY"] === undefined &&
    io.env["DECIONIS_API_KEY_FILE"] === undefined;
  const env = keyFromLogin ? { ...io.env, DECIONIS_API_KEY: credentials.apiKey } : io.env;
  return { config, env, configPath: file.path };
}

/** A refusal to start, on one line that names the setting and never a value. */
export function explainRefusal(error: unknown): string {
  if (error instanceof GatewayConfigError) {
    const hint =
      error.code === "CONFIG_MISSING" && error.setting === "DECIONIS_API_KEY"
        ? "\n\nRun agentsafe login, set DECIONIS_API_KEY, or run without a key for the local demo authority."
        : error.code === "CONFIG_MISSING" && error.setting === "upstream"
          ? "\n\nName the service to protect: agentsafe proxy --upstream http://localhost:3000"
          : "";
    return `AgentSafe refused to start.\n\n${error.message}${hint}\n`;
  }
  if (error instanceof ConfigFileError) {
    return `AgentSafe refused to start.\n\n${error.code}: ${error.path}\n`;
  }
  const message = error instanceof Error ? error.message : "UNKNOWN";
  return `AgentSafe refused to start.\n\n${message}\n`;
}

/**
 * `agentsafe proxy` and `agentsafe run`: the gateway as a process. The
 * configuration is resolved, the gateway assembled, the listener bound, the
 * banner printed; `SIGTERM` and `SIGINT` stop the listener with a grace
 * period, close the gateway and exit 0.
 */
export async function runProxy(
  io: CliProcess,
  argv: readonly string[],
  dependencies: GatewayDependencies = {},
): Promise<void> {
  let resolved: ResolvedGateway;
  let parsed: ParsedArguments;
  try {
    parsed = parseArguments(argv, PROXY_ARGUMENTS);
    resolved = resolveGateway(io, parsed);
  } catch (error) {
    io.stderr(explainRefusal(error));
    io.exit(2);
    return;
  }
  const { config, env } = resolved;
  let gateway: Gateway;
  try {
    gateway = await Gateway.create(config, {
      env,
      io: {
        stdout: (line) => io.stdout(`${line}\n`),
        stderr: (line) => io.stderr(`${line}\n`),
        color: io.color && config.output.format === "HUMAN",
      },
      version: packageVersion(),
      ...dependencies,
    });
  } catch (error) {
    io.stderr(explainRefusal(error));
    io.exit(1);
    return;
  }
  const server = new GatewayHttpServer(gateway, {
    metricsToken: env["AGENTSAFE_METRICS_TOKEN"] ?? null,
  });
  let address;
  try {
    address = await server.listen(config.listen.port, config.listen.host);
  } catch (error) {
    await gateway.close();
    const code = (error as { code?: string }).code ?? "LISTEN_FAILED";
    io.stderr(
      `AgentSafe refused to start.\n\n${code}: ${config.listen.host}:${config.listen.port}${
        code === "EADDRINUSE" ? "\n\nAnother process holds the port; choose one with --port." : ""
      }\n`,
    );
    io.exit(1);
    return;
  }
  const host = address.address.includes(":") ? `[${address.address}]` : address.address;
  gateway.started(`http://${host}:${address.port}`);
  let stopping = false;
  const stop = (signal: string): void => {
    if (stopping) return;
    stopping = true;
    gateway.stopped(signal);
    void server
      .close()
      .then(() => gateway.close())
      .then(() => io.exit(0));
  };
  io.onSignal("SIGTERM", () => stop("SIGTERM"));
  io.onSignal("SIGINT", () => stop("SIGINT"));
}
