import {
  INTERCEPT_DEFAULTS,
  Interceptor,
  type InterceptEvent,
  type InterceptorDependencies,
  type InterceptorOptions,
} from "../http/InterceptServer.js";
import { packageVersion } from "../Version.js";
import { ArgumentError, optionPort, optionValue, parseArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import { refusalLine, speaksJson } from "./Proxy.js";

export const INTERCEPT_ARGUMENTS = {
  valued: ["http-port", "https-port", "bind"],
  flags: ["json"],
} as const;

/** The variables the sidecar is configured with; the flags win over them. */
export const INTERCEPT_ENVIRONMENT = {
  httpPort: "AGENTSAFE_INTERCEPT_HTTP_PORT",
  httpsPort: "AGENTSAFE_INTERCEPT_HTTPS_PORT",
  bind: "AGENTSAFE_INTERCEPT_BIND",
} as const;

export class InterceptConfigError extends Error {
  public constructor(
    public readonly code: "CONFIG_INVALID",
    public readonly setting: string,
  ) {
    super(`${code}: ${setting}`);
    this.name = "InterceptConfigError";
  }
}

function portFrom(
  flag: number | undefined,
  env: Readonly<Record<string, string | undefined>>,
  variable: string,
  fallback: number,
): number {
  if (flag !== undefined) return flag;
  const value = env[variable];
  if (value === undefined || value === "") return fallback;
  if (!/^\d{1,5}$/.test(value) || Number(value) < 1 || Number(value) > 65_535) {
    throw new InterceptConfigError("CONFIG_INVALID", variable);
  }
  return Number(value);
}

/** The interceptor's options from the flags and the environment, each named when refused. */
export function resolveInterceptor(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>>,
): InterceptorOptions {
  const parsed = parseArguments(argv, INTERCEPT_ARGUMENTS);
  const httpPort = portFrom(
    optionPort(parsed, "http-port"),
    env,
    INTERCEPT_ENVIRONMENT.httpPort,
    INTERCEPT_DEFAULTS.httpPort,
  );
  const httpsPort = portFrom(
    optionPort(parsed, "https-port"),
    env,
    INTERCEPT_ENVIRONMENT.httpsPort,
    INTERCEPT_DEFAULTS.httpsPort,
  );
  if (httpPort === httpsPort) throw new InterceptConfigError("CONFIG_INVALID", "https-port");
  const bind =
    optionValue(parsed, "bind") ?? env[INTERCEPT_ENVIRONMENT.bind] ?? INTERCEPT_DEFAULTS.bind;
  if (!/^[\d.:a-f]+$/i.test(bind)) throw new InterceptConfigError("CONFIG_INVALID", "bind");
  return {
    bind,
    listeners: [
      { port: httpPort, destinationPort: 80 },
      { port: httpsPort, destinationPort: 443 },
    ],
    peekTimeoutMs: INTERCEPT_DEFAULTS.peekTimeoutMs,
    connectTimeoutMs: INTERCEPT_DEFAULTS.connectTimeoutMs,
    idleTimeoutMs: INTERCEPT_DEFAULTS.idleTimeoutMs,
    maxConnections: INTERCEPT_DEFAULTS.maxConnections,
  };
}

/** One line per event for a terminal; the JSON form is the event itself. */
export function describe(event: InterceptEvent, version: string): string {
  switch (event.event) {
    case "INTERCEPT_STARTED":
      return `AgentSafe intercept ${version} listening on ${event.listeners
        .map((listener) => `${listener.listen} (for :${listener.for_port})`)
        .join(" and ")}. Observing; nothing is decrypted or decided.`;
    case "INTERCEPT_OBSERVED":
      return event.protocol === "HTTP"
        ? `-> HTTP ${event.method ?? ""} ${event.host}:${event.port} ${event.target ?? ""}`.trimEnd()
        : `-> TLS ${event.host}:${event.port}${event.alpn === undefined ? "" : ` (${event.alpn.join(", ")})`}`;
    case "INTERCEPT_REFUSED": {
      const where = event.host === undefined ? "" : ` ${event.host}:${event.port ?? ""}`;
      const detail = event.detail === undefined ? "" : ` (${event.detail})`;
      return `x  refused${where}: ${event.reason}${detail}`;
    }
    case "INTERCEPT_REPORT": {
      const summary = event.intercept;
      const lines = [
        `Intercept report: ${summary.connections} connection(s), ${summary.placed} placed, ${Object.values(summary.refused).reduce((a, b) => a + b, 0)} refused${summary.since === null ? "" : `, ${summary.since} to ${summary.until}`}.`,
      ];
      for (const [destination, counts] of Object.entries(summary.destinations)) {
        const methods = Object.entries(counts.methods)
          .map(([method, count]) => `${method} x${count}`)
          .join(", ");
        lines.push(
          `  ${destination}  ${counts.protocol}  ${counts.connections} connection(s), ${counts.bytes_to_destination} B out, ${counts.bytes_from_destination} B in${methods === "" ? "" : `  ${methods}`}`,
        );
      }
      for (const [reason, count] of Object.entries(summary.refused)) {
        lines.push(`  refused ${reason} x${count}`);
      }
      lines.push(event.next);
      return lines.join("\n");
    }
    case "INTERCEPT_STOPPED":
      return `Stopped on ${event.signal}.`;
  }
}

/**
 * `agentsafe intercept`: the transparent interceptor as a process, the
 * sidecar the redirect rules point at. It binds its listeners, reports every
 * destination it places or refuses as one line, and on `SIGTERM` or `SIGINT`
 * prints the ledger's report, stops, and exits 0. It holds no key and asks
 * no authority: this is the observe phase.
 */
export async function runIntercept(
  io: CliProcess,
  argv: readonly string[],
  dependencies: Partial<Omit<InterceptorDependencies, "emit">> = {},
): Promise<void> {
  const json = speaksJson(io, argv);
  const version = packageVersion();
  let options: InterceptorOptions;
  try {
    options = resolveInterceptor(argv, io.env);
  } catch (error) {
    io.stderr(
      json
        ? refusalLine(error)
        : `AgentSafe refused to start.\n\n${error instanceof ArgumentError || error instanceof InterceptConfigError ? error.message : "UNKNOWN"}\n`,
    );
    io.exit(2);
    return;
  }
  const emit = (event: InterceptEvent): void => {
    io.stdout(json ? `${JSON.stringify(event)}\n` : `${describe(event, version)}\n`);
  };
  const interceptor = new Interceptor(options, { ...dependencies, emit });
  try {
    await interceptor.listen();
  } catch (error) {
    const code = (error as { code?: string }).code ?? "LISTEN_FAILED";
    const ports = options.listeners.map((listener) => listener.port).join(",");
    io.stderr(
      json
        ? refusalLine(new Error(`${code}: ${options.bind}:${ports}`))
        : `AgentSafe refused to start.\n\n${code}: ${options.bind}:${ports}${
            code === "EADDRINUSE"
              ? "\n\nAnother process holds a port; choose with --http-port and --https-port."
              : ""
          }\n`,
    );
    io.exit(1);
    return;
  }
  let stopping = false;
  const stop = (signal: string): void => {
    if (stopping) return;
    stopping = true;
    emit(interceptor.report());
    emit({ event: "INTERCEPT_STOPPED", at: new Date().toISOString(), signal });
    void interceptor.close().then(() => io.exit(0));
  };
  io.onSignal("SIGTERM", () => stop("SIGTERM"));
  io.onSignal("SIGINT", () => stop("SIGINT"));
}
