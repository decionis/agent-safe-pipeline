import { Gateway, type GatewayDependencies } from "../gateway/Gateway.js";
import {
  GatewayConfigError,
  GatewayConfigLoader,
  type GatewayConfig,
} from "../gateway/GatewayConfig.js";
import { GatewayHttpServer } from "../http/GatewayHttpServer.js";
import {
  GOVERN_DEFAULTS,
  InterceptGovernor,
  type UnlistedPolicy,
} from "../http/InterceptGovernor.js";
import {
  INTERCEPT_DEFAULTS,
  Interceptor,
  type InterceptEvent,
  type InterceptorDependencies,
  type InterceptorOptions,
} from "../http/InterceptServer.js";
import type { InterceptProtocol } from "../intercept/Destination.js";
import { LeafIssuer, LeafIssuerError } from "../intercept/LeafIssuer.js";
import { parseAuthority } from "../intercept/RequestHead.js";
import { packageVersion } from "../Version.js";
import {
  ArgumentError,
  optionPort,
  optionValue,
  parseArguments,
  type ParsedArguments,
} from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import { ConfigFileError, loadConfigFile } from "./ConfigFile.js";
import { readCredentials } from "./Credentials.js";
import { refusalLine, speaksJson } from "./Proxy.js";

export const INTERCEPT_ARGUMENTS = {
  valued: [
    "http-port",
    "https-port",
    "bind",
    "govern",
    "unlisted",
    "ca-cert",
    "ca-key",
    "mode",
    "failure-policy",
    "authority",
    "config",
  ],
  flags: ["json", "verbose"],
} as const;

/** The variables the sidecar is configured with; the flags win over them. */
export const INTERCEPT_ENVIRONMENT = {
  httpPort: "AGENTSAFE_INTERCEPT_HTTP_PORT",
  httpsPort: "AGENTSAFE_INTERCEPT_HTTPS_PORT",
  bind: "AGENTSAFE_INTERCEPT_BIND",
  /** The destinations to govern, comma-separated host names; empty observes everything. */
  govern: "AGENTSAFE_INTERCEPT_GOVERN",
  /** `passthrough` or `refuse` for a destination not governed. */
  unlisted: "AGENTSAFE_INTERCEPT_UNLISTED",
  /** The operator authority's certificate, PEM, that governed TLS is terminated under. */
  caCertificateFile: "AGENTSAFE_INTERCEPT_CA_CERT_FILE",
  /** The operator authority's private key, PEM. */
  caKeyFile: "AGENTSAFE_INTERCEPT_CA_KEY_FILE",
} as const;

export class InterceptConfigError extends Error {
  public constructor(
    public readonly code: "CONFIG_INVALID" | "CONFIG_MISSING",
    public readonly setting: string,
    detail?: string,
  ) {
    super(detail === undefined ? `${code}: ${setting}` : `${code}: ${setting} (${detail})`);
    this.name = "InterceptConfigError";
  }
}

/** What an operator asked the interceptor to govern, before any file is read. */
export interface GovernSettings {
  readonly hosts: ReadonlySet<string>;
  readonly unlisted: UnlistedPolicy;
  /** Where the operator authority's certificate and key are; null when governed TLS is not to be terminated. */
  readonly authority: { readonly certificateFile: string; readonly keyFile: string } | null;
}

export interface InterceptSettings {
  readonly listeners: InterceptorOptions;
  /** Null when nothing is governed and nothing is refused: the observe phase alone. */
  readonly govern: GovernSettings | null;
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

/** A governed destination is a host name: the name a TLS hello or a Host header carries. */
function governedHost(value: string, setting: string): string {
  const authority = parseAuthority(value.trim());
  if (
    authority === null ||
    authority.port !== null ||
    authority.host.startsWith("[") ||
    /^[\d.]+$/.test(authority.host)
  ) {
    throw new InterceptConfigError("CONFIG_INVALID", setting, "a host name, no port, no address");
  }
  return authority.host;
}

/** The interceptor's settings from the flags and the environment, each named when refused. */
export function resolveIntercept(
  parsed: ParsedArguments,
  env: Readonly<Record<string, string | undefined>>,
): InterceptSettings {
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
  const listeners: InterceptorOptions = {
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

  const governFlag = optionValue(parsed, "govern");
  const governRaw = governFlag ?? env[INTERCEPT_ENVIRONMENT.govern] ?? "";
  const governSetting = governFlag === undefined ? INTERCEPT_ENVIRONMENT.govern : "govern";
  const hosts = new Set(
    governRaw
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry !== "")
      .map((entry) => governedHost(entry, governSetting)),
  );
  const unlistedFlag = optionValue(parsed, "unlisted");
  const unlisted = (unlistedFlag ?? env[INTERCEPT_ENVIRONMENT.unlisted] ?? GOVERN_DEFAULTS.unlisted)
    .trim()
    .toLowerCase();
  if (unlisted !== "passthrough" && unlisted !== "refuse") {
    throw new InterceptConfigError(
      "CONFIG_INVALID",
      unlistedFlag === undefined ? INTERCEPT_ENVIRONMENT.unlisted : "unlisted",
      "passthrough or refuse",
    );
  }
  const certificateFile =
    optionValue(parsed, "ca-cert") ?? env[INTERCEPT_ENVIRONMENT.caCertificateFile] ?? null;
  const keyFile = optionValue(parsed, "ca-key") ?? env[INTERCEPT_ENVIRONMENT.caKeyFile] ?? null;
  if ((certificateFile === null) !== (keyFile === null)) {
    throw new InterceptConfigError(
      "CONFIG_MISSING",
      certificateFile === null
        ? INTERCEPT_ENVIRONMENT.caCertificateFile
        : INTERCEPT_ENVIRONMENT.caKeyFile,
      "the authority's certificate and key come together",
    );
  }
  if (hosts.size === 0 && unlisted === "passthrough") return { listeners, govern: null };
  return {
    listeners,
    govern: {
      hosts,
      unlisted,
      authority: certificateFile === null || keyFile === null ? null : { certificateFile, keyFile },
    },
  };
}

/** One line per event for a terminal; the JSON form is the event itself. */
export function describe(event: InterceptEvent, version: string): string {
  switch (event.event) {
    case "INTERCEPT_STARTED":
      return `AgentSafe intercept ${version} listening on ${event.listeners
        .map((listener) => `${listener.listen} (for :${listener.for_port})`)
        .join(" and ")}.`;
    case "INTERCEPT_GOVERNING":
      return event.hosts.length === 0
        ? `Governing nothing; destinations are ${event.unlisted === "refuse" ? "refused" : "observed"}.`
        : `Governing ${event.hosts.join(", ")}${event.tls ? ", TLS terminated under the operator's authority" : ", plaintext only"}; other destinations are ${event.unlisted === "refuse" ? "refused" : "observed"}.`;
    case "INTERCEPT_OBSERVED": {
      const governed = event.governed ? "  governed" : "";
      return event.protocol === "HTTP"
        ? `${`-> HTTP ${event.method ?? ""} ${event.host}:${event.port} ${event.target ?? ""}`.trimEnd()}${governed}`
        : `-> TLS ${event.host}:${event.port}${event.alpn === undefined ? "" : ` (${event.alpn.join(", ")})`}${governed}`;
    }
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
        const tail = methods === "" ? "" : `  ${methods}`;
        if (!counts.governed) {
          lines.push(
            `  ${destination}  ${counts.protocol}  ${counts.connections} connection(s), ${counts.bytes_to_destination} B out, ${counts.bytes_from_destination} B in${tail}`,
          );
          continue;
        }
        // The gateway's account of a governed destination: what it was handed
        // and what became of it, in its own names.
        const account =
          counts.gateway === null
            ? "no request reached the gateway"
            : `gateway ${counts.gateway.mode}: ${
                Object.entries(counts.gateway.requests)
                  .map(([name, count]) => `${name} x${count}`)
                  .join(", ") || "no request"
              }`;
        lines.push(
          `  ${destination}  ${counts.protocol}  governed  ${counts.connections} connection(s), ${account}${tail}`,
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

/** What a test hands in beneath the command: the sockets, the clock, and the gateways' own seams. */
export interface InterceptDependencies extends Partial<
  Omit<InterceptorDependencies, "emit" | "governor">
> {
  readonly gateway?: GatewayDependencies;
}

/** A gateway and its listener for one governed destination. */
interface GovernedGateway {
  readonly gateway: Gateway;
  readonly server: GatewayHttpServer;
}

/**
 * Resolves the gateway configuration governed destinations share, the way
 * `agentsafe proxy` resolves its own: flags, environment, file, stored login.
 * The upstream is a placeholder here, replaced per governed host.
 */
function resolveGovernedGateway(
  io: CliProcess,
  parsed: ParsedArguments,
): { readonly config: GatewayConfig; readonly env: Readonly<Record<string, string | undefined>> } {
  const file = loadConfigFile(io, optionValue(parsed, "config"));
  const credentials = readCredentials(io);
  const mode = optionValue(parsed, "mode");
  const failurePolicy = optionValue(parsed, "failure-policy");
  const authority = optionValue(parsed, "authority");
  const config = GatewayConfigLoader.load({
    flags: {
      upstream: "https://governed.invalid",
      ...(mode === undefined ? {} : { mode }),
      ...(failurePolicy === undefined ? {} : { failurePolicy }),
      ...(authority === undefined ? {} : { authority }),
      ...(parsed.options.get("verbose") === true ? { verbose: true } : {}),
      ...(parsed.options.get("json") === true ? { json: true } : {}),
    },
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
  return { config, env };
}

/** The configuration for one governed destination: the shared settings, with that host as the upstream. */
export function governedConfig(
  base: GatewayConfig,
  host: string,
  protocol: InterceptProtocol,
): GatewayConfig {
  return {
    ...base,
    upstream: {
      ...base.upstream,
      url: protocol === "TLS" ? `https://${host}` : `http://${host}`,
      // A workload that spoke plain HTTP to this host is not made safer by the
      // hop refusing to; the request is forwarded as it was addressed.
      insecure: protocol === "HTTP",
      system: host,
    },
    sources: { ...base.sources, upstream: "environment" },
  };
}

function refusal(error: unknown): string {
  if (
    error instanceof ArgumentError ||
    error instanceof InterceptConfigError ||
    error instanceof GatewayConfigError
  ) {
    return error.message;
  }
  if (error instanceof ConfigFileError) return `${error.code}: ${error.path}`;
  if (error instanceof LeafIssuerError) {
    return `${error.code}: ${INTERCEPT_ENVIRONMENT.caCertificateFile}`;
  }
  return error instanceof Error ? error.message : "UNKNOWN";
}

/**
 * `agentsafe intercept`: the transparent interceptor as a process, the
 * sidecar the redirect rules point at. It binds its listeners, reports every
 * destination it places, governs or refuses as one line, and on `SIGTERM` or
 * `SIGINT` prints the ledger's report, stops, and exits 0. With nothing to
 * govern it holds no key and asks no authority; with governed destinations it
 * runs the gateway for each, under the configuration `agentsafe proxy`
 * takes, and terminates their TLS under the operator's authority.
 */
export async function runIntercept(
  io: CliProcess,
  argv: readonly string[],
  dependencies: InterceptDependencies = {},
): Promise<void> {
  const json = speaksJson(io, argv);
  const version = packageVersion();
  const refuse = (error: unknown): string =>
    json
      ? refusalLine(new Error(refusal(error)))
      : `AgentSafe refused to start.\n\n${refusal(error)}\n`;
  let settings: InterceptSettings;
  let governor: InterceptGovernor | null = null;
  const governed = new Map<string, GovernedGateway>();
  const gatewayIo = {
    stdout: (line: string) => io.stdout(`${line}\n`),
    stderr: (line: string) => io.stderr(`${line}\n`),
    color: false,
  };
  try {
    const parsed = parseArguments(argv, INTERCEPT_ARGUMENTS);
    settings = resolveIntercept(parsed, io.env);
    if (settings.govern !== null) {
      const govern = settings.govern;
      let issuer: LeafIssuer | null = null;
      if (govern.authority !== null) {
        const certificatePem = io.files.read(govern.authority.certificateFile);
        const keyPem = io.files.read(govern.authority.keyFile);
        if (certificatePem === null) {
          throw new InterceptConfigError(
            "CONFIG_INVALID",
            INTERCEPT_ENVIRONMENT.caCertificateFile,
            "unreadable",
          );
        }
        if (keyPem === null) {
          throw new InterceptConfigError(
            "CONFIG_INVALID",
            INTERCEPT_ENVIRONMENT.caKeyFile,
            "unreadable",
          );
        }
        issuer = new LeafIssuer({ certificatePem, keyPem });
      }
      // The gateway's configuration is resolved now, so a missing key or a
      // refused setting is a refusal to start rather than a first request that fails.
      const shared = govern.hosts.size === 0 ? null : resolveGovernedGateway(io, parsed);
      governor = new InterceptGovernor(
        {
          hosts: govern.hosts,
          unlisted: govern.unlisted,
          issuer,
          handshakeTimeoutMs: GOVERN_DEFAULTS.handshakeTimeoutMs,
        },
        {
          gatewayFor: async (host, protocol) => {
            const key = `${protocol} ${host}`;
            const existing = governed.get(key);
            if (existing !== undefined) return existing.server;
            if (shared === null) throw new Error("NOTHING_GOVERNED");
            const config = governedConfig(shared.config, host, protocol);
            const gateway = await Gateway.create(config, {
              env: shared.env,
              io: gatewayIo,
              version,
              ...dependencies.gateway,
            });
            gateway.started(config.upstream.url);
            const server = new GatewayHttpServer(gateway);
            governed.set(key, { gateway, server });
            return server;
          },
        },
      );
    }
  } catch (error) {
    io.stderr(refuse(error));
    io.exit(2);
    return;
  }
  const emit = (event: InterceptEvent): void => {
    io.stdout(json ? `${JSON.stringify(event)}\n` : `${describe(event, version)}\n`);
  };
  const interceptor = new Interceptor(settings.listeners, {
    ...(dependencies.dial === undefined ? {} : { dial: dependencies.dial }),
    ...(dependencies.now === undefined ? {} : { now: dependencies.now }),
    emit,
    governor,
    // The report gives a governed destination its gateway's account of it.
    governedCounts: (host, protocol) => {
      const status = governed.get(`${protocol} ${host}`)?.gateway.status();
      return status === undefined ? null : { mode: status.mode, requests: status.counts };
    },
  });
  try {
    await interceptor.listen();
  } catch (error) {
    const code = (error as { code?: string }).code ?? "LISTEN_FAILED";
    const ports = settings.listeners.listeners.map((listener) => listener.port).join(",");
    io.stderr(
      json
        ? refusalLine(new Error(`${code}: ${settings.listeners.bind}:${ports}`))
        : `AgentSafe refused to start.\n\n${code}: ${settings.listeners.bind}:${ports}${
            code === "EADDRINUSE"
              ? "\n\nAnother process holds a port; choose with --http-port and --https-port."
              : ""
          }\n`,
    );
    io.exit(1);
    return;
  }
  if (governor !== null) {
    emit({
      event: "INTERCEPT_GOVERNING",
      at: new Date().toISOString(),
      hosts: [...governor.hosts].sort(),
      unlisted: governor.unlisted,
      tls: settings.govern?.authority !== null,
    });
  }
  let stopping = false;
  const stop = (signal: string): void => {
    if (stopping) return;
    stopping = true;
    emit(interceptor.report());
    for (const { gateway } of governed.values()) gateway.stopped(signal);
    emit({ event: "INTERCEPT_STOPPED", at: new Date().toISOString(), signal });
    void interceptor
      .close()
      .then(() => Promise.all([...governed.values()].map(({ server }) => server.close())))
      .then(() => Promise.all([...governed.values()].map(({ gateway }) => gateway.close())))
      .then(() => io.exit(0));
  };
  io.onSignal("SIGTERM", () => stop("SIGTERM"));
  io.onSignal("SIGINT", () => stop("SIGINT"));
}
