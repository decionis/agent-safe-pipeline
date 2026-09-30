import type { GatewayDependencies } from "../gateway/Gateway.js";
import { GatewayConfigError, parseListen } from "../gateway/GatewayConfig.js";
import { TenantHost } from "../hosted/TenantHost.js";
import { TenantRegistryError } from "../hosted/TenantRegistry.js";
import { GatewayHttpServer } from "../http/GatewayHttpServer.js";
import { packageVersion } from "../Version.js";
import { optionPort, optionValue, parseArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";

export const HOST_ARGUMENTS = {
  valued: ["registry", "port", "listen"],
  flags: [],
} as const;

/** How often the registry is read for a change, when nothing says otherwise. */
export const REGISTRY_POLL_MS = 5_000;
/** How often tenants that could not be built are tried again, with the registry unchanged. */
export const TENANT_RETRY_MS = 60_000;

/**
 * `agentsafe host`: many tenants' hosted gateways in one process, from the
 * registry the operator mounts (`--registry` or `AGENTSAFE_TENANT_REGISTRY`).
 * Every tenant is a hosted gateway at `{id}.{domain}`; a request is routed by
 * its host alone, and a host no tenant has is refused with 421, except the
 * platform's `healthz` and `readyz`. The registry is read again on `SIGHUP`
 * and whenever its text changes; `SIGTERM` and `SIGINT` stop the listener
 * with a grace period, close every gateway and exit 0. Everything this
 * process prints is JSON, one line each, and every tenant's line carries its
 * id.
 */
export async function runHost(
  io: CliProcess,
  argv: readonly string[],
  dependencies: Omit<GatewayDependencies, "env" | "io"> = {},
  pollMs: number = REGISTRY_POLL_MS,
  retryMs: number = TENANT_RETRY_MS,
  clock: () => number = Date.now,
): Promise<void> {
  const refuse = (reason: string, code: number): void => {
    io.stderr(`${JSON.stringify({ event: "REFUSED_TO_START", reason })}\n`);
    io.exit(code);
  };
  let registryPath: string;
  let listen: { host: string; port: number };
  try {
    const parsed = parseArguments(argv, HOST_ARGUMENTS);
    const named = optionValue(parsed, "registry") ?? io.env["AGENTSAFE_TENANT_REGISTRY"];
    if (named === undefined || named.trim() === "") {
      throw new GatewayConfigError(
        "CONFIG_MISSING",
        "registry",
        "--registry FILE or AGENTSAFE_TENANT_REGISTRY",
      );
    }
    registryPath = named.trim();
    const port = optionPort(parsed, "port");
    const address = optionValue(parsed, "listen") ?? io.env["AGENTSAFE_LISTEN"];
    listen =
      address !== undefined
        ? parseListen(address, "listen")
        : { host: "0.0.0.0", port: port ?? Number(io.env["PORT"] ?? 8080) };
    if (address !== undefined && port !== undefined) listen = { ...listen, port };
  } catch (error) {
    refuse(error instanceof Error ? error.message : "UNKNOWN", 2);
    return;
  }

  const lines = {
    stdout: (line: string) => io.stdout(`${line}\n`),
    stderr: (line: string) => io.stderr(`${line}\n`),
    color: false,
  };
  let host: TenantHost;
  try {
    host = await TenantHost.start({
      registryPath,
      env: io.env,
      io: lines,
      readFile: (path) => io.files.read(path),
      version: packageVersion(),
      dependencies,
    });
  } catch (error) {
    refuse(error instanceof TenantRegistryError ? error.message : "REGISTRY_UNREADABLE", 1);
    return;
  }
  const server = new GatewayHttpServer(host.select, {
    metricsToken: io.env["AGENTSAFE_METRICS_TOKEN"] ?? null,
    probe: { ready: () => true },
  });
  let address;
  try {
    address = await server.listen(listen.port, listen.host);
  } catch (error) {
    await host.close();
    refuse((error as { code?: string }).code ?? "LISTEN_FAILED", 1);
    return;
  }
  lines.stdout(
    JSON.stringify({
      event: "TENANT_HOST_STARTED",
      listen: `${address.address}:${address.port}`,
      tenants: host.hostnames().length,
    }),
  );

  // A change to the registry's text is a reload; so is SIGHUP. Either way the
  // host reads the file itself, so a half-written file is refused, not served.
  // A tenant that could not be built (its key not yet synced into the mount,
  // most often) is tried again every retryMs until it is, without a restart.
  let seen = io.files.read(registryPath);
  let loaded = clock();
  const poll =
    pollMs > 0
      ? setInterval(() => {
          const text = io.files.read(registryPath);
          const changed = text !== seen;
          const retry = host.failures().length > 0 && clock() - loaded >= retryMs;
          if (changed || retry) {
            seen = text;
            loaded = clock();
            void host.reload();
          }
        }, pollMs)
      : null;
  poll?.unref();
  io.onSignal("SIGHUP", () => {
    seen = io.files.read(registryPath);
    loaded = clock();
    void host.reload();
  });

  let stopping = false;
  const stop = (signal: string): void => {
    if (stopping) return;
    stopping = true;
    if (poll !== null) clearInterval(poll);
    lines.stdout(JSON.stringify({ event: "TENANT_HOST_STOPPED", signal }));
    void server
      .close()
      .then(() => host.close())
      .then(() => io.exit(0));
  };
  io.onSignal("SIGTERM", () => stop("SIGTERM"));
  io.onSignal("SIGINT", () => stop("SIGINT"));
}
