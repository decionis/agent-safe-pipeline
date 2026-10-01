import type { GatewayDependencies } from "../gateway/Gateway.js";
import { GatewayConfigError, parseListen } from "../gateway/GatewayConfig.js";
import { TenantHost } from "../hosted/TenantHost.js";
import { TenantRegistryError } from "../hosted/TenantRegistry.js";
import { GatewayHttpServer } from "../http/GatewayHttpServer.js";
import { RedirectServer } from "../http/RedirectServer.js";
import { TlsListener } from "../http/TlsListener.js";
import { SecurityEvents } from "../incident/SecurityEvents.js";
import { CompositeSecretStore } from "../secrets/CompositeSecretStore.js";
import { packageVersion } from "../Version.js";
import { optionPort, optionValue, parseArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";

export const HOST_ARGUMENTS = {
  valued: ["registry", "port", "listen", "tls-cert", "tls-key", "redirect-listen", "apex-page"],
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
 *
 * With `--tls-cert` and `--tls-key` (or AGENTSAFE_TLS_CERT_FILE and
 * AGENTSAFE_TLS_KEY_FILE) the listener terminates TLS itself, so a layer-4
 * load balancer is the whole edge: the key is watched like any mounted
 * secret, and a renewed certificate and key replace the context in place.
 * `--redirect-listen` adds a plain-HTTP listener that only redirects to
 * HTTPS, and `--apex-page` (an HTML file) is what the registry's domain
 * itself answers at `/`.
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
  let tlsFiles: { cert: string; key: string } | null;
  let redirectListen: { host: string; port: number } | null;
  let apexPath: string | null;
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
    const cert = optionValue(parsed, "tls-cert") ?? io.env["AGENTSAFE_TLS_CERT_FILE"];
    const key = optionValue(parsed, "tls-key") ?? io.env["AGENTSAFE_TLS_KEY_FILE"];
    if ((cert === undefined) !== (key === undefined)) {
      throw new GatewayConfigError("CONFIG_INVALID", "tls", "--tls-cert and --tls-key together");
    }
    tlsFiles = cert === undefined || key === undefined ? null : { cert, key };
    const redirect = optionValue(parsed, "redirect-listen") ?? io.env["AGENTSAFE_REDIRECT_LISTEN"];
    if (redirect !== undefined && tlsFiles === null) {
      throw new GatewayConfigError(
        "CONFIG_INVALID",
        "redirect-listen",
        "a redirect to HTTPS needs the listener to terminate TLS",
      );
    }
    redirectListen = redirect === undefined ? null : parseListen(redirect, "redirect-listen");
    apexPath = optionValue(parsed, "apex-page") ?? io.env["AGENTSAFE_APEX_PAGE"] ?? null;
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
  // The listener's own key, in the same watched-secret slot the executor's
  // listener uses; its certificate is read again at every rotation.
  let keys: CompositeSecretStore | null = null;
  let tls: TlsListener | null = null;
  try {
    if (tlsFiles !== null) {
      const files = tlsFiles;
      const production = io.env["NODE_ENV"] === "production";
      const events = new SecurityEvents((line) => lines.stderr(line));
      keys = CompositeSecretStore.fromEnvironment(
        { EXECUTOR_TLS_KEY_FILE: files.key },
        ["EXECUTOR_TLS_KEY"],
        { events, production, enforcePermissions: production, watch: true },
      );
      const store = keys;
      tls = new TlsListener({
        minVersion: "TLSv1.2",
        material: () => {
          const cert = io.files.read(files.cert);
          if (cert === null)
            throw new GatewayConfigError("CONFIG_INVALID", "tls-cert", "a readable PEM file");
          return { cert, key: store.get("EXECUTOR_TLS_KEY"), clientCa: null };
        },
        events,
      });
    }
  } catch (error) {
    keys?.close();
    await host.close();
    refuse(error instanceof Error ? error.message : "TLS_UNAVAILABLE", 1);
    return;
  }
  const apexPage = (): string | null => (apexPath === null ? null : io.files.read(apexPath));
  const server = new GatewayHttpServer(host.select, {
    metricsToken: io.env["AGENTSAFE_METRICS_TOKEN"] ?? null,
    probe: { ready: () => true },
    tls,
    apex: { hostname: () => host.domain(), page: apexPage },
  });
  // A renewal that does not make a valid context (a key that does not match
  // its certificate, a file not yet whole) keeps the context in use and says so.
  const stopRotation =
    keys?.onRotate("EXECUTOR_TLS_KEY", () => {
      try {
        server.rotateTls();
      } catch {
        lines.stderr(JSON.stringify({ event: "TLS_ROTATION_REFUSED" }));
      }
    }) ?? null;
  const redirector =
    redirectListen === null ? null : new RedirectServer({ domain: () => host.domain() });
  let address;
  try {
    address = await server.listen(listen.port, listen.host);
    if (redirector !== null && redirectListen !== null) {
      await redirector.listen(redirectListen.port, redirectListen.host);
    }
  } catch (error) {
    await server.close(0).catch(() => undefined);
    stopRotation?.();
    keys?.close();
    await host.close();
    refuse((error as { code?: string }).code ?? "LISTEN_FAILED", 1);
    return;
  }
  lines.stdout(
    JSON.stringify({
      event: "TENANT_HOST_STARTED",
      listen: `${address.address}:${address.port}`,
      tls: tls !== null,
      redirect: redirectListen === null ? null : `${redirectListen.host}:${redirectListen.port}`,
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
    void Promise.all([server.close(), redirector?.close()])
      .then(() => {
        stopRotation?.();
        keys?.close();
        return host.close();
      })
      .then(() => io.exit(0));
  };
  io.onSignal("SIGTERM", () => stop("SIGTERM"));
  io.onSignal("SIGINT", () => stop("SIGINT"));
}
