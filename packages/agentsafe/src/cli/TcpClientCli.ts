import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  type Stats,
} from "node:fs";
import { resolve } from "node:path";
import {
  TcpConnector,
  TcpTunnel,
  type TcpClientConfig,
  type TcpClientDependencies,
} from "../egress/TcpClient.js";
import { TcpClientError } from "../tcp/TcpWire.js";
import { optionPort, optionValue, parseArguments, type ParsedArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";

export const TCP_CLIENT_ARGUMENTS = {
  valued: ["control-api", "api", "gateway", "route", "credential-file", "target", "port"],
  flags: ["help"],
} as const;

const USAGE =
  "[--control-api https://api.decionis.com] --gateway https://<tenant>.decionisedge.com --route <UUID> --credential-file <path> --target <IP:port>";

const MAX_CREDENTIAL_FILE_BYTES = 4096;

/** No FIFO can block open; no bytes are read before checking the opened file itself. */
export function readTcpCredentialFile(
  file: string,
  options: { readonly platform?: typeof process.platform; readonly uid?: number } = {},
): string {
  const platform = options.platform ?? process.platform;
  const uid = options.uid ?? process.geteuid?.() ?? process.getuid?.();
  const check = (stat: Stats): void => {
    if (!stat.isFile() || stat.isSymbolicLink())
      throw new TcpClientError("TCP_CREDENTIAL_FILE_UNSAFE");
    if (stat.size > MAX_CREDENTIAL_FILE_BYTES)
      throw new TcpClientError("TCP_CREDENTIAL_FILE_TOO_LARGE");
    if (platform !== "win32") {
      if (uid === undefined || stat.uid !== uid)
        throw new TcpClientError("TCP_CREDENTIAL_FILE_OWNER");
      if ((stat.mode & 0o077) !== 0) throw new TcpClientError("TCP_CREDENTIAL_FILE_PERMISSIONS");
    }
  };
  let descriptor: number | undefined;
  const bytes = Buffer.alloc(MAX_CREDENTIAL_FILE_BYTES);
  try {
    const before = lstatSync(file);
    check(before);
    const flags = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0);
    const noFollow = constants.O_NOFOLLOW ?? 0;
    try {
      descriptor = openSync(file, flags | noFollow);
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (noFollow === 0 || !["EINVAL", "ENOTSUP", "EOPNOTSUPP"].includes(code ?? "")) throw error;
      descriptor = openSync(file, flags);
    }
    const opened = fstatSync(descriptor);
    check(opened);
    const pathNow = lstatSync(file);
    check(pathNow);
    // This also seals the fallback on systems/filesystems without O_NOFOLLOW.
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      pathNow.dev !== opened.dev ||
      pathNow.ino !== opened.ino
    ) {
      throw new TcpClientError("TCP_CREDENTIAL_FILE_CHANGED");
    }
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(descriptor, bytes, length, bytes.length - length, length);
      if (count === 0) break;
      length += count;
    }
    check(fstatSync(descriptor));
    return bytes.subarray(0, length).toString("utf8");
  } catch (error) {
    throw error instanceof TcpClientError
      ? error
      : new TcpClientError("TCP_CREDENTIAL_FILE_UNREADABLE");
  } finally {
    bytes.fill(0);
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function required(parsed: ParsedArguments, name: string): string {
  const value = optionValue(parsed, name);
  if (value === undefined || value === "") throw new TcpClientError(`TCP_OPTION_REQUIRED:${name}`);
  return value;
}

function configuration(
  io: CliProcess,
  parsed: ParsedArguments,
  dependencies: TcpClientDependencies,
): TcpClientConfig {
  if (parsed.positionals.length !== 0) throw new TcpClientError("TCP_POSITIONAL_REFUSED");
  const file = resolve(io.cwd, required(parsed, "credential-file"));
  const credential = (): string => {
    const text = (dependencies.readCredential ?? readTcpCredentialFile)(file);
    if (text.length > 2052) throw new TcpClientError("TCP_CREDENTIAL_FILE_UNREADABLE");
    const value = text.trim();
    if (!/^[\w.~-]{16,2048}$/.test(value)) throw new TcpClientError("TCP_CREDENTIAL_INVALID");
    return value;
  };
  credential();
  const api = optionValue(parsed, "api");
  const control = optionValue(parsed, "control-api");
  if (api !== undefined && control !== undefined && api !== control)
    throw new TcpClientError("TCP_CONTROL_API_AMBIGUOUS");
  return {
    controlApi: control ?? api ?? "https://api.decionis.com",
    gatewayUrl: required(parsed, "gateway"),
    routeId: required(parsed, "route"),
    target: required(parsed, "target"),
    credential,
  };
}

function refusal(io: CliProcess, error: unknown, exit: number): void {
  // External messages may contain a URL, file contents or TLS details. Only emit our own codes.
  io.stderr(
    `${JSON.stringify({ event: "TCP_REFUSED_TO_START", code: error instanceof TcpClientError ? error.code : "TCP_CONFIGURATION_INVALID" })}\n`,
  );
  io.exit(exit);
}

function dependenciesFor(
  io: CliProcess,
  dependencies: TcpClientDependencies,
): TcpClientDependencies {
  return {
    fetch: io.fetch,
    ...dependencies,
    report: (event) => {
      io.stdout(`${JSON.stringify(event)}\n`);
      dependencies.report?.(event);
    },
  };
}

function shutdown(io: CliProcess, close: () => Promise<void>): void {
  let stopping = false;
  const stop = (): void => {
    if (stopping) return;
    stopping = true;
    void close().then(
      () => io.exit(0),
      () => io.exit(1),
    );
  };
  io.onSignal("SIGTERM", stop);
  io.onSignal("SIGINT", stop);
}

/** Holds two spare outbound legs using only the connector's credential file and fixed local target. */
export async function runConnector(
  io: CliProcess,
  argv: readonly string[],
  dependencies: TcpClientDependencies = {},
): Promise<void> {
  try {
    const parsed = parseArguments(argv, TCP_CLIENT_ARGUMENTS);
    if (parsed.options.has("help")) {
      io.stdout(
        `agentsafe connector ${USAGE}\nUse the connector credential file. The target is fixed locally; opaque TCP is forwarded without inspecting commands.\n`,
      );
      return;
    }
    if (parsed.options.has("port")) throw new TcpClientError("TCP_CONNECTOR_LISTEN_REFUSED");
    const connector = new TcpConnector(
      configuration(io, parsed, dependencies),
      dependenciesFor(io, dependencies),
    );
    shutdown(io, () => connector.close());
    connector.start();
  } catch (error) {
    refusal(io, error, 2);
  }
}

/** A single loopback listener using the distinct client credential; no arbitrary bind option. */
export async function runTunnel(
  io: CliProcess,
  argv: readonly string[],
  dependencies: TcpClientDependencies = {},
): Promise<void> {
  let tunnel: TcpTunnel | undefined;
  try {
    const parsed = parseArguments(argv, TCP_CLIENT_ARGUMENTS);
    if (parsed.options.has("help")) {
      io.stdout(
        `agentsafe tunnel ${USAGE} --port <local-port>\nUse the client credential file. Listens only on 127.0.0.1; application TLS certificate verification still applies.\n`,
      );
      return;
    }
    const port = optionPort(parsed, "port");
    if (port === undefined) throw new TcpClientError("TCP_OPTION_REQUIRED:port");
    tunnel = new TcpTunnel(
      configuration(io, parsed, dependencies),
      dependenciesFor(io, dependencies),
    );
    const address = await tunnel.listen(port);
    const running = tunnel;
    shutdown(io, () => running.close());
    io.stdout(
      `${JSON.stringify({ event: "TCP_TUNNEL_LISTENING", listen: `127.0.0.1:${address.port}` })}\n`,
    );
  } catch (error) {
    await tunnel?.close();
    refusal(io, error, 2);
  }
}
