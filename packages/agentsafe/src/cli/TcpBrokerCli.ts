import { isAbsolute } from "node:path";
import { TcpControlClient } from "../egress/TcpControlClient.js";
import { parseListen } from "../gateway/GatewayConfig.js";
import { TcpBroker } from "../http/TcpBroker.js";
import { TlsListener } from "../http/TlsListener.js";
import { SecurityEvents } from "../incident/SecurityEvents.js";
import { CompositeSecretStore } from "../secrets/CompositeSecretStore.js";
import { optionValue, parseArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";

/** Operator-only broker command. The only dialed origin comes from startup configuration. */
export async function runTcpBroker(
  io: CliProcess,
  argv: readonly string[],
  certificatePollMs = 5_000,
): Promise<void> {
  let keys: CompositeSecretStore | null = null;
  let broker: TcpBroker | null = null;
  try {
    const parsed = parseArguments(argv, {
      valued: ["listen", "tls-cert", "tls-key", "token-file", "control-api", "domain"],
      flags: [],
    });
    if (parsed.positionals.length) throw new Error("TCP_BROKER_ARGUMENTS_INVALID");
    const value = (name: string): string => {
      const found = optionValue(parsed, name);
      if (!found) throw new Error("TCP_BROKER_ARGUMENT_REQUIRED");
      return found;
    };
    const listen = parseListen(optionValue(parsed, "listen") ?? ":8443", "listen");
    const domain = value("domain");
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain))
      throw new Error("TCP_BROKER_DOMAIN_INVALID");
    const certFile = value("tls-cert");
    const keyFile = value("tls-key");
    const tokenFile = value("token-file");
    if (![certFile, keyFile, tokenFile].every(isAbsolute))
      throw new Error("TCP_BROKER_FILE_INVALID");
    const control = new TcpControlClient(
      value("control-api"),
      () => io.files.read(tokenFile) ?? "",
    );
    const events = new SecurityEvents((line) => io.stderr(`${line}\n`));
    const production = io.env["NODE_ENV"] === "production";
    keys = CompositeSecretStore.fromEnvironment(
      { EXECUTOR_TLS_KEY_FILE: keyFile },
      ["EXECUTOR_TLS_KEY"],
      { events, production, enforcePermissions: production, watch: true },
    );
    const store = keys;
    const tls = new TlsListener({
      minVersion: "TLSv1.2",
      events,
      material: () => {
        const cert = io.files.read(certFile);
        if (!cert) throw new Error("TCP_BROKER_TLS_INVALID");
        return { cert, key: store.get("EXECUTOR_TLS_KEY"), clientCa: null };
      },
    });
    broker = new TcpBroker({ tls, domain, control });
    const running = broker;
    const address = await running.listen(listen.port, listen.host);
    let certificate = io.files.read(certFile);
    const rotate = (): void => {
      try {
        running.rotateTls();
        certificate = io.files.read(certFile);
      } catch {
        io.stderr('{"event":"TCP_BROKER_TLS_ROTATION_REFUSED"}\n');
      }
    };
    const stopRotation = store.onRotate("EXECUTOR_TLS_KEY", rotate);
    // cert-manager may renew a certificate while retaining the private key.
    const certificatePoll = setInterval(() => {
      if (io.files.read(certFile) !== certificate) rotate();
    }, certificatePollMs);
    certificatePoll.unref();
    let stopped = false;
    const stop = (): void => {
      if (stopped) return;
      stopped = true;
      stopRotation();
      clearInterval(certificatePoll);
      void running.close().finally(() => {
        store.close();
        io.exit(0);
      });
    };
    io.onSignal("SIGTERM", stop);
    io.onSignal("SIGINT", stop);
    io.stdout(
      `${JSON.stringify({ event: "TCP_BROKER_STARTED", listen: `${address.address}:${address.port}` })}\n`,
    );
  } catch {
    await broker?.close().catch(() => undefined);
    keys?.close();
    io.stderr('{"event":"TCP_BROKER_START_REFUSED"}\n');
    io.exit(2);
  }
}
