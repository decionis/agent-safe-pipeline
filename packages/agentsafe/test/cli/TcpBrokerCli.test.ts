import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runTcpBroker } from "../../src/cli/TcpBrokerCli.js";
import { runHost } from "../../src/cli/Host.js";
import { closedPort } from "../support/Environment.js";
import { fakeProcess } from "../support/GatewayHarness.js";
import { TestCertificateAuthority } from "../support/TestCertificateAuthority.js";

describe("TCP broker command", () => {
  const paths: string[] = [];
  afterEach(() => {
    for (const path of paths.splice(0)) rmSync(path, { recursive: true, force: true });
  });
  it("refuses missing and unsafe operator configuration without echoing a secret", async () => {
    const io = fakeProcess();
    await runTcpBroker(io, []);
    expect(io.exits).toEqual([2]);
    expect(io.err.join("")).toBe('{"event":"TCP_BROKER_START_REFUSED"}\n');
    const bad = fakeProcess();
    await runTcpBroker(bad, [
      "--domain",
      "decionisedge.com",
      "--token-file",
      "secret\r\nvalue",
      "--tls-key",
      "/missing",
      "--tls-cert",
      "/missing",
      "--control-api",
      "http://bad.example",
    ]);
    expect(bad.exits).toEqual([2]);
    expect(bad.err.join("")).not.toContain("secret");
  });
  it("starts, observes certificate-only rotation and closes on a signal", async () => {
    const directory = mkdtempSync(join(tmpdir(), "tcp-broker-cli-"));
    paths.push(directory);
    const keyFile = join(directory, "tls.key");
    const certFile = join(directory, "tls.crt");
    const tokenFile = join(directory, "token");
    const ca = new TestCertificateAuthority();
    const certificate = ca.issueServer(["*.decionisedge.com"]);
    writeFileSync(keyFile, certificate.key, { mode: 0o600 });
    const io = fakeProcess({
      files: { [certFile]: certificate.cert, [tokenFile]: "s".repeat(64) },
    });
    await runTcpBroker(
      io,
      [
        "--listen",
        `127.0.0.1:${await closedPort()}`,
        "--domain",
        "decionisedge.com",
        "--token-file",
        tokenFile,
        "--tls-key",
        keyFile,
        "--tls-cert",
        certFile,
        "--control-api",
        "https://api.example",
      ],
      10,
    );
    expect(io.exits).toEqual([]);
    expect(io.out.join("")).toContain("TCP_BROKER_STARTED");
    io.stored.set(certFile, { text: certificate.cert + "\n", mode: undefined });
    await vi.waitFor(() => expect(io.err.join("")).toContain("TLS_CONTEXT_ROTATED"));
    io.signals.get("SIGTERM")?.();
    await vi.waitFor(() => expect(io.exits).toEqual([0]));
    expect(io.out.join("") + io.err.join("")).not.toContain("s".repeat(64));
  });
  it("refuses TCP relay configuration without host TLS while retaining the registry", async () => {
    const registry = "/etc/agentsafe/tenants.yaml";
    const io = fakeProcess({
      env: { AGENTSAFE_TCP_BROKER_HOST: "agentsafe-tcp-broker.agentsafe.svc.cluster.local" },
      files: {
        [registry]: JSON.stringify({ version: 1, domain: "decionisedge.com", tenants: [] }),
      },
    });
    await runHost(io, ["--registry", registry], {}, 0);
    expect(io.exits).toEqual([2]);
    expect(io.err.join("")).toContain("TCP_RELAY_CONFIGURATION_INVALID");
  });
});
