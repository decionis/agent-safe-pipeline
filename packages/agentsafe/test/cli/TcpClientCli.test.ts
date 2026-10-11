import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readTcpCredentialFile, runConnector, runTunnel } from "../../src/cli/TcpClientCli.js";
import { TcpClientError } from "../../src/tcp/TcpWire.js";
import { fakeProcess, type FakeProcess } from "../support/GatewayHarness.js";
import { closedPort } from "../support/Environment.js";

const KEY = "synthetic-role-specific-key";
const FILE = "/keys/connector";
const ARGS = [
  "--control-api",
  "https://control.example",
  "--gateway",
  "https://tenant.decionisedge.example",
  "--route",
  "00000000-0000-4000-8000-000000000123",
  "--credential-file",
  FILE,
  "--target",
  "127.0.0.1:5432",
];
const settle = (ms = 10): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function memoryCredentials(io: FakeProcess): { readCredential: (path: string) => string } {
  return {
    readCredential: (path) => {
      const value = io.files.read(path);
      if (value === null) throw new TcpClientError("TCP_CREDENTIAL_FILE_UNREADABLE");
      return value;
    },
  };
}

function credentialFile(contents = KEY, mode = 0o600): string {
  const directory = mkdtempSync(join(tmpdir(), "agentsafe-tcp-credential-"));
  directories.push(directory);
  const file = join(directory, "credential.key");
  writeFileSync(file, contents, { mode });
  chmodSync(file, mode);
  return file;
}

describe("agentsafe connector and tunnel", () => {
  it("reads the role credential file, posts only to the configured API, and stops retries on a signal", async () => {
    const posted: { url: string; authorization: string | null; body: string }[] = [];
    const io = fakeProcess({
      files: { [FILE]: `${KEY}\n` },
      env: { DECIONIS_API_KEY: "must-never-use-workspace-key" },
      fetch: async (input, init) => {
        posted.push({
          url: String(input),
          authorization: new Headers(init?.headers).get("authorization"),
          body: String(init?.body),
        });
        return new Response(null, { status: 403 });
      },
    });
    await runConnector(io, ARGS, memoryCredentials(io));
    await settle();
    expect(posted).toHaveLength(2);
    expect(posted[0]).toEqual({
      url: "https://control.example/v1/public/gateway/tcp/tickets",
      authorization: `Bearer ${KEY}`,
      body: '{"route_id":"00000000-0000-4000-8000-000000000123","role":"connector"}',
    });
    io.signals.get("SIGTERM")?.();
    io.signals.get("SIGINT")?.();
    await settle();
    expect(io.exits).toEqual([0]);
    expect(io.out.join("") + io.err.join("")).not.toContain(KEY);
    expect(io.out.join("") + io.err.join("")).not.toContain("must-never-use-workspace-key");
  });

  it("starts one loopback tunnel and closes its listener cleanly", async () => {
    const port = await closedPort();
    const io = fakeProcess({ files: { [FILE]: KEY } });
    await runTunnel(io, [...ARGS, "--port", String(port)], memoryCredentials(io));
    expect(io.exits).toEqual([]);
    expect(io.out.join("")).toContain(`127.0.0.1:${port}`);
    io.signals.get("SIGINT")?.();
    await settle();
    expect(io.exits).toEqual([0]);
  });

  it("resolves relative credential files from cwd and defaults the API while preserving the alias override", async () => {
    for (const [extra, hostname] of [
      [[], "api.decionis.com"],
      [["--api", "https://staging.example"], "staging.example"],
    ] as const) {
      const posted: string[] = [];
      const io = fakeProcess({
        cwd: "/work/project",
        files: { "/work/project/client.key": KEY },
        fetch: async (input, init) => {
          posted.push(String(input));
          expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${KEY}`);
          return new Response(null, { status: 403 });
        },
      });
      await runConnector(
        io,
        [...ARGS.slice(2), "--credential-file", "./client.key", ...extra],
        memoryCredentials(io),
      );
      await settle();
      expect(posted).toHaveLength(2);
      for (const request of posted) {
        const url = new URL(request);
        expect(url.protocol).toBe("https:");
        expect(url.hostname).toBe(hostname);
        expect(url.port).toBe("");
        expect(url.pathname).toBe("/v1/public/gateway/tcp/tickets");
        expect(url.search).toBe("");
        expect(url.hash).toBe("");
      }
      io.signals.get("SIGTERM")?.();
      await settle();
      expect(io.exits).toEqual([0]);
    }
  });

  it("refuses unsafe targets, bind overrides, plaintext control, unreadable credentials, and missing local ports", async () => {
    const cases = [
      [...ARGS, "--target", "database.example:5432"],
      [...ARGS, "--listen", "0.0.0.0:5432"],
      [...ARGS, "--control-api", "http://control.example"],
      [...ARGS, "--credential-file", "/keys/missing"],
      [...ARGS, "--credential-file", "relative"],
      [...ARGS, "--gateway", "https://other.example/path"],
    ];
    for (const argv of cases) {
      const io = fakeProcess({ files: { [FILE]: KEY } });
      await runConnector(io, argv, memoryCredentials(io));
      expect(io.exits).toEqual([2]);
      expect(io.err.join("")).not.toContain(KEY);
    }
    const missingPort = fakeProcess({ files: { [FILE]: KEY } });
    await runTunnel(missingPort, ARGS, memoryCredentials(missingPort));
    expect(missingPort.exits).toEqual([2]);
    const injected = fakeProcess({ files: { [FILE]: `${KEY}\r\nHost: attacker.example` } });
    await runConnector(injected, ARGS, memoryCredentials(injected));
    expect(injected.exits).toEqual([2]);
    expect(injected.err.join("")).not.toContain("attacker.example");
  });

  it("explains the distinct credentials and application TLS without starting connections", async () => {
    const connector = fakeProcess();
    const tunnel = fakeProcess();
    await runConnector(connector, ["--help"]);
    await runTunnel(tunnel, ["--help"]);
    expect(connector.out.join("")).toContain("connector credential");
    expect(tunnel.out.join("")).toContain("client credential");
    expect(tunnel.out.join("")).toContain("127.0.0.1");
    expect(tunnel.out.join("")).toContain("certificate verification");
    expect(connector.signals.size + tunnel.signals.size).toBe(0);
  });

  it("uses the bounded real-file reader by default", async () => {
    const file = credentialFile();
    let requests = 0;
    const io = fakeProcess({
      fetch: async (_input, init) => {
        expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${KEY}`);
        requests += 1;
        return new Response(null, { status: 403 });
      },
    });
    await runConnector(io, [...ARGS, "--credential-file", file]);
    await settle();
    expect(requests).toBe(2);
    io.signals.get("SIGTERM")?.();
    await settle();
    expect(io.exits).toEqual([0]);
  });

  it.skipIf(process.platform === "win32")(
    "refuses group/world permissions and a different owner before reading",
    () => {
      const file = credentialFile();
      expect(readTcpCredentialFile(file)).toBe(KEY);
      for (const mode of [0o777, 0o644, 0o640]) {
        chmodSync(file, mode);
        expect(() => readTcpCredentialFile(file)).toThrow("TCP_CREDENTIAL_FILE_PERMISSIONS");
      }
      chmodSync(file, 0o600);
      expect(() => readTcpCredentialFile(file, { uid: statSync(file).uid + 1 })).toThrow(
        "TCP_CREDENTIAL_FILE_OWNER",
      );
    },
  );

  it.skipIf(process.platform === "win32")(
    "refuses symbolic links and FIFOs without blocking",
    () => {
      const file = credentialFile();
      const symbolic = `${file}.symlink`;
      symlinkSync(file, symbolic);
      expect(() => readTcpCredentialFile(symbolic)).toThrow("TCP_CREDENTIAL_FILE_UNSAFE");
      const fifo = `${file}.fifo`;
      execFileSync("mkfifo", ["-m", "600", fifo]);
      const started = Date.now();
      expect(() => readTcpCredentialFile(fifo)).toThrow("TCP_CREDENTIAL_FILE_UNSAFE");
      expect(Date.now() - started).toBeLessThan(500);
    },
  );

  it("refuses oversized and nonregular files and skips POSIX mode/owner checks on Windows", () => {
    const oversized = credentialFile("x".repeat(4097));
    expect(() => readTcpCredentialFile(oversized)).toThrow("TCP_CREDENTIAL_FILE_TOO_LARGE");
    expect(() => readTcpCredentialFile(directories[0] ?? "")).toThrow("TCP_CREDENTIAL_FILE_UNSAFE");
    const windows = credentialFile(KEY, 0o777);
    expect(
      readTcpCredentialFile(windows, { platform: "win32", uid: statSync(windows).uid + 1 }),
    ).toBe(KEY);
  });
});
