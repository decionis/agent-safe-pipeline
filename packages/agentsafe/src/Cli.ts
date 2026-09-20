#!/usr/bin/env node
/**
 * `agentsafe <command>`. The gateway commands (`init`, `proxy`, `run`,
 * `status`, `doctor`, `test`, `config`, `login`, `logout`, `version`) are
 * in `cli/Commands.ts`. `serve` runs the trusted executor with the reference
 * forwarding handler and the configuration in the environment; an adopter
 * with their own handlers calls `serve(handlers)` from their own entry
 * instead. `verify chain [file]` (also `verify-chain`) walks the chained
 * lines of a file, or of standard input, and exits non-zero on any break.
 * `verify bundle <dir>` (also `verify-bundle`) verifies an evidence bundle
 * offline: every file's digest against the manifest, both chains, and the
 * signature when the bundle carries one. `verify intent <file|dir>...`
 * checks Agent-Safe Intent vectors, or prints the canonical bytes and hash
 * of a binding, offline. `probe-containment <name=host:port>...` runs in
 * the agent zone and reports whether a system of record answers without the
 * executor; it exits 1 when any target does. Anything else is refused with
 * a stable code and exit status 2.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";
import { nodeCliProcess } from "./cli/CliProcess.js";
import { isGatewayCommand, runGatewayCommand } from "./cli/Commands.js";
import { usage } from "./cli/Help.js";
import { runVerifyIntent } from "./cli/VerifyIntent.js";
import { parseTarget, probeContainment } from "./containment/ContainmentProbe.js";
import { dial } from "./egress/TcpProbe.js";
import { serve } from "./Serve.js";
import { packageVersion } from "./Version.js";
import { verifyAuditChain } from "./verify/VerifyAuditChain.js";
import { verifyEvidenceBundle } from "./verify/VerifyEvidenceBundle.js";

const COMMANDS = [
  "init",
  "proxy",
  "run",
  "intercept",
  "status",
  "doctor",
  "test",
  "config",
  "login",
  "logout",
  "version",
  "verify",
  "serve",
  "verify-chain",
  "verify-bundle",
  "verify-intent",
  "probe-containment",
] as const;
/**
 * The whole entry is one function rather than top-level statements, because
 * the single-executable build bundles it as CommonJS, which has no top-level
 * `await`; nothing else about it changes.
 */
async function main(): Promise<void> {
  let command = process.argv[2];
  let rest = process.argv.slice(3);

  if (command === "--version" || command === "-v") command = "version";
  if (command === "--help" || command === "-h") command = "help";
  // `verify chain`, `verify bundle` and `verify intent` are the verifiers
  // under one word; the hyphenated names keep working as they always have.
  if (
    command === "verify" &&
    (rest[0] === "chain" || rest[0] === "bundle" || rest[0] === "intent")
  ) {
    command = `verify-${rest[0]}`;
    rest = rest.slice(1);
  }

  if (command === undefined) {
    // No command is a refusal, as it always was, with the usage beside the code.
    process.stderr.write(usage(packageVersion()));
    process.exit(2);
  } else if (isGatewayCommand(command)) {
    await runGatewayCommand(command, rest, nodeCliProcess());
  } else if (command === "serve") {
    await serve();
  } else if (command === "verify-chain") {
    const source = rest[0];
    const text = readFileSync(source === undefined ? 0 : source, "utf8");
    const report = verifyAuditChain(text.replace(/\n$/, "").split("\n"));
    process.stdout.write(`${JSON.stringify(report)}\n`);
    process.exit(report.ok ? 0 : 1);
  } else if (command === "verify-bundle") {
    const directory = rest[0];
    if (directory === undefined) {
      process.stderr.write(`${JSON.stringify({ event: "BUNDLE_DIRECTORY_REQUIRED" })}\n`);
      process.exit(2);
    }
    const report = await verifyEvidenceBundle({
      read: (name) => {
        try {
          return readFileSync(join(directory, name), "utf8");
        } catch {
          return null;
        }
      },
      verifySignature: async (signature, manifest) => {
        // A public key belongs to whoever is checking, not to the bundle: a
        // signature the bundle verified with its own key proves nothing.
        const publicKey = process.env["AGENTSAFE_EVIDENCE_PUBLIC_KEY"];
        if (publicKey === undefined) return false;
        const { compactVerify, importSPKI } = await import("jose");
        try {
          const verified = await compactVerify(signature, await importSPKI(publicKey, "EdDSA"));
          return Buffer.from(verified.payload).toString("utf8") === manifest;
        } catch {
          return false;
        }
      },
    });
    process.stdout.write(`${JSON.stringify(report)}\n`);
    process.exit(report.ok ? 0 : 1);
  } else if (command === "verify-intent") {
    runVerifyIntent(nodeCliProcess(), rest);
  } else if (command === "probe-containment") {
    const arguments_ = rest;
    if (arguments_.length === 0) {
      process.stderr.write(`${JSON.stringify({ event: "CONTAINMENT_TARGETS_REQUIRED" })}\n`);
      process.exit(2);
    }
    let targets;
    try {
      targets = arguments_.map((argument) => parseTarget(argument));
    } catch (error) {
      process.stderr.write(
        `${JSON.stringify({ event: "CONTAINMENT_TARGET_INVALID", detail: String(error) })}\n`,
      );
      process.exit(2);
    }
    const report = await probeContainment({ targets, dial });
    for (const finding of report.findings) process.stdout.write(`${JSON.stringify(finding)}\n`);
    // A reachable target is the finding worth failing a job over; containment
    // is never asserted, so a clean run exits 0 without claiming anything.
    process.exit(report.noneReachable ? 0 : 1);
  } else if (command === "verify") {
    process.stderr.write(usage(packageVersion()));
    process.exit(2);
  } else {
    process.stderr.write(
      `${JSON.stringify({ event: "UNKNOWN_COMMAND", command: command ?? null, commands: COMMANDS })}\n`,
    );
    process.exit(2);
  }
}

main().catch((error: unknown) => {
  process.stderr.write(
    `${JSON.stringify({ event: "CLI_FAILED", detail: error instanceof Error ? error.message : String(error) })}\n`,
  );
  process.exit(1);
});
