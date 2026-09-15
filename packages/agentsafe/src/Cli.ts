#!/usr/bin/env node
/**
 * `agentsafe <command>`. `serve` runs the trusted executor with the reference
 * forwarding handler and the configuration in the environment; an adopter
 * with their own handlers calls `serve(handlers)` from their own entry
 * instead. `verify-chain [file]` walks the chained lines of a file, or of
 * standard input, and exits non-zero on any break. `verify-bundle <dir>`
 * verifies an evidence bundle offline: every file's digest against the
 * manifest, both chains, and the signature when the bundle carries one.
 * `probe-containment <name=host:port>...` runs in the agent zone and reports
 * whether a system of record answers without the executor; it exits 1 when
 * any target does. Anything else is refused with a stable code and exit
 * status 2.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";
import { parseTarget, probeContainment } from "./containment/ContainmentProbe.js";
import { dial } from "./egress/TcpProbe.js";
import { serve } from "./Serve.js";
import { verifyAuditChain } from "./verify/VerifyAuditChain.js";
import { verifyEvidenceBundle } from "./verify/VerifyEvidenceBundle.js";

const COMMANDS = ["serve", "verify-chain", "verify-bundle", "probe-containment"] as const;
const command = process.argv[2];

if (command === "serve") {
  await serve();
} else if (command === "verify-chain") {
  const source = process.argv[3];
  const text = readFileSync(source === undefined ? 0 : source, "utf8");
  const report = verifyAuditChain(text.replace(/\n$/, "").split("\n"));
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.exit(report.ok ? 0 : 1);
} else if (command === "verify-bundle") {
  const directory = process.argv[3];
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
} else if (command === "probe-containment") {
  const arguments_ = process.argv.slice(3);
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
} else {
  process.stderr.write(
    `${JSON.stringify({ event: "UNKNOWN_COMMAND", command: command ?? null, commands: COMMANDS })}\n`,
  );
  process.exit(2);
}
