#!/usr/bin/env node
/**
 * `agentsafe <command>`. `serve` runs the trusted executor with the reference
 * forwarding handler and the configuration in the environment; an adopter
 * with their own handlers calls `serve(handlers)` from their own entry
 * instead. `verify-chain [file]` walks the chained lines of a file, or of
 * standard input, and exits non-zero on any break. Anything else is refused
 * with a stable code and exit status 2.
 */
import { readFileSync } from "node:fs";
import process from "node:process";
import { serve } from "./Serve.js";
import { verifyAuditChain } from "./verify/VerifyAuditChain.js";

const COMMANDS = ["serve", "verify-chain"] as const;
const command = process.argv[2];

if (command === "serve") {
  await serve();
} else if (command === "verify-chain") {
  const source = process.argv[3];
  const text = readFileSync(source === undefined ? 0 : source, "utf8");
  const report = verifyAuditChain(text.replace(/\n$/, "").split("\n"));
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.exit(report.ok ? 0 : 1);
} else {
  process.stderr.write(
    `${JSON.stringify({ event: "UNKNOWN_COMMAND", command: command ?? null, commands: COMMANDS })}\n`,
  );
  process.exit(2);
}
