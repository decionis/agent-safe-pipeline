#!/usr/bin/env node
/**
 * `agentsafe <command>`. `serve` runs the trusted executor with the reference
 * forwarding handler and the configuration in the environment; an adopter
 * with their own handlers calls `serve(handlers)` from their own entry
 * instead. Anything else is refused with a stable code and exit status 2.
 */
import process from "node:process";
import { serve } from "./Serve.js";

const COMMANDS = ["serve"] as const;
const command = process.argv[2];

if (command === "serve") {
  await serve();
} else {
  process.stderr.write(
    `${JSON.stringify({ event: "UNKNOWN_COMMAND", command: command ?? null, commands: COMMANDS })}\n`,
  );
  process.exit(2);
}
