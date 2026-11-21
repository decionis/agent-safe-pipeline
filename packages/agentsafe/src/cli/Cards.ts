import { PostgresCardHolds } from "../adapters/cards/PostgresCardHolds.js";
import {
  StripeBridgeConfigError,
  stripeBridgeSettingsFromEnv,
} from "../adapters/stripe/StripeBridgeSettings.js";
import { StripeBridgeServer } from "../http/StripeBridgeServer.js";
import { ArgumentError, parseArguments, type ParsedArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";

export const CARDS_COMMANDS = ["holds-schema", "stripe-bridge"] as const;

const SPECS = {
  "holds-schema": { valued: ["table"], flags: [] },
  "stripe-bridge": { valued: [], flags: [] },
} as const;

class UsageError extends Error {}

function optionValue(parsed: ParsedArguments, name: string): string | undefined {
  const value = parsed.options.get(name);
  return typeof value === "string" ? value : undefined;
}

/** The DDL for the shared card hold store, for the operator who creates the tables. */
function holdsSchema(io: CliProcess, parsed: ParsedArguments): number {
  let schema: string;
  try {
    schema = PostgresCardHolds.schema(optionValue(parsed, "table"));
  } catch {
    throw new UsageError("TABLE_INVALID");
  }
  io.stdout(schema);
  return 0;
}

/**
 * Stripe Issuing in front of the executor's card hook (docs/banking/stripe-issuing.md): a
 * listener configured from `STRIPE_BRIDGE_*`, one JSON line per event on stderr, stopped by
 * `SIGTERM` or `SIGINT`. Shadow unless `STRIPE_BRIDGE_MODE=enforce`.
 */
async function stripeBridge(io: CliProcess): Promise<void> {
  let settings;
  try {
    settings = stripeBridgeSettingsFromEnv(io.env, (path) => {
      const text = io.files.read(path);
      if (text === null) throw new StripeBridgeConfigError("STRIPE_BRIDGE_FILE_UNREADABLE");
      return text;
    });
  } catch (error) {
    const code =
      error instanceof StripeBridgeConfigError ? error.code : "STRIPE_BRIDGE_CONFIG_INVALID";
    io.stderr(`${JSON.stringify({ event: "STRIPE_BRIDGE_CONFIG", code })}\n`);
    io.exit(2);
    return;
  }
  const log = (line: Readonly<Record<string, unknown>>) =>
    io.stderr(`${JSON.stringify({ at: new Date().toISOString(), ...line })}\n`);
  const server = StripeBridgeServer.fromSettings(settings, log, (path) => {
    const text = io.files.read(path);
    if (text === null) throw new StripeBridgeConfigError("STRIPE_BRIDGE_FILE_UNREADABLE");
    return text;
  });
  const { port } = await server.listen(settings.port, settings.host);
  log({
    event: "STRIPE_BRIDGE_LISTENING",
    host: settings.host,
    port,
    mode: settings.mode,
    livemode: settings.livemode,
    deadline_ms: settings.deadlineMs,
    on_undecided: settings.onUndecided,
  });
  const stop = (signal: string) => {
    void server.close().then(() => {
      log({ event: "STRIPE_BRIDGE_STOPPED", signal });
      io.exit(0);
    });
  };
  io.onSignal("SIGTERM", () => stop("SIGTERM"));
  io.onSignal("SIGINT", () => stop("SIGINT"));
}

/** `agentsafe cards <command>`: what an operator runs for the card hook. */
export async function runCards(io: CliProcess, argv: readonly string[]): Promise<void> {
  const command = argv[0];
  if (command === undefined || !(CARDS_COMMANDS as readonly string[]).includes(command)) {
    io.stderr(`${JSON.stringify({ event: "CARDS_COMMAND_REQUIRED", commands: CARDS_COMMANDS })}\n`);
    io.exit(2);
    return;
  }
  const name = command as (typeof CARDS_COMMANDS)[number];
  try {
    const parsed = parseArguments(argv.slice(1), SPECS[name]);
    if (name === "stripe-bridge") {
      await stripeBridge(io);
      return;
    }
    io.exit(holdsSchema(io, parsed));
  } catch (error) {
    const code =
      error instanceof UsageError
        ? error.message
        : error instanceof ArgumentError
          ? `${error.code}: ${error.option}`
          : "ARGUMENTS_INVALID";
    io.stderr(`${JSON.stringify({ event: "CARDS_USAGE", command: name, code })}\n`);
    io.exit(2);
  }
}
