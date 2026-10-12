import { PostgresCardHolds } from "../adapters/cards/PostgresCardHolds.js";
import { ArgumentError, parseArguments, type ParsedArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";

export const CARDS_COMMANDS = ["holds-schema"] as const;

const SPECS = {
  "holds-schema": { valued: ["table"], flags: [] },
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

/** `agentsafe cards <command>`: what an operator runs for the card hold store. */
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
