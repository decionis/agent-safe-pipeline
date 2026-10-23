/** Parsed command-line arguments: `--name value`, `--name=value`, `--flag`, and the rest. */
export interface ParsedArguments {
  readonly options: ReadonlyMap<string, string | true>;
  /** Every value of each valued option, in order: what a repeatable option reads. */
  readonly values: ReadonlyMap<string, readonly string[]>;
  readonly positionals: readonly string[];
}

/** Which options a command accepts, and which of them take a value. */
export interface ArgumentSpec {
  readonly valued: readonly string[];
  readonly flags: readonly string[];
}

export class ArgumentError extends Error {
  public constructor(
    public readonly code: "UNKNOWN_OPTION" | "VALUE_REQUIRED" | "VALUE_INVALID",
    public readonly option: string,
  ) {
    super(`${code}: ${option}`);
    this.name = "ArgumentError";
  }
}

/**
 * A small parser, because a command here has a handful of options and a
 * dependency for that would be a dependency for nothing. Unknown options
 * are refused by name; a valued option without a value is refused too.
 */
export function parseArguments(argv: readonly string[], spec: ArgumentSpec): ParsedArguments {
  const options = new Map<string, string | true>();
  const values = new Map<string, string[]>();
  const positionals: string[] = [];
  const set = (name: string, value: string): void => {
    options.set(name, value);
    values.set(name, [...(values.get(name) ?? []), value]);
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index] ?? "";
    if (argument === "--") {
      positionals.push(...argv.slice(index + 1));
      break;
    }
    if (!argument.startsWith("--")) {
      positionals.push(argument);
      continue;
    }
    const equals = argument.indexOf("=");
    const name = equals === -1 ? argument.slice(2) : argument.slice(2, equals);
    if (spec.flags.includes(name)) {
      if (equals !== -1) throw new ArgumentError("VALUE_INVALID", name);
      options.set(name, true);
      continue;
    }
    if (!spec.valued.includes(name)) throw new ArgumentError("UNKNOWN_OPTION", name);
    if (equals !== -1) {
      set(name, argument.slice(equals + 1));
      continue;
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--"))
      throw new ArgumentError("VALUE_REQUIRED", name);
    set(name, value);
    index += 1;
  }
  return { options, values, positionals };
}

/** A valued option as a string, or undefined. */
export function optionValue(parsed: ParsedArguments, name: string): string | undefined {
  const value = parsed.options.get(name);
  return typeof value === "string" ? value : undefined;
}

/** Every value a repeatable option was given, in order; none when it was not given. */
export function optionValues(parsed: ParsedArguments, name: string): readonly string[] {
  return parsed.values.get(name) ?? [];
}

/** A valued option as a port number, refused by name when it is not one. */
export function optionPort(parsed: ParsedArguments, name: string): number | undefined {
  const value = optionValue(parsed, name);
  if (value === undefined) return undefined;
  if (!/^\d{1,5}$/.test(value) || Number(value) < 1 || Number(value) > 65_535) {
    throw new ArgumentError("VALUE_INVALID", name);
  }
  return Number(value);
}
