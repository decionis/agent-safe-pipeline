import { isAbsolute, join } from "node:path";
import { parse as parseYaml } from "yaml";
import type { CliProcess } from "./CliProcess.js";

/** The file a directory is expected to hold, when no other is named. */
export const DEFAULT_CONFIG_FILE = "agentsafe.yaml";
const MAX_CONFIG_BYTES = 256 * 1024;

export class ConfigFileError extends Error {
  public constructor(
    public readonly code:
      "CONFIG_FILE_NOT_FOUND" | "CONFIG_FILE_UNREADABLE" | "CONFIG_FILE_NOT_YAML",
    public readonly path: string,
  ) {
    super(`${code}: ${path}`);
    this.name = "ConfigFileError";
  }
}

export interface LoadedConfigFile {
  readonly path: string | null;
  readonly document: unknown;
}

/** The file to read: `--config`, then `AGENTSAFE_CONFIG`, then `./agentsafe.yaml` if it exists. */
export function locateConfigFile(io: CliProcess, flag: string | undefined): string | null {
  const named = flag ?? io.env["AGENTSAFE_CONFIG"];
  if (named !== undefined && named.trim() !== "") {
    return isAbsolute(named) ? named : join(io.cwd, named);
  }
  const conventional = join(io.cwd, DEFAULT_CONFIG_FILE);
  return io.files.exists(conventional) ? conventional : null;
}

/**
 * Reads and parses the file. A named file that is missing is a refusal; the
 * conventional one is simply absent. The document is handed to the loader
 * as data, which is where its shape is checked and refused by key.
 */
export function loadConfigFile(io: CliProcess, flag: string | undefined): LoadedConfigFile {
  const path = locateConfigFile(io, flag);
  if (path === null) return { path: null, document: null };
  const text = io.files.read(path);
  if (text === null) {
    throw new ConfigFileError(
      flag !== undefined || io.env["AGENTSAFE_CONFIG"] !== undefined
        ? "CONFIG_FILE_NOT_FOUND"
        : "CONFIG_FILE_UNREADABLE",
      path,
    );
  }
  if (Buffer.byteLength(text, "utf8") > MAX_CONFIG_BYTES) {
    throw new ConfigFileError("CONFIG_FILE_UNREADABLE", path);
  }
  let document: unknown;
  try {
    document = parseYaml(text, { maxAliasCount: 10, uniqueKeys: true });
  } catch {
    throw new ConfigFileError("CONFIG_FILE_NOT_YAML", path);
  }
  if (document === null || document === undefined) return { path, document: null };
  if (typeof document !== "object" || Array.isArray(document)) {
    throw new ConfigFileError("CONFIG_FILE_NOT_YAML", path);
  }
  return { path, document };
}
