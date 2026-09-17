import { join } from "node:path";
import { z } from "zod";
import type { StoredCredentials } from "../gateway/GatewayConfig.js";
import type { CliProcess } from "./CliProcess.js";

const CREDENTIALS_FILE = "credentials.json";
const MAX_CREDENTIALS_BYTES = 16 * 1024;

const CredentialsSchema = z.strictObject({
  version: z.literal(1),
  decionis: z.strictObject({
    apiKey: z.string().min(1).max(4_096),
    tenantId: z.string().uuid().nullable(),
    endpoint: z.string().min(1).max(500).nullable(),
  }),
});

/** Where `agentsafe login` keeps what it stored: `$AGENTSAFE_HOME`, else the XDG config directory. */
export function credentialsDirectory(io: CliProcess): string {
  const explicit = io.env["AGENTSAFE_HOME"]?.trim();
  if (explicit !== undefined && explicit !== "") return explicit;
  const xdg = io.env["XDG_CONFIG_HOME"]?.trim();
  return join(xdg !== undefined && xdg !== "" ? xdg : join(io.home, ".config"), "agentsafe");
}

export function credentialsPath(io: CliProcess): string {
  return join(credentialsDirectory(io), CREDENTIALS_FILE);
}

/**
 * The stored login, or null when there is none or it cannot be read as one.
 * Production never reads it: a server's credential is mounted, not logged
 * in, and the gateway's loader refuses the layer there.
 */
export function readCredentials(io: CliProcess): StoredCredentials | null {
  if (io.env["NODE_ENV"] === "production") return null;
  const text = io.files.read(credentialsPath(io));
  if (text === null || Buffer.byteLength(text, "utf8") > MAX_CREDENTIALS_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  const result = CredentialsSchema.safeParse(parsed);
  if (!result.success) return null;
  return result.data.decionis;
}

/** Writes the login, readable by this user alone. */
export function writeCredentials(io: CliProcess, credentials: StoredCredentials): string {
  const directory = credentialsDirectory(io);
  io.files.mkdir(directory);
  const path = join(directory, CREDENTIALS_FILE);
  io.files.write(
    path,
    `${JSON.stringify({ version: 1, decionis: credentials }, null, 2)}\n`,
    0o600,
  );
  return path;
}

export function removeCredentials(io: CliProcess): string {
  const path = credentialsPath(io);
  io.files.remove(path);
  return path;
}
