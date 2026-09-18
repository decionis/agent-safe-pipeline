/**
 * The Decionis key a developer keeps on their own machine: what
 * `agentsafe login` stores, and what an example provisions for itself when
 * asked to run hosted with no key set. One file, one shape, readable by its
 * owner alone, so the two paths onto Decionis share a credential rather
 * than each keeping its own. Production never reads it: a server's
 * credential is mounted, not logged in.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { z } from "zod";

export interface StoredCredentials {
  readonly apiKey: string;
  /** The key's organization, which every intent must name; null when the login did not say. */
  readonly tenantId: string | null;
  /** The authority the key belongs to; null means the default. */
  readonly endpoint: string | null;
  /** True for a workspace an example provisioned without an account; absent for a login. */
  readonly provisional?: boolean;
}

/** The files the store touches, behind a seam so a test hands in a directory of its own. */
export interface CredentialFiles {
  /** The text, or null when there is no such file. */
  read(path: string): string | null;
  write(path: string, text: string, mode: number): void;
  mkdir(path: string): void;
}

export interface CredentialStoreOptions {
  readonly env: Readonly<Record<string, string | undefined>>;
  /** The user's home directory; defaults to the process's. */
  readonly home?: string;
  readonly files?: CredentialFiles;
}

const CREDENTIALS_FILE = "credentials.json";
const MAX_CREDENTIALS_BYTES = 16 * 1024;

const CredentialsSchema = z.strictObject({
  version: z.literal(1),
  decionis: z.strictObject({
    apiKey: z.string().min(1).max(4_096),
    tenantId: z.string().uuid().nullable(),
    endpoint: z.string().min(1).max(500).nullable(),
    provisional: z.boolean().optional(),
  }),
});

export const nodeCredentialFiles: CredentialFiles = {
  read: (path) => {
    try {
      return readFileSync(path, "utf8");
    } catch {
      return null;
    }
  },
  write: (path, text, mode) => {
    writeFileSync(path, text, { encoding: "utf8", mode });
  },
  mkdir: (path) => {
    mkdirSync(path, { recursive: true, mode: 0o700 });
  },
};

/** Where the credential lives: `$AGENTSAFE_HOME`, else the XDG config directory, under `agentsafe`. */
export function credentialsDirectory(options: CredentialStoreOptions): string {
  const explicit = options.env["AGENTSAFE_HOME"]?.trim();
  if (explicit !== undefined && explicit !== "") return explicit;
  const xdg = options.env["XDG_CONFIG_HOME"]?.trim();
  const home = options.home ?? homedir();
  return join(xdg !== undefined && xdg !== "" ? xdg : join(home, ".config"), "agentsafe");
}

export function credentialsPath(options: CredentialStoreOptions): string {
  return join(credentialsDirectory(options), CREDENTIALS_FILE);
}

/**
 * The stored credential, or null when there is none, it cannot be read as
 * one, or the process is marked production, where a login is never a source.
 */
export function readStoredCredentials(options: CredentialStoreOptions): StoredCredentials | null {
  if (options.env["NODE_ENV"] === "production") return null;
  const files = options.files ?? nodeCredentialFiles;
  const text = files.read(credentialsPath(options));
  if (text === null || Buffer.byteLength(text, "utf8") > MAX_CREDENTIALS_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  const result = CredentialsSchema.safeParse(parsed);
  if (!result.success) return null;
  const { provisional, ...credentials } = result.data.decionis;
  return provisional === undefined ? credentials : { ...credentials, provisional };
}

/** Writes the credential, readable by this user alone, and returns where. */
export function writeStoredCredentials(
  options: CredentialStoreOptions,
  credentials: StoredCredentials,
): string {
  const files = options.files ?? nodeCredentialFiles;
  const directory = credentialsDirectory(options);
  files.mkdir(directory);
  const path = join(directory, CREDENTIALS_FILE);
  files.write(path, `${JSON.stringify({ version: 1, decionis: credentials }, null, 2)}\n`, 0o600);
  return path;
}
