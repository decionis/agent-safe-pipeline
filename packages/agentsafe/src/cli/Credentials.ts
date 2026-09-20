/**
 * What `agentsafe login` keeps, read through the process seam the commands
 * share. The file, its shape and its place are the pipeline's
 * `StoredCredentials`: the same credential an example provisions for
 * itself under `DECIONIS_HOSTED=1`, so a login and a provisioned workspace
 * are one thing on a developer's machine.
 */
import {
  credentialsDirectory as sharedCredentialsDirectory,
  credentialsPath as sharedCredentialsPath,
  readStoredCredentials,
  writeStoredCredentials,
  type CredentialStoreOptions,
} from "@decionis/agent-safe-pipeline";
import type { StoredCredentials } from "../gateway/GatewayConfig.js";
import type { CliProcess } from "./CliProcess.js";

function store(io: CliProcess): CredentialStoreOptions {
  return {
    env: io.env,
    home: io.home,
    files: {
      read: (path) => io.files.read(path),
      write: (path, text, mode) => {
        io.files.write(path, text, mode);
      },
      mkdir: (path) => {
        io.files.mkdir(path);
      },
    },
  };
}

/** Where `agentsafe login` keeps what it stored: `$AGENTSAFE_HOME`, else the XDG config directory. */
export function credentialsDirectory(io: CliProcess): string {
  return sharedCredentialsDirectory(store(io));
}

export function credentialsPath(io: CliProcess): string {
  return sharedCredentialsPath(store(io));
}

/**
 * The stored login, or null when there is none or it cannot be read as one.
 * Production never reads it: a server's credential is mounted, not logged
 * in, and the gateway's loader refuses the layer there.
 */
export function readCredentials(io: CliProcess): StoredCredentials | null {
  const stored = readStoredCredentials(store(io));
  if (stored === null) return null;
  // Whether the key is a provisional workspace's travels with it: the loader
  // runs such a key in shadow and refuses to enforce with it.
  return {
    apiKey: stored.apiKey,
    tenantId: stored.tenantId,
    endpoint: stored.endpoint,
    ...(stored.provisional === undefined ? {} : { provisional: stored.provisional }),
  };
}

/** Writes the login, readable by this user alone. */
export function writeCredentials(io: CliProcess, credentials: StoredCredentials): string {
  return writeStoredCredentials(store(io), credentials);
}

export function removeCredentials(io: CliProcess): string {
  const path = credentialsPath(io);
  io.files.remove(path);
  return path;
}
