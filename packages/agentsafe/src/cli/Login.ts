import { z } from "zod";
import { DEFAULT_AUTHORITY_ENDPOINT } from "../gateway/GatewayConfig.js";
import { optionValue, parseArguments, ArgumentError } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import {
  credentialsPath,
  readCredentials,
  removeCredentials,
  writeCredentials,
} from "./Credentials.js";

export const LOGIN_ARGUMENTS = {
  valued: ["tenant", "endpoint"],
  flags: ["key-stdin"],
} as const;

const KEY = /^[\w.\-:]{16,4096}$/;

/**
 * `agentsafe login`: stores a Decionis key for this user, readable by this
 * user alone, to be used when no `DECIONIS_API_KEY` is set. The key is read
 * from standard input or a prompt that does not echo, never from an
 * argument, so it appears in no shell history and no process list. Nothing
 * is sent anywhere; `agentsafe doctor` checks that Decionis accepts it.
 */
export async function runLogin(io: CliProcess, argv: readonly string[]): Promise<void> {
  let parsed;
  try {
    parsed = parseArguments(argv, LOGIN_ARGUMENTS);
  } catch (error) {
    io.stderr(`${error instanceof ArgumentError ? error.message : "ARGUMENTS_INVALID"}\n`);
    io.exit(2);
    return;
  }
  if (io.env["NODE_ENV"] === "production") {
    io.stderr("login is for a developer's machine; a deployment mounts DECIONIS_API_KEY_FILE.\n");
    io.exit(1);
    return;
  }
  const key = (await io.readLine("Decionis API key: ", true)).trim();
  if (!KEY.test(key)) {
    io.stderr("That does not look like a Decionis key; nothing was stored.\n");
    io.exit(1);
    return;
  }
  const tenant =
    optionValue(parsed, "tenant")?.trim() ??
    (await io.readLine("Organization id (blank to set DECIONIS_TENANT_ID later): ", false)).trim();
  if (tenant !== "" && !z.string().uuid().safeParse(tenant).success) {
    io.stderr("The organization id is a UUID; nothing was stored.\n");
    io.exit(1);
    return;
  }
  const endpoint = optionValue(parsed, "endpoint")?.trim() ?? null;
  if (endpoint !== null && !/^https:\/\/[^\s/]+$/.test(endpoint)) {
    io.stderr("The endpoint is an https origin; nothing was stored.\n");
    io.exit(1);
    return;
  }
  const path = writeCredentials(io, {
    apiKey: key,
    tenantId: tenant === "" ? null : tenant,
    endpoint,
  });
  io.stdout(
    [
      `Stored a Decionis login at ${path} (mode 0600).`,
      `Endpoint     ${endpoint ?? DEFAULT_AUTHORITY_ENDPOINT}`,
      `Organization ${tenant === "" ? "not set; export DECIONIS_TENANT_ID" : tenant}`,
      "",
      "DECIONIS_API_KEY in the environment takes precedence over this login.",
      "Next: agentsafe doctor",
      "",
    ].join("\n"),
  );
  io.exit(0);
}

/** `agentsafe logout`: removes the stored login; the environment is untouched. */
export function runLogout(io: CliProcess): void {
  const present = readCredentials(io) !== null || io.files.exists(credentialsPath(io));
  const path = removeCredentials(io);
  io.stdout(present ? `Removed ${path}.\n` : `No login stored at ${path}.\n`);
  io.exit(0);
}
