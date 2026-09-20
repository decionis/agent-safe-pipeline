import { ProvisionError, provisionWorkspace } from "@decionis/agent-safe-pipeline";
import { z } from "zod";
import { DEFAULT_AUTHORITY_ENDPOINT } from "../gateway/GatewayConfig.js";
import { processSurface } from "../gateway/InstallSurface.js";
import { packageVersion } from "../Version.js";
import { optionValue, parseArguments, ArgumentError, type ParsedArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import {
  credentialsPath,
  readCredentials,
  removeCredentials,
  writeCredentials,
} from "./Credentials.js";

export const LOGIN_ARGUMENTS = {
  valued: ["tenant", "endpoint"],
  flags: ["key-stdin", "provision"],
} as const;

/** What a test hands in beneath the command: the call that mints a workspace. */
export interface LoginDependencies {
  readonly provision?: typeof provisionWorkspace;
}

const KEY = /^[\w.\-:]{16,4096}$/;
const ENDPOINT = /^https:\/\/[^\s/]+$/;

/**
 * `agentsafe login`: stores a Decionis key for this user, readable by this
 * user alone, to be used when no `DECIONIS_API_KEY` is set. The key is read
 * from standard input or a prompt that does not echo, never from an
 * argument, so it appears in no shell history and no process list. Nothing
 * is sent anywhere; `agentsafe doctor` checks that Decionis accepts it.
 */
export async function runLogin(
  io: CliProcess,
  argv: readonly string[],
  dependencies: LoginDependencies = {},
): Promise<void> {
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
  if (parsed.options.get("provision") === true) {
    await provision(io, parsed, dependencies);
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
  if (endpoint !== null && !ENDPOINT.test(endpoint)) {
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

/**
 * `agentsafe login --provision`: a free Decionis workspace, minted now with
 * no account, no email and no card, and stored as the login. It is the step
 * from the local demo authority to Decionis deciding: the workspace
 * evaluates in shadow, every dossier it mints is signed `provisional_anonymous`,
 * and enforcement still needs a key from an organization. The call carries
 * what every hosted call carries, the runtime's version and the surface it
 * was installed from, and nothing about the machine or the person.
 */
async function provision(
  io: CliProcess,
  parsed: ParsedArguments,
  dependencies: LoginDependencies,
): Promise<void> {
  if (optionValue(parsed, "tenant") !== undefined || parsed.options.get("key-stdin") === true) {
    io.stderr("--provision takes no key and no organization: the workspace brings its own.\n");
    io.exit(2);
    return;
  }
  const endpointFlag = optionValue(parsed, "endpoint")?.trim() ?? null;
  if (endpointFlag !== null && !ENDPOINT.test(endpointFlag)) {
    io.stderr("The endpoint is an https origin; nothing was provisioned.\n");
    io.exit(1);
    return;
  }
  const endpoint = endpointFlag ?? DEFAULT_AUTHORITY_ENDPOINT;
  const existing = readCredentials(io);
  if (existing !== null) {
    const path = credentialsPath(io);
    if (
      existing.provisional === true &&
      (existing.endpoint ?? DEFAULT_AUTHORITY_ENDPOINT) === endpoint
    ) {
      io.stdout(
        `A provisional workspace is already stored at ${path}: organization ${existing.tenantId ?? "unknown"}. It decides in shadow; \`agentsafe logout\` before minting another.\n`,
      );
      io.exit(0);
      return;
    }
    io.stderr(`A login is stored at ${path}; keep it, or \`agentsafe logout\` first.\n`);
    io.exit(1);
    return;
  }
  const surface = processSurface(io.env);
  let workspace;
  try {
    workspace = await (dependencies.provision ?? provisionWorkspace)({
      baseUrl: endpoint,
      allowInsecureLoopback: io.env["DECIONIS_ALLOW_INSECURE_LOOPBACK"]?.trim() === "true",
      source: {
        example: `agentsafe-login@${packageVersion()}`,
        ...(surface === null ? {} : { surface }),
      },
      agentName: "agentsafe login",
    });
  } catch (error) {
    io.stderr(`${provisionRefusal(error)}\n`);
    io.exit(1);
    return;
  }
  const path = writeCredentials(io, {
    apiKey: workspace.rawKey,
    tenantId: workspace.orgId,
    endpoint: endpointFlag,
    provisional: true,
  });
  const decisions = workspace.limits["governed_decisions_per_month"];
  const note = workspace.claim["note"];
  io.stdout(
    [
      `Provisioned a free Decionis workspace ${workspace.orgId} (provisional, no account${
        typeof decisions === "number" ? `; ${String(decisions)} governed decisions a month` : ""
      }).`,
      `Stored its key at ${path} (mode 0600).`,
      `Endpoint     ${endpoint}`,
      `Organization ${workspace.orgId}`,
      "",
      "It decides in shadow: every consequential request is forwarded unchanged, and the verdict",
      "Decionis would have given is recorded and reported. Enforcement needs a key from your",
      "organization: agentsafe login.",
      ...(typeof note === "string" && note.length <= 500 ? [`Claim it: ${note}`] : []),
      "Next: agentsafe doctor",
      "",
    ].join("\n"),
  );
  io.exit(0);
}

/** Why the workspace was not minted, by the authority's own name for it, and when to try again. */
function provisionRefusal(error: unknown): string {
  if (!(error instanceof ProvisionError)) {
    return "Decionis could not be asked for a workspace; nothing was stored.";
  }
  const retry =
    error.retryAfterSeconds === null ? "" : ` Try again in ${String(error.retryAfterSeconds)} s.`;
  switch (error.code) {
    case "PROVISION_LIMIT_REACHED":
      return `Decionis is minting no more free workspaces right now (${error.code}).${retry}`;
    case "PROVISION_UNAVAILABLE":
      return `Decionis could not be reached, or answered ${String(error.status ?? "nothing")} (${error.code}).${retry}`;
    case "PROVISION_TIMED_OUT":
      return `Decionis did not answer in time (${error.code}).`;
    case "PROVISION_REFUSED":
      return `Decionis refused to mint a workspace (${error.code}, ${String(error.status ?? "no status")}).`;
    case "PROVISION_RESPONSE_INVALID":
      return `Decionis answered with something other than a workspace (${error.code}).`;
  }
}

/** `agentsafe logout`: removes the stored login; the environment is untouched. */
export function runLogout(io: CliProcess): void {
  const present = readCredentials(io) !== null || io.files.exists(credentialsPath(io));
  const path = removeCredentials(io);
  io.stdout(present ? `Removed ${path}.\n` : `No login stored at ${path}.\n`);
  io.exit(0);
}
