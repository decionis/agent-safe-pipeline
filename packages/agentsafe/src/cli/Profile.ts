import { ApiProfiles, type ApiProfile } from "@decionis/agent-safe-pipeline";
import { ArgumentError, optionValue, parseArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";

export const PROFILE_COMMANDS = ["list", "openapi"] as const;

const SPEC = { valued: ["server", "prefix"], flags: [] } as const;
const SERVER = /^https:\/\/[^\s/?#]+(?:\/[^\s?#]*)?$/;
const LOCAL = /^http:\/\/(?:127\.0\.0\.1|localhost)(?::\d{1,5})?(?:\/[^\s?#]*)?$/;

/**
 * `agentsafe profile list` names the API intent profiles this build ships;
 * `agentsafe profile openapi <id> --server <gateway URL>` writes one as the
 * OpenAPI 3.0 document an AgentCore Gateway target (or any OpenAPI tool
 * importer) is created from. Every operation's server is the AgentSafe
 * gateway, so each tool call an agent makes is governed before it reaches the
 * platform.
 */
export function runProfile(io: CliProcess, argv: readonly string[]): void {
  const command = argv[0];
  if (command === "list") {
    io.stdout(
      `${JSON.stringify({
        profiles: ApiProfiles.ids().map((id) => {
          const profile = ApiProfiles.get(id)!;
          return {
            id,
            platform: profile.platform,
            title: profile.definition.title,
            operations: profile.definition.operations.length,
          };
        }),
      })}\n`,
    );
    return;
  }
  if (command !== "openapi") {
    io.stderr(
      `${JSON.stringify({ event: "PROFILE_COMMAND_REQUIRED", commands: PROFILE_COMMANDS })}\n`,
    );
    io.exit(2);
    return;
  }
  try {
    const parsed = parseArguments(argv.slice(1), SPEC);
    const id = parsed.positionals[0];
    const profile = id === undefined ? null : ApiProfiles.get(id);
    if (profile === null) {
      io.stderr(
        `${JSON.stringify({ event: "PROFILE_UNKNOWN", profile: id ?? null, profiles: ApiProfiles.ids() })}\n`,
      );
      io.exit(2);
      return;
    }
    const server = optionValue(parsed, "server");
    if (server === undefined || !(SERVER.test(server) || LOCAL.test(server))) {
      io.stderr(
        `${JSON.stringify({ event: "PROFILE_SERVER_REQUIRED", detail: "--server https://<the AgentSafe gateway>" })}\n`,
      );
      io.exit(2);
      return;
    }
    const prefix = optionValue(parsed, "prefix") ?? profile.definition.prefixes[0]!;
    if (!profile.definition.prefixes.includes(prefix)) {
      io.stderr(
        `${JSON.stringify({ event: "PROFILE_PREFIX_UNKNOWN", prefixes: profile.definition.prefixes })}\n`,
      );
      io.exit(2);
      return;
    }
    io.stdout(
      `${JSON.stringify(profileOpenApi(profile, withoutTrailingSlash(server), prefix), null, 2)}\n`,
    );
  } catch (error) {
    io.stderr(
      `${JSON.stringify({ event: "PROFILE_ARGUMENTS_INVALID", detail: error instanceof ArgumentError ? error.message : "invalid arguments" })}\n`,
    );
    io.exit(2);
  }
}

/** The server URL without trailing slashes, read without a backtracking pattern. */
function withoutTrailingSlash(server: string): string {
  let end = server.length;
  while (end > 0 && server[end - 1] === "/") end -= 1;
  return server.slice(0, end);
}

/**
 * One profile as an OpenAPI 3.0.3 document whose server is the gateway. The
 * operations that share a method and path (an API that overloads a path by a
 * query value) are one OpenAPI operation, named after the one without a query
 * constraint, with the selecting query values as documented parameters: the
 * gateway still tells them apart.
 */
export function profileOpenApi(
  profile: ApiProfile,
  server: string,
  prefix: string,
): Record<string, unknown> {
  const paths: Record<string, Record<string, Record<string, unknown>>> = {};
  const groups = new Map<string, ApiProfile["definition"]["operations"][number][]>();
  for (const operation of profile.definition.operations) {
    const key = `${operation.method} ${prefix}${operation.path}`;
    groups.set(key, [...(groups.get(key) ?? []), operation]);
  }
  for (const [key, operations] of groups) {
    const [method, path] = [key.slice(0, key.indexOf(" ")), key.slice(key.indexOf(" ") + 1)];
    const primary = operations.find((operation) => operation.query === undefined) ?? operations[0]!;
    const placeholders = [...path.matchAll(/\{([A-Z]\w{0,63})\}/gi)].map((found) => found[1]!);
    const queries = new Map<string, Set<string>>();
    for (const operation of operations) {
      for (const [name, value] of Object.entries(operation.query ?? {})) {
        queries.set(name, new Set([...(queries.get(name) ?? []), value]));
      }
    }
    const readsBody = operations.some((operation) =>
      Object.values(operation.facts).some((pointer) => pointer.startsWith("/body")),
    );
    const governed = operations
      .map(
        (operation) =>
          `${
            operation.query === undefined
              ? ""
              : `With ${Object.entries(operation.query)
                  .map(([name, value]) => `${name}=${value}`)
                  .join("&")}: `
          }${operation.summary} Governed as ${operation.action}.`,
      )
      .join(" ");
    paths[path] = {
      ...(paths[path] ?? {}),
      [method.toLowerCase()]: {
        operationId: primary.id.replaceAll(".", "_"),
        summary: primary.summary,
        description: `${governed} The AgentSafe gateway asks Decionis before the call reaches ${profile.definition.title.split(":")[0]}; a held or refused call is answered by the gateway, never forwarded.`,
        parameters: [
          ...placeholders.map((name) => ({
            name,
            in: "path",
            required: true,
            schema: { type: "string" },
          })),
          ...[...queries].map(([name, values]) => ({
            name,
            in: "query",
            required: false,
            schema: { type: "string", enum: [...values] },
          })),
        ],
        ...(method === "DELETE"
          ? {}
          : {
              requestBody: {
                required: readsBody,
                content: {
                  "application/json": { schema: { type: "object", additionalProperties: true } },
                },
              },
            }),
        responses: {
          default: {
            description:
              "The platform's answer, or the gateway's own when Decionis held or refused the call (the agentsafe-execution header says which).",
          },
        },
        "x-agentsafe-profile": profile.id,
        "x-agentsafe-actions": operations.map((operation) => ({
          operation: operation.id,
          action: operation.action,
          ...(operation.query === undefined ? {} : { query: operation.query }),
        })),
      },
    };
  }
  return {
    openapi: "3.0.3",
    info: {
      title: profile.definition.title,
      version: profile.id,
      description: `The ${profile.id} API intent profile (agent-safe.profile.api/1), served through the AgentSafe gateway at ${server}.`,
    },
    servers: [{ url: server }],
    paths,
  };
}
