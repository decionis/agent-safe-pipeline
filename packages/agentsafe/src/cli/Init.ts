import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import {
  ACTION_NAME,
  CONSEQUENTIAL_METHODS,
  renderConfigFile,
  type ConsequentialMethod,
  type GatewayMode,
  type RouteConfig,
} from "../gateway/GatewayConfig.js";
import { optionPort, optionValue, parseArguments, ArgumentError } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import { DEFAULT_CONFIG_FILE } from "./ConfigFile.js";

export const INIT_ARGUMENTS = {
  valued: ["upstream", "port", "mode", "config"],
  flags: ["force"],
} as const;

const OPENAPI_FILES = ["openapi.yaml", "openapi.yml", "openapi.json"];
const MAX_OPENAPI_BYTES = 4 * 1024 * 1024;
const MAX_ROUTES = 200;
const DEFAULT_UPSTREAM = "http://localhost:3000";
/** What a `package.json` script says about the port the app listens on, when it says. */
const PORT_HINT = /(?:\bPORT=|--port[ =]|\s-p )(\d{2,5})\b/;

/** What `init` learned about the directory, and wrote. */
export interface InitReport {
  readonly path: string;
  readonly upstream: string;
  readonly routes: readonly RouteConfig[];
  readonly source: "flag" | "package.json" | "default";
  readonly openapi: string | null;
}

/** An OpenAPI operationId as an action name, or a name from the path and method. */
export function actionNameFrom(
  operationId: unknown,
  path: string,
  method: ConsequentialMethod,
): string {
  if (typeof operationId === "string") {
    let candidate = operationId
      .trim()
      .replace(/([a-z0-9])([A-Z])/g, "$1.$2")
      .toLowerCase()
      .replace(/[^a-z0-9._:-]+/g, ".")
      .replace(/^[^a-z]+/, "")
      .slice(0, 120);
    // A trailing separator names nothing; a scan from the end drops them all.
    let end = candidate.length;
    while (end > 0 && "._:-".includes(candidate[end - 1] ?? "")) end -= 1;
    candidate = candidate.slice(0, end);
    if (ACTION_NAME.test(candidate)) return candidate;
  }
  const segments = path
    .split("/")
    .filter((segment) => segment !== "" && !segment.startsWith("{") && !segment.startsWith(":"))
    .map((segment) => segment.toLowerCase().replace(/[^a-z0-9]+/g, "-"))
    .filter((segment) => /^[a-z]/.test(segment));
  const resource = segments.at(-1) ?? "http";
  const verb = method === "POST" ? "create" : method === "DELETE" ? "delete" : "update";
  return `${resource}.${verb}`;
}

/**
 * The consequential operations an OpenAPI document declares, as routes. A
 * document that is not one, or that has none, yields no routes; the file
 * is a hint, never a requirement.
 */
export function routesFromOpenApi(text: string): readonly RouteConfig[] {
  let document: unknown;
  try {
    document = parseYaml(text, { maxAliasCount: 100, uniqueKeys: false });
  } catch {
    return [];
  }
  const paths = (document as { paths?: unknown } | null)?.paths;
  if (paths === null || typeof paths !== "object" || Array.isArray(paths)) return [];
  const routes: RouteConfig[] = [];
  for (const [rawPath, item] of Object.entries(paths as Record<string, unknown>)) {
    if (!rawPath.startsWith("/") || item === null || typeof item !== "object") continue;
    const path = rawPath
      .split("/")
      .map((segment) => (segment.startsWith("{") && segment.endsWith("}") ? "*" : segment))
      .join("/")
      .slice(0, 500);
    for (const method of CONSEQUENTIAL_METHODS) {
      const operation = (item as Record<string, unknown>)[method.toLowerCase()];
      if (operation === undefined || operation === null || typeof operation !== "object") continue;
      routes.push({
        path,
        action: actionNameFrom((operation as { operationId?: unknown }).operationId, path, method),
        methods: [method],
      });
      if (routes.length >= MAX_ROUTES) return routes;
    }
  }
  return routes;
}

/** The upstream a `package.json` script implies, or null. */
export function upstreamFromPackage(text: string | null): string | null {
  if (text === null) return null;
  let manifest: unknown;
  try {
    manifest = JSON.parse(text);
  } catch {
    return null;
  }
  const scripts = (manifest as { scripts?: unknown } | null)?.scripts;
  if (scripts === null || typeof scripts !== "object") return null;
  for (const name of ["dev", "start", "serve"]) {
    const script = (scripts as Record<string, unknown>)[name];
    const port = typeof script === "string" ? PORT_HINT.exec(script)?.[1] : undefined;
    if (port !== undefined) return `http://localhost:${port}`;
  }
  return null;
}

/**
 * `agentsafe init`: writes the smallest working configuration into the
 * current directory, and looks around first. A `package.json` whose scripts
 * name a port gives the upstream; an OpenAPI document gives the routes. It
 * modifies no application code and refuses to overwrite a file it finds.
 */
export function runInit(io: CliProcess, argv: readonly string[]): InitReport | null {
  let parsed;
  try {
    parsed = parseArguments(argv, INIT_ARGUMENTS);
  } catch (error) {
    io.stderr(`${error instanceof ArgumentError ? error.message : "ARGUMENTS_INVALID"}\n`);
    io.exit(2);
    return null;
  }
  const target = optionValue(parsed, "config") ?? join(io.cwd, DEFAULT_CONFIG_FILE);
  if (io.files.exists(target) && parsed.options.get("force") !== true) {
    io.stderr(`${target} exists; pass --force to replace it.\n`);
    io.exit(1);
    return null;
  }
  let upstream = optionValue(parsed, "upstream");
  let source: InitReport["source"] = "flag";
  if (upstream === undefined) {
    const hinted = upstreamFromPackage(io.files.read(join(io.cwd, "package.json")));
    upstream = hinted ?? DEFAULT_UPSTREAM;
    source = hinted === null ? "default" : "package.json";
  }
  const port = optionPort(parsed, "port") ?? 8080;
  const modeFlag = optionValue(parsed, "mode")?.trim().toUpperCase();
  const mode: GatewayMode = modeFlag === "SHADOW" ? "SHADOW" : "ENFORCEMENT";
  let routes: readonly RouteConfig[] = [];
  let openapi: string | null = null;
  for (const name of OPENAPI_FILES) {
    const text = io.files.read(join(io.cwd, name));
    if (text === null || Buffer.byteLength(text, "utf8") > MAX_OPENAPI_BYTES) continue;
    routes = routesFromOpenApi(text);
    openapi = name;
    break;
  }
  io.files.write(target, renderConfigFile({ upstream, listen: `127.0.0.1:${port}`, mode, routes }));
  const report: InitReport = { path: target, upstream, routes, source, openapi };
  io.stdout(
    [
      `Wrote ${target}`,
      "",
      `Upstream     ${upstream}${source === "package.json" ? " (from package.json)" : source === "default" ? " (default; edit gateway.upstream)" : ""}`,
      `Routes       ${routes.length === 0 ? "none named; every POST, PUT, PATCH and DELETE is governed" : `${routes.length} from ${openapi ?? "the document"}`}`,
      `Mode         ${mode}`,
      "",
      "Next:",
      `  agentsafe proxy --config ${target}`,
      `  curl -X POST http://127.0.0.1:${port}/payments -H 'content-type: application/json' -d '{"amount": 500}'`,
      "",
    ].join("\n"),
  );
  return report;
}
