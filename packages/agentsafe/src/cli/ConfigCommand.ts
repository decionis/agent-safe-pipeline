import { stringify as toYaml } from "yaml";
import type { GatewayConfig } from "../gateway/GatewayConfig.js";
import { parseArguments, ArgumentError } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import { explainRefusal, resolveGateway, PROXY_ARGUMENTS } from "./Proxy.js";

/** The configuration as it resolved, with no secret in it: names of secrets only, and where each setting came from. */
export function effectiveConfig(config: GatewayConfig): Record<string, unknown> {
  return {
    version: 1,
    gateway: {
      listen: `${config.listen.host}:${config.listen.port}`,
      upstream: config.upstream.url,
      upstreamInsecure: config.upstream.insecure,
      upstreamTimeoutMs: config.upstream.timeoutMs,
      system: config.upstream.system,
      environment: config.upstream.environment,
    },
    authority: {
      kind: config.authority.kind.toLowerCase(),
      endpoint: config.authority.endpoint,
      mode: config.authority.mode.toLowerCase(),
      failurePolicy: config.authority.failurePolicy === "FAIL_CLOSED" ? "failClosed" : "failOpen",
      tenantId: config.authority.tenantId,
      timeoutMs: config.authority.timeoutMs,
      allowInsecureLoopback: config.authority.allowInsecureLoopback,
    },
    interception: {
      http: config.interception.http,
      unmatched: config.interception.unmatched.toLowerCase(),
      maxBodyBytes: config.interception.maxBodyBytes,
      maxEmbeddedBodyBytes: config.interception.maxEmbeddedBodyBytes,
      principalHeader: config.interception.principalHeader,
      routes: config.interception.routes.map((route) => ({
        path: route.path,
        action: route.action,
        methods: [...route.methods],
      })),
    },
    actor: { ...config.actor },
    intentTtlSeconds: config.intentTtlSeconds,
    presence:
      config.escalation.mode === "NONE"
        ? { managed: false }
        : {
            managed: config.escalation.mode === "MANAGED",
            approverId: config.escalation.approverId,
            ...(config.escalation.mode === "MANAGED"
              ? { approverRole: config.escalation.approverRole }
              : {}),
            level: config.escalation.requirements.level,
            methods: [...config.escalation.requirements.methods],
          },
    evidence: { ...config.evidence },
    output: { format: config.output.format.toLowerCase(), verbose: config.output.verbose },
    secrets: { required: [...config.secrets.required], values: "never shown" },
    production: config.production,
    sources: { ...config.sources },
  };
}

/** `agentsafe config`: the effective configuration and the layer each setting came from. */
export function runConfig(io: CliProcess, argv: readonly string[]): void {
  let parsed;
  let config: GatewayConfig;
  let path: string | null;
  try {
    parsed = parseArguments(argv, PROXY_ARGUMENTS);
    const resolved = resolveGateway(io, parsed);
    config = resolved.config;
    path = resolved.configPath;
  } catch (error) {
    io.stderr(
      explainRefusal(error).replace("refused to start", "cannot resolve the configuration"),
    );
    io.exit(error instanceof ArgumentError ? 2 : 1);
    return;
  }
  const effective = { ...effectiveConfig(config), file: path };
  io.stdout(
    parsed.options.get("json") === true ? `${JSON.stringify(effective)}\n` : toYaml(effective),
  );
  io.exit(0);
}
