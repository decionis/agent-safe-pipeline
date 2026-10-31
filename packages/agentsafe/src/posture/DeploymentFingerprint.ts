import { createHash } from "node:crypto";
import { ActionManifest, Rfc8785, type JsonValue } from "@decionis/agent-safe-pipeline";
import type { FailurePolicy, GatewayConfig, GatewayMode } from "../gateway/GatewayConfig.js";
import { gatewayManifest } from "../gateway/GatewayManifest.js";
import { RouteTable } from "../gateway/RouteTable.js";

/** The contract of the document: versioned, so a reader holding one knows what it covers. */
export const DEPLOYMENT_FINGERPRINT_CONTRACT = "agent-safe.deployment-fingerprint/1";

/** What a secret-derived value is written as in the digested configuration. */
export const REDACTED = "[REDACTED]";

/** One row of the route table: what it matches, the action, and how a decision about it is enforced. */
export interface FingerprintRoute {
  readonly methods: readonly string[];
  readonly path: string;
  readonly action: string | null;
  /** The gateway's mode for a governed row; `PASSTHROUGH` or `REFUSE` where nothing is asked. */
  readonly mode: GatewayMode | "PASSTHROUGH" | "REFUSE";
  /** What a governed row does when the authority cannot answer; null where nothing is asked. */
  readonly failure_policy: FailurePolicy | null;
}

/**
 * `agent-safe.deployment-fingerprint/1`: what one running gateway is, from
 * what it was configured with and nothing it observed, so the same
 * configuration under the same build always yields the same document. A
 * report of what was tested here (an acceptance run) can name its digest as
 * the condition it holds under: any change to a field below is a different
 * deployment.
 */
export interface DeploymentFingerprintDocument {
  readonly fingerprint: typeof DEPLOYMENT_FINGERPRINT_CONTRACT;
  /** The runtime's version, and the image digest the orchestrator declared for it (`supplied`), or null. */
  readonly runtime: { readonly version: string; readonly image_digest: string | null };
  /** `sha256:` over the RFC 8785 form of the effective configuration, every secret-derived value redacted. */
  readonly configuration_digest: string;
  /**
   * The digest of the action space this gateway loaded, as `agentsafe actions
   * manifest --gateway --digest` prints it for the same configuration; null
   * when no manifest describes it: the gateway governs nothing, or more than
   * one manifest lists.
   */
  readonly action_manifest_digest: string | null;
  /** The route table, in the order the gateway tries it. */
  readonly routes: readonly FingerprintRoute[];
  /** Who the gateway says acts: the actor it names, the header a caller names itself in, the subject's issuer. */
  readonly principals: {
    readonly actor: string;
    readonly header: string | null;
    readonly subject_issuer: string | null;
  };
  /** Whose identity reaches the upstream: the caller's, or a credential the gateway holds; and its own token. */
  readonly upstream_identity: {
    readonly mode: "CALLER" | "GATEWAY_CREDENTIAL";
    readonly header: string | null;
    readonly gateway_token: boolean;
  };
  readonly authority: {
    readonly kind: GatewayConfig["authority"]["kind"];
    readonly endpoint: string;
    readonly tenant: string;
  };
  /** The declared systems of record the agent zone must not reach directly, as `name=host:port`. */
  readonly containment: readonly string[];
}

export interface DeploymentFingerprint {
  readonly document: DeploymentFingerprintDocument;
  /** `sha256:` over the document's RFC 8785 form. */
  readonly digest: string;
}

export interface FingerprintRuntime {
  readonly version: string;
  readonly imageDigest: string | null;
}

function digestOf(value: JsonValue): string {
  return `sha256:${createHash("sha256").update(Rfc8785.stringify(value)).digest("hex")}`;
}

/**
 * The effective configuration as the fingerprint digests it: every setting,
 * but never where it came from, which does not change what the gateway does.
 * The configuration holds no secret value, only the names of secrets and the
 * files they are read from; the tenant keys' digests are the one value derived
 * from a secret, so each is written as `[REDACTED]`, and a rotation that keeps
 * their number changes nothing.
 */
export function redactedConfiguration(config: GatewayConfig): JsonValue {
  const { sources: _sources, tenantKeys, ...settings } = config;
  void _sources;
  return JSON.parse(
    JSON.stringify({ ...settings, tenantKeys: tenantKeys.map(() => REDACTED) }),
  ) as JsonValue;
}

/** The fingerprint of a gateway built from this configuration under this runtime. Nothing is sent anywhere. */
export function deploymentFingerprint(
  config: GatewayConfig,
  runtime: FingerprintRuntime,
): DeploymentFingerprint {
  const routes = RouteTable.of(config);
  let manifest: string | null;
  try {
    manifest = ActionManifest.digest(gatewayManifest(routes));
  } catch {
    // No action at all, or more actions or targets than one manifest lists.
    manifest = null;
  }
  const document: DeploymentFingerprintDocument = {
    fingerprint: DEPLOYMENT_FINGERPRINT_CONTRACT,
    runtime: { version: runtime.version, image_digest: runtime.imageDigest },
    configuration_digest: digestOf(redactedConfiguration(config)),
    action_manifest_digest: manifest,
    routes: routes.rows().map((row) => {
      const governed = row.disposition === "GOVERN";
      return {
        methods: [...row.methods],
        path: row.path,
        action: row.action,
        mode: governed ? config.authority.mode : row.disposition,
        failure_policy: governed ? config.authority.failurePolicy : null,
      };
    }),
    principals: {
      actor: config.actor.id,
      header: config.interception.principalHeader,
      subject_issuer: config.subject?.issuer ?? null,
    },
    upstream_identity: {
      mode: config.upstream.credential === null ? "CALLER" : "GATEWAY_CREDENTIAL",
      header: config.upstream.credential?.header ?? null,
      gateway_token: config.upstream.gatewayToken !== null,
    },
    authority: {
      kind: config.authority.kind,
      endpoint: config.authority.endpoint,
      tenant: config.authority.tenantId,
    },
    containment: config.containment.targets.map(
      (target) => `${target.name}=${target.host}:${target.port}`,
    ),
  };
  return { document, digest: digestOf(document as unknown as JsonValue) };
}

/**
 * The fields of two fingerprints that differ, by name, in document order;
 * none when they are the same deployment.
 */
export function changedFields(
  before: DeploymentFingerprintDocument,
  after: DeploymentFingerprintDocument,
): readonly string[] {
  return Object.keys(after).filter(
    (field) =>
      Rfc8785.stringify((before as unknown as Record<string, JsonValue>)[field] ?? null) !==
      Rfc8785.stringify((after as unknown as Record<string, JsonValue>)[field] ?? null),
  );
}
