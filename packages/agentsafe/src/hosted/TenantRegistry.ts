import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { CanonicalIntentHasher, type JsonValue } from "@decionis/agent-safe-pipeline";

export const TENANT_REGISTRY_VERSION = 1;
/** The most tenants one host serves; a registry over it is refused, not truncated. */
export const MAX_TENANTS = 1_000;

/** A DNS label: what a tenant id becomes as the leftmost part of its hostname. */
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
/** A lower-case hostname of at least two labels. */
const DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
/** Labels a tenant may not take: they name the operator's own hosts. */
const RESERVED_LABELS: ReadonlySet<string> = new Set(["www", "api", "status", "admin", "console"]);

const RateLimitSchema = z.strictObject({
  requestsPerSecond: z.number().positive().max(10_000),
  burst: z.number().int().min(1).max(100_000),
});

const TenantSchema = z.strictObject({
  /** The tenant's label; it is served at `{id}.{domain}`. */
  id: z
    .string()
    .regex(LABEL, "a lower-case DNS label")
    .refine((id) => !RESERVED_LABELS.has(id), "a label the operator keeps for itself"),
  upstream: z.string().url(),
  tenantKeyDigests: z.array(z.string()).min(1).max(2),
  workspace: z.strictObject({
    /** The Decionis workspace the tenant's evaluations run in. */
    tenantId: z.string().uuid(),
    /** The mounted file holding the workspace key; the key itself is never in the registry. */
    apiKeyFile: z
      .string()
      .min(1)
      .max(500)
      .refine((path) => isAbsolute(path), "an absolute path"),
  }),
  /** This tenant's rate, per process; the registry's `rateLimit` otherwise. */
  rateLimit: RateLimitSchema.optional(),
  /** The tenant's `interception` section, as `agentsafe.yaml` has it; validated by the gateway's loader. */
  interception: z.record(z.string(), z.unknown()).optional(),
});

export const TenantRegistrySchema = z.strictObject({
  version: z.literal(TENANT_REGISTRY_VERSION),
  /** The domain every tenant is a host under, e.g. `decionisedge.com`. */
  domain: z.string().regex(DOMAIN, "a lower-case hostname"),
  /** Where each tenant's evidence is kept, one directory per tenant; none when absent. */
  evidenceDir: z
    .string()
    .min(1)
    .max(500)
    .refine((path) => isAbsolute(path), "an absolute path")
    .optional(),
  /** The rate every tenant without its own is admitted at; the hosted default when absent. */
  rateLimit: RateLimitSchema.optional(),
  tenants: z.array(TenantSchema).max(MAX_TENANTS),
});

export type TenantEntry = z.infer<typeof TenantSchema>;
export type TenantRegistry = z.infer<typeof TenantRegistrySchema>;

/** A registry that cannot be served: the code, and where it went wrong, never a value from the file. */
export class TenantRegistryError extends Error {
  public constructor(
    public readonly code: "REGISTRY_UNREADABLE" | "REGISTRY_INVALID" | "REGISTRY_DUPLICATE_TENANT",
    public readonly where: string | null = null,
  ) {
    super(where === null ? code : `${code}: ${where}`);
    this.name = "TenantRegistryError";
  }
}

/**
 * The tenant registry the operator mounts, parsed and checked whole: YAML or
 * JSON, `version: 1`, one domain, and each tenant with its label, upstream,
 * key digests and workspace. What each tenant's gateway makes of its entry
 * (a public https upstream, well-formed digests, a valid interception
 * section) is checked again by the gateway's own loader when it is built.
 */
export function parseTenantRegistry(text: string): TenantRegistry {
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch {
    throw new TenantRegistryError("REGISTRY_UNREADABLE");
  }
  const parsed = TenantRegistrySchema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new TenantRegistryError(
      "REGISTRY_INVALID",
      issue === undefined ? null : issue.path.join(".") || "(root)",
    );
  }
  const seen = new Set<string>();
  for (const tenant of parsed.data.tenants) {
    if (seen.has(tenant.id)) throw new TenantRegistryError("REGISTRY_DUPLICATE_TENANT", tenant.id);
    seen.add(tenant.id);
  }
  return parsed.data;
}

/** The hostname a tenant is served at. */
export function tenantHostname(registry: TenantRegistry, tenant: TenantEntry): string {
  return `${tenant.id}.${registry.domain}`;
}

/**
 * A digest of everything that shapes a tenant's gateway: its entry and the
 * registry-wide settings it inherits. A reload rebuilds a tenant's gateway
 * only when this changes, so an edit to one tenant never interrupts another.
 */
export function tenantFingerprint(registry: TenantRegistry, tenant: TenantEntry): string {
  const canonical = CanonicalIntentHasher.stringify({
    domain: registry.domain,
    evidenceDir: registry.evidenceDir ?? null,
    rateLimit: registry.rateLimit ?? null,
    tenant: tenant as unknown as JsonValue,
  });
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}
