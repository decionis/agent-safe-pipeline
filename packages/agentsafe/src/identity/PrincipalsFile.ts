import { z } from "zod";

export const PRINCIPALS_VERSION = "agent-safe.principals/1";
export const MAX_PRINCIPALS = 200;

/** What an operator may do; each control route names the scope it needs. */
export const OPERATOR_SCOPES = [
  "halt",
  "resume",
  "secrets.reload",
  "status",
  "metrics",
  "evidence",
] as const;
export type OperatorScope = (typeof OPERATOR_SCOPES)[number];

const identifier = z.string().trim().min(1).max(200);
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);
// Bounded here, and read as a rule by the registry: `RateLimiter.parseRule`
// is what a rate rule means, and its refusal names the principal by id
// rather than by its position in the file.
const rateLimit = z.string().trim().min(1).max(20);
const claimValue = z.union([z.string().max(500), z.number(), z.boolean()]);

/**
 * How a principal proves itself. The file holds identities and digests,
 * never a token: a bearer credential is the SHA-256 of the token, a client
 * certificate is named by its SAN URI and optionally pinned by fingerprint,
 * and a workload token is named by issuer and subject.
 */
export const PrincipalCredentialSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("MTLS"),
    san_uri: z
      .string()
      .trim()
      .min(1)
      .max(500)
      .regex(/^[a-z][a-z0-9+.-]*:/i),
    cert_fingerprint_sha256: hex64.optional(),
  }),
  z.strictObject({
    kind: z.literal("WORKLOAD_JWT"),
    issuer: z.string().trim().min(1).max(500),
    subject: z.string().trim().min(1).max(500),
    audience: z.string().trim().min(1).max(200).optional(),
    required_claims: z.record(z.string().min(1).max(200), claimValue).optional(),
  }),
  z.strictObject({ kind: z.literal("BEARER"), token_sha256: hex64 }),
]);

const common = {
  id: identifier,
  credential: PrincipalCredentialSchema,
  /** `<count>/<seconds>`: how many requests this principal may make per window. */
  rate_limit: rateLimit.optional(),
};

export const ProposerSchema = z.strictObject({
  ...common,
  role: z.literal("PROPOSER"),
  tenant_id: z.string().uuid(),
  actor: z.strictObject({ id: identifier, type: identifier, runtime: identifier.optional() }),
  allowed_actions: z.array(z.string().trim().min(1).max(120)).min(1).max(50),
});

export const OperatorSchema = z.strictObject({
  ...common,
  role: z.literal("OPERATOR"),
  scopes: z.array(z.enum(OPERATOR_SCOPES)).min(1).max(OPERATOR_SCOPES.length),
});

export const PrincipalsFileSchema = z.strictObject({
  version: z.literal(PRINCIPALS_VERSION),
  principals: z
    .array(z.discriminatedUnion("role", [ProposerSchema, OperatorSchema]))
    .min(1)
    .max(MAX_PRINCIPALS),
});

export type PrincipalEntry = z.infer<typeof PrincipalsFileSchema>["principals"][number];
export type PrincipalCredentialEntry = z.infer<typeof PrincipalCredentialSchema>;

/** A refusal to load principals: the code and the entry or path it concerns, never a value. */
export class PrincipalsError extends Error {
  public constructor(
    public readonly code: string,
    public readonly subject: string | null = null,
  ) {
    super(subject === null ? code : `${code}: ${subject}`);
    this.name = "PrincipalsError";
  }
}

/** The identity a credential asserts; two principals may never share one. */
export function credentialIdentity(credential: PrincipalCredentialEntry): string {
  switch (credential.kind) {
    case "BEARER":
      return `BEARER:${credential.token_sha256}`;
    case "MTLS":
      return `MTLS:${credential.san_uri}`;
    case "WORKLOAD_JWT":
      return `WORKLOAD_JWT:${credential.issuer}|${credential.subject}`;
  }
}

/**
 * Parses and checks a principals file: the schema, then no duplicate id and
 * no credential identity claimed twice. What it cannot check here, that
 * every allowed action is registered and every credential kind has what it
 * needs, the registry checks when it is built.
 */
export function parsePrincipalsFile(text: string): readonly PrincipalEntry[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new PrincipalsError("PRINCIPALS_INVALID", "not JSON");
  }
  const result = PrincipalsFileSchema.safeParse(parsed);
  if (!result.success) {
    const issue = result.error.issues[0];
    throw new PrincipalsError(
      "PRINCIPALS_INVALID",
      issue === undefined ? null : issue.path.join("."),
    );
  }
  const ids = new Set<string>();
  const identities = new Set<string>();
  for (const entry of result.data.principals) {
    if (ids.has(entry.id)) throw new PrincipalsError("PRINCIPALS_DUPLICATE_ID", entry.id);
    ids.add(entry.id);
    const identity = credentialIdentity(entry.credential);
    if (identities.has(identity))
      throw new PrincipalsError("PRINCIPALS_CREDENTIAL_SHARED", entry.id);
    identities.add(identity);
  }
  return result.data.principals;
}
