import { z } from "zod";
import { JsonObjectSchema, JsonValueSchema } from "./JsonValue.js";

/** Where the published schema of the binding lives; the `$id` it carries. */
export const INTENT_SCHEMA_ID =
  "https://github.com/decionis/agent-safe-pipeline/blob/master/spec/intent/v1/schema.json";

const identifier = z.string().min(1).max(200);
const actionType = z
  .string()
  .min(1)
  .max(120)
  .regex(/^[a-z][a-z0-9._:-]*$/);
const sha256Digest = z.string().regex(/^sha256:[0-9a-f]{64}$/);

/**
 * The `agent-safe.intent/1` binding as it is hashed and sent, as a strict
 * schema: what `CanonicalIntentHasher.bindingOf` produces, and what an
 * implementation in another language must produce byte for byte before
 * canonicalization. Nothing here trims or coerces, because a validator that
 * altered a binding would be validating different bytes than it hashes.
 * `context` is any JSON object that carries the trusted runtime's
 * `idempotency_key`; every other object refuses a key it does not name.
 */
export const AuthorityIntentBindingSchema = z
  .object({
    protocol_version: z.literal("agent-safe.intent/1"),
    tenant_id: z.string().uuid(),
    intent_id: z.string().uuid(),
    captured_at: z.string().datetime(),
    expires_at: z.string().datetime(),
    actor: z
      .object({
        id: identifier,
        type: identifier,
        runtime: identifier.optional(),
        trust_level: z.string().min(1).max(80).optional(),
      })
      .strict(),
    action: z
      .object({
        type: actionType,
        resource: z.string().min(1).max(500),
        parameters: JsonObjectSchema,
      })
      .strict(),
    context: z.object({ idempotency_key: z.string().min(1).max(180) }).catchall(JsonValueSchema),
    downstream_target: z
      .object({
        system: identifier,
        operation: identifier,
        environment: identifier.optional(),
        endpoint: z.string().min(1).max(500).optional(),
      })
      .strict(),
    expected_effect_digest: sha256Digest.optional(),
  })
  .strict()
  .meta({
    title: "agent-safe.intent/1 binding",
    description:
      "The execution intent as the authority receives it and as it is hashed: keys sorted by UTF-16 code unit, encoded as JSON without whitespace, and digested with SHA-256. Every property is inside the hash.",
  });

/** What the schema accepts; the tests hold it to the `AuthorityIntentBinding` wire interface. */
export type AuthorityIntentBindingInput = z.infer<typeof AuthorityIntentBindingSchema>;

/**
 * The binding's JSON Schema (draft 2020-12), the document published at
 * `spec/intent/v1/schema.json`. It is derived from the schema above, so the
 * published file and the validator cannot disagree; a test holds the file to
 * this output.
 */
export function intentBindingJsonSchema(): Record<string, unknown> {
  const generated = z.toJSONSchema(AuthorityIntentBindingSchema, {
    target: "draft-2020-12",
    io: "input",
  });
  const { $schema, ...rest } = generated;
  return { $schema, $id: INTENT_SCHEMA_ID, ...rest };
}
