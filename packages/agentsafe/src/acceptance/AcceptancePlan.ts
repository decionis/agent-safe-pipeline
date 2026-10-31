/**
 * The plan of an acceptance run, `agent-safe.acceptance-plan/1`: what the
 * operator names, and the only thing a run sends anywhere
 * ([ADR 0009](../../../../docs/architecture/decisions/0009-acceptance-run-on-named-targets.md)).
 *
 * The plan is the operator's statement. A canary is a resource the operator
 * says may change; nothing here can check that, so the report repeats it as
 * the operator's word. What the plan establishes is the run's scope: the
 * writes, origins, providers and servers it names, and nothing else.
 */
import { createHash } from "node:crypto";
import { JsonValueSchema, Rfc8785, type JsonValue } from "@decionis/agent-safe-pipeline";
import { z } from "zod";

export const ACCEPTANCE_PLAN_VERSION = "agent-safe.acceptance-plan/1";

/** At most this many writes of each kind, so one run's evidence stays one document. */
export const MAX_PLAN_WRITES = 16;

const name = z
  .string()
  .regex(/^[a-z0-9][a-z0-9._-]{0,63}$/, "lower case letters, digits, '.', '_' or '-'");
const httpUrl = z
  .string()
  .max(2_000)
  .url()
  .refine((value) => /^https?:$/.test(new URL(value).protocol), "an http or https URL");
const method = z.enum(["POST", "PUT", "PATCH", "DELETE"]);
const path = z
  .string()
  .max(2_000)
  .regex(/^\/[^\s#]*$/, "a path from '/', with its query if any, and no fragment");

/** One write the run sends: its method, its path with any query, and its JSON body. */
export const PlanWriteSchema = z.strictObject({
  name,
  method,
  path,
  body: JsonValueSchema.optional(),
});

/** A write the operator expects refused, at a resource the operator says may change. */
export const ProhibitedWriteSchema = PlanWriteSchema.extend({
  canary: z.string().min(1).max(300),
});

export const AcceptancePlanSchema = z
  .strictObject({
    version: z.literal(ACCEPTANCE_PLAN_VERSION),
    /** The deployed gateway, as the agent's zone reaches it. */
    gateway: httpUrl,
    /**
     * When a report from this plan stops being current. The fingerprint does
     * not see network policy, cloud IAM or the upstream's own configuration,
     * so a report must lapse on a date even when nothing it binds moved.
     */
    expires_at: z.string().datetime({ offset: false }),
    permitted: z.array(PlanWriteSchema).max(MAX_PLAN_WRITES).default([]),
    prohibited: z.array(ProhibitedWriteSchema).max(MAX_PLAN_WRITES).default([]),
    /** For each upstream origin, a read with no side effect. */
    origins: z
      .array(z.strictObject({ name, url: httpUrl }))
      .max(MAX_PLAN_WRITES)
      .default([]),
    providers: z
      .array(
        z.strictObject({
          name,
          url: httpUrl,
          write: PlanWriteSchema.omit({ name: true }).extend({
            canary: z.string().min(1).max(300),
          }),
        }),
      )
      .max(MAX_PLAN_WRITES)
      .default([]),
    mcp: z
      .array(z.strictObject({ name, url: httpUrl }))
      .max(MAX_PLAN_WRITES)
      .default([]),
    metadata: z.boolean().default(false),
  })
  .superRefine((plan, context) => {
    const names = [...plan.permitted, ...plan.prohibited].map((write) => write.name);
    const repeated = names.find((value, index) => names.indexOf(value) !== index);
    if (repeated !== undefined) {
      context.addIssue({
        code: "custom",
        message: `the write name ${repeated} is used twice`,
        path: ["permitted"],
      });
    }
  });

export type AcceptancePlan = z.infer<typeof AcceptancePlanSchema>;
export type PlanWrite = z.infer<typeof PlanWriteSchema>;
export type ProhibitedWrite = z.infer<typeof ProhibitedWriteSchema>;

/** A plan refused as written: the first problem, by field. */
export class AcceptancePlanError extends Error {
  public constructor(public readonly detail: string) {
    super(`ACCEPTANCE_PLAN_INVALID: ${detail}`);
    this.name = "AcceptancePlanError";
  }
}

/** The plan, checked; refused with the first problem by its field. */
export function parseAcceptancePlan(value: unknown): AcceptancePlan {
  const parsed = AcceptancePlanSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0]!;
    throw new AcceptancePlanError(`${issue.path.join(".") || "plan"}: ${issue.message}`);
  }
  return parsed.data;
}

/** `sha256:` over the plan's RFC 8785 form: what a report says it ran. */
export function planDigest(plan: AcceptancePlan): string {
  const canonical = Rfc8785.stringify(plan as unknown as JsonValue);
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

/**
 * A write's path and query as the gateway's listener reads them: parsed as a
 * URL, so a character a client percent-encodes on the way is compared encoded.
 */
export function splitTarget(target: string): { readonly path: string; readonly search: string } {
  const url = new URL(target, "http://gateway.invalid");
  return { path: url.pathname, search: url.search };
}

/** A write's body as it is sent: JSON, or nothing. */
export function writeBody(write: { readonly body?: JsonValue | undefined }): Buffer {
  return write.body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(write.body));
}

/** A gateway's base URL with no trailing `/`, so a route under it is joined once. */
export function withoutTrailingSlashes(url: string): string {
  let base = url;
  while (base.endsWith("/")) base = base.slice(0, -1);
  return base;
}
