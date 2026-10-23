import { z } from "zod";

/**
 * The reference the trusted executor stamps into a plan step's intent. It
 * lives apart from the plan so that the intent schema can name it without
 * importing the canonicalizer the plan's digest needs.
 */
export const PlanIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[a-z0-9][\w.-]*$/i);
export const PlanStepIdSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[a-z][a-z0-9_-]*$/);

/** Which step of which plan an intent is, as the trusted executor states it. */
export const PlanStepReferenceSchema = z
  .object({
    plan_id: PlanIdSchema,
    plan_digest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    step_id: PlanStepIdSchema,
  })
  .strict();

export type PlanStepReference = z.infer<typeof PlanStepReferenceSchema>;
