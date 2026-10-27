import { z } from "zod";

/** Published bundle selectors understood by Decionis, shared by config and dispatch validation. */
export const PolicyIdSchema = z.string().uuid();
export const PolicyVersionSchema = z
  .string()
  .min(1)
  .max(100)
  .regex(/^\P{Cc}+$/u);
