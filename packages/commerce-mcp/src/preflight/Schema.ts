import canonicalContract from "../../contract/CommercePreflight.v1.json" with { type: "json" };
import { CommerceGateError } from "../Errors.js";
import type { CommercePreflightInput } from "./Contracts.js";

export interface PreflightJsonSchema {
  type?: string | readonly string[];
  const?: unknown;
  enum?: readonly unknown[];
  anyOf?: readonly PreflightJsonSchema[];
  required?: readonly string[];
  properties?: Readonly<Record<string, PreflightJsonSchema>>;
  additionalProperties?: boolean | PreflightJsonSchema;
  items?: PreflightJsonSchema;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  minItems?: number;
  maxItems?: number;
  pattern?: string;
  format?: string;
  description?: string;
}

/** Generated from the server's Zod contract; no client-maintained facts or policy schema. */
export const commercePreflightFactsSchema: PreflightJsonSchema =
  canonicalContract.schemas.CommercePreflightFacts;
export const commercePreflightInputSchema: PreflightJsonSchema =
  canonicalContract.schemas.CommercePreflightInput;
export const commerceCheckResultSchema: PreflightJsonSchema =
  canonicalContract.schemas.CommerceCheckResult;
export const commercePreflightResultSchema: PreflightJsonSchema =
  canonicalContract.schemas.CommercePreflightResult;

export function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** Shape validation only; applicability, thresholds, and decisions stay server-owned. */
export function matchesPreflightSchema(value: unknown, schema: PreflightJsonSchema): boolean {
  if ("const" in schema && value !== schema.const) return false;
  if (schema.enum && !schema.enum.includes(value)) return false;
  if (schema.anyOf) return schema.anyOf.some((branch) => matchesPreflightSchema(value, branch));
  if (schema.type === undefined) return false;
  if (typeof schema.type !== "string") {
    return schema.type.some((type) => matchesPreflightSchema(value, { ...schema, type }));
  }
  if (schema.type === "null") return value === null;
  if (schema.type === "boolean") return typeof value === "boolean";
  if (schema.type === "number" || schema.type === "integer") {
    return (
      typeof value === "number" &&
      Number.isFinite(value) &&
      (schema.type !== "integer" || Number.isInteger(value)) &&
      (schema.minimum === undefined || value >= schema.minimum) &&
      (schema.maximum === undefined || value <= schema.maximum)
    );
  }
  if (schema.type === "string") {
    return (
      typeof value === "string" &&
      (schema.minLength === undefined || value.length >= schema.minLength) &&
      (schema.maxLength === undefined || value.length <= schema.maxLength) &&
      (!schema.pattern || new RegExp(schema.pattern).test(value)) &&
      (schema.format !== "date-time" || validTimestamp(value))
    );
  }
  if (schema.type === "array") {
    return (
      Array.isArray(value) &&
      (schema.minItems === undefined || value.length >= schema.minItems) &&
      (schema.maxItems === undefined || value.length <= schema.maxItems) &&
      value.every(
        (item) => schema.items !== undefined && matchesPreflightSchema(item, schema.items),
      )
    );
  }
  if (schema.type !== "object" || !isPlainRecord(value)) return false;
  if (schema.required?.some((key) => !Object.hasOwn(value, key) || value[key] === undefined))
    return false;
  return Object.entries(value).every(([key, item]) => {
    const property =
      schema.properties && Object.hasOwn(schema.properties, key)
        ? schema.properties[key]
        : undefined;
    if (property) return item === undefined || matchesPreflightSchema(item, property);
    return (
      typeof schema.additionalProperties === "object" &&
      matchesPreflightSchema(item, schema.additionalProperties)
    );
  });
}

function validTimestamp(value: string): boolean {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})$/.exec(
      value,
    );
  if (!match || !Number.isFinite(Date.parse(value))) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthDays = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return (
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= monthDays[month - 1] &&
    Number(match[4]) <= 23 &&
    Number(match[5]) <= 59 &&
    (match[6] === undefined || Number(match[6]) <= 59)
  );
}

export function parseCommercePreflightInput(value: unknown): CommercePreflightInput {
  if (!matchesPreflightSchema(value, commercePreflightInputSchema)) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      "preflight must match the bounded commerce-preflight-v1 facts contract. No policy or execution overrides are accepted.",
    );
  }
  // Match the bytes sent over JSON: optional undefined fields are omitted, not invented.
  return JSON.parse(JSON.stringify(value)) as CommercePreflightInput;
}
