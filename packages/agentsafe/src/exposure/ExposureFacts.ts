import type { InterceptedRequest } from "../gateway/InterceptedRequest.js";
import type {
  ExposureActionType,
  ExposureDeclaration,
  ExposureRouteSubject,
} from "./ExposureDeclaration.js";

/**
 * What a money-releasing request states, as the ledger counts it: the action
 * type, the amount in integer minor units, the currency, and each subject's
 * identifier. The identifiers stay in this process: the ledger receives
 * only their digests (ExposureGate).
 */
export interface ExposureFacts {
  readonly actionType: ExposureActionType;
  readonly amount: number;
  readonly currency: string;
  readonly subjects: Readonly<Partial<Record<ExposureRouteSubject, string>>>;
}

/** Why a declared fact could not be read; the request is never counted on a guess. */
export type ExposureFactsRefusal =
  "EXPOSURE_AMOUNT_UNREADABLE" | "EXPOSURE_CURRENCY_UNREADABLE" | "EXPOSURE_SUBJECT_UNREADABLE";

export type ExposureFactsResult =
  | { readonly ok: true; readonly facts: ExposureFacts }
  | { readonly ok: false; readonly code: ExposureFactsRefusal };

/** The longest identifier a subject may be: an identifier, never a payload. */
export const MAX_SUBJECT_LENGTH = 200;

/** ISO 4217 currencies without minor units, and those with three; every other has two. */
const ZERO_DECIMALS: ReadonlySet<string> = new Set([
  "BIF",
  "CLP",
  "DJF",
  "GNF",
  "ISK",
  "JPY",
  "KMF",
  "KRW",
  "PYG",
  "RWF",
  "UGX",
  "UYI",
  "VND",
  "VUV",
  "XAF",
  "XOF",
  "XPF",
]);
const THREE_DECIMALS: ReadonlySet<string> = new Set([
  "BHD",
  "IQD",
  "JOD",
  "KWD",
  "LYD",
  "OMR",
  "TND",
]);
const CURRENCY = /^[A-Z]{3}$/;
const INDEX = /^(?:0|[1-9]\d{0,8})$/;
const MINOR = /^\d{1,16}$/;
const MAJOR = /^(\d{1,16})(?:\.(\d{1,3}))?$/;

type Json = null | boolean | number | string | readonly Json[] | { readonly [key: string]: Json };

/** The minor-unit exponent of a currency. */
export function currencyExponent(currency: string): number {
  if (ZERO_DECIMALS.has(currency)) return 0;
  return THREE_DECIMALS.has(currency) ? 3 : 2;
}

/**
 * Walks an RFC 6901 pointer, one token per segment and nothing that
 * backtracks. Only an object's own keys and an array's decimal indexes are
 * followed, so a pointer cannot reach a prototype.
 */
export function walkPointer(root: Json | undefined, pointer: string): Json | undefined {
  let node: Json | undefined = root;
  for (const raw of pointer.split("/").slice(1)) {
    if (node === undefined || node === null || typeof node !== "object") return undefined;
    const token = raw.replaceAll("~1", "/").replaceAll("~0", "~");
    if (Array.isArray(node)) {
      const list = node as readonly Json[];
      node = INDEX.test(token) ? list[Number(token)] : undefined;
    } else {
      const record = node as { readonly [key: string]: Json };
      node = Object.prototype.hasOwnProperty.call(record, token) ? record[token] : undefined;
    }
  }
  return node;
}

/** A scalar as text: a string, or a finite number; anything else is not one. */
function scalar(value: Json | undefined): string | undefined {
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
}

/**
 * An amount as integer minor units, exactly: a minor amount is an integer;
 * a major amount is a decimal with no more fractional digits than the
 * currency has. A negative, fractional-minor, exponent-notation or
 * over-precise amount is unreadable rather than rounded.
 */
export function minorUnits(
  value: Json | undefined,
  unit: ExposureDeclaration["amountUnit"],
  currency: string,
): number | null {
  const text = scalar(value)?.trim();
  if (text === undefined) return null;
  let minor: number;
  if (unit === "MINOR") {
    if (!MINOR.test(text)) return null;
    minor = Number(text);
  } else {
    const match = MAJOR.exec(text);
    if (match === null) return null;
    const exponent = currencyExponent(currency);
    const fraction = match[2] ?? "";
    if (fraction.length > exponent) return null;
    minor = Number(`${match[1] ?? ""}${fraction.padEnd(exponent, "0")}`);
  }
  return Number.isSafeInteger(minor) ? minor : null;
}

/** A route pattern's `:name` segments, each to the request's segment in its place. */
function pathParameters(pattern: string, path: string): Record<string, string> {
  const names = pattern.split("/").filter((segment) => segment !== "");
  const values = path.split("/").filter((segment) => segment !== "");
  const parameters: Record<string, string> = {};
  names.forEach((name, index) => {
    const value = values[index];
    if (!name.startsWith(":") || value === undefined) return;
    try {
      parameters[name.slice(1)] = decodeURIComponent(value);
    } catch {
      // An undecodable segment states nothing; the route table refused it already.
    }
  });
  return parameters;
}

function queryRoot(search: string): { [key: string]: string | string[] } {
  const query: { [key: string]: string | string[] } = {};
  for (const [key, value] of new URLSearchParams(search)) {
    if (!Object.prototype.hasOwnProperty.call(query, key)) query[key] = value;
    else {
      const current = query[key]!;
      query[key] = Array.isArray(current) ? [...current, value] : [current, value];
    }
  }
  return query;
}

function bodyRoot(request: InterceptedRequest): Json | undefined {
  if (request.body.length === 0 || !/json/i.test(request.headers["content-type"] ?? "")) {
    return undefined;
  }
  try {
    return JSON.parse(request.body.toString("utf8")) as Json;
  } catch {
    return undefined;
  }
}

/**
 * Reads what a route declares from the request it governs. The agent, when
 * the route names no pointer for it, is the gateway's own configured actor:
 * the identity the intent already names, which the caller cannot choose.
 */
export function readExposureFacts(
  declaration: ExposureDeclaration,
  request: InterceptedRequest,
  routePath: string,
  actorId: string,
): ExposureFactsResult {
  const root: { [key: string]: Json } = {
    path: pathParameters(routePath, request.path),
    query: queryRoot(request.search),
    headers: { ...request.headers },
  };
  const body = bodyRoot(request);
  if (body !== undefined) root["body"] = body;
  const currency = (
    declaration.currency.startsWith("/")
      ? (scalar(walkPointer(root, declaration.currency)) ?? "")
      : declaration.currency
  )
    .trim()
    .toUpperCase();
  if (!CURRENCY.test(currency)) return { ok: false, code: "EXPOSURE_CURRENCY_UNREADABLE" };
  const amount = minorUnits(
    walkPointer(root, declaration.amount),
    declaration.amountUnit,
    currency,
  );
  if (amount === null) return { ok: false, code: "EXPOSURE_AMOUNT_UNREADABLE" };
  const subjects: Partial<Record<ExposureRouteSubject, string>> = {};
  for (const [kind, pointer] of Object.entries(declaration.subjects) as [
    ExposureRouteSubject,
    string,
  ][]) {
    const value = scalar(walkPointer(root, pointer))?.trim();
    if (value === undefined || value === "" || value.length > MAX_SUBJECT_LENGTH) {
      return { ok: false, code: "EXPOSURE_SUBJECT_UNREADABLE" };
    }
    subjects[kind] = value;
  }
  subjects.agent ??= actorId;
  return {
    ok: true,
    facts: { actionType: declaration.actionType, amount, currency, subjects },
  };
}

/**
 * The amount a committed payment's answer says moved, when the route names
 * where: in the route's unit and the request's currency, and only when it is
 * no more than was reserved. Anything else settles the reserved amount, which
 * errs toward the cap.
 */
export function readSettledAmount(
  declaration: ExposureDeclaration,
  facts: ExposureFacts,
  answer: { readonly headers: readonly (readonly [string, string])[]; readonly body: Buffer },
): number | null {
  if (declaration.settledAmount === null || answer.body.length === 0) return null;
  const type = answer.headers.find(([name]) => name.toLowerCase() === "content-type")?.[1] ?? "";
  if (!/json/i.test(type)) return null;
  let body: Json;
  try {
    body = JSON.parse(answer.body.toString("utf8")) as Json;
  } catch {
    return null;
  }
  const amount = minorUnits(
    walkPointer({ body }, declaration.settledAmount),
    declaration.amountUnit,
    facts.currency,
  );
  return amount !== null && amount <= facts.amount ? amount : null;
}
