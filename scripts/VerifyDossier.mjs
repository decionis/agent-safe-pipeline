/**
 * Fetches one Decision Dossier with the caller's key, then verifies its
 * Ed25519 proof bundle against the authority's public JWKS with the
 * independently published `@decionis/verify` library. The fetch needs the
 * key that minted the record; the verification needs nothing but the public
 * keys, which is why anyone holding the saved record can repeat it.
 *
 *   pnpm decionis:verify <dossier-id> [--out dossier.json]
 *
 * Reads DECIONIS_API_KEY, DECIONIS_TENANT_ID, DECIONIS_API_URL (default
 * https://api.decionis.com) and DECIONIS_ALLOW_INSECURE_LOOPBACK, exactly as
 * `createGate` does; with no key in the environment, the credential a run
 * under DECIONIS_HOSTED=1 stored (or `agentsafe login` did) is used, exactly
 * as `createHostedGate` does. The key travels in one place: the authorization
 * header of the record fetch. The JWKS is fetched without it.
 */
import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import {
  assessDossierIssuer,
  assessDossierReproducibility,
  resolveJwksUrl,
  verifyDossierProofBundle,
} from "@decionis/verify";
import { readBoundedJsonResponse } from "./BoundedJsonResponse.mjs";

export const DEFAULT_API_URL = "https://api.decionis.com";
/** A signed record with its inputs snapshot can be large; the verifier's own bound. */
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const DOSSIER_ID_PATTERN = /^[\w-]{1,200}$/;
const TIMEOUT_MS = 10_000;

export function usage() {
  return [
    "usage: pnpm decionis:verify <dossier-id> [--out <path>]",
    "",
    "  DECIONIS_API_KEY                  the key the record was minted under; else the stored one",
    "  DECIONIS_TENANT_ID                that key's organization; else the stored one",
    `  DECIONIS_API_URL                  default ${DEFAULT_API_URL}`,
    "  DECIONIS_ALLOW_INSECURE_LOOPBACK  'true' permits http://127.0.0.1 for a loopback double",
    "",
    "  --out <path>   also save the signed record, for `decionis-verify --file <path>` later",
  ].join("\n");
}

export function parseArguments(argv) {
  let dossierId;
  let out;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--out") {
      out = argv[index + 1];
      index += 1;
      if (out === undefined) throw new Error("DOSSIER_OUT_PATH_MISSING");
    } else if (argument === "--help" || argument === "-h") {
      return { help: true };
    } else if (dossierId === undefined) {
      dossierId = argument;
    } else {
      throw new Error("DOSSIER_ARGUMENT_UNEXPECTED");
    }
  }
  if (dossierId === undefined) return { help: true };
  if (!DOSSIER_ID_PATTERN.test(dossierId)) throw new Error("DOSSIER_ID_INVALID");
  return { help: false, dossierId, ...(out === undefined ? {} : { out }) };
}

/** The stored credential, through the built pipeline; null when there is none or no build. */
async function storedCredentials(env) {
  try {
    const { readStoredCredentials } = await import(
      new URL("../packages/pipeline/dist/Index.js", import.meta.url).href
    );
    return readStoredCredentials({ env });
  } catch {
    return null;
  }
}

export function authorityUrl(env) {
  const raw = (env.DECIONIS_API_URL ?? "").trim() || DEFAULT_API_URL;
  const url = new URL(raw);
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "localhost";
  if (url.username || url.password) throw new Error("DECIONIS_URL_MUST_NOT_CONTAIN_CREDENTIALS");
  if (url.search || url.hash) throw new Error("DECIONIS_URL_MUST_NOT_CONTAIN_QUERY_OR_FRAGMENT");
  const insecureAllowed = (env.DECIONIS_ALLOW_INSECURE_LOOPBACK ?? "").trim() === "true";
  if (url.protocol !== "https:" && !(insecureAllowed && loopback)) {
    throw new Error("DECIONIS_URL_MUST_USE_HTTPS");
  }
  let end = raw.length;
  while (end > 0 && raw.charCodeAt(end - 1) === 47) end -= 1;
  return raw.slice(0, end);
}

async function fetchJson(fetchImpl, url, headers) {
  const response = await fetchImpl(url, {
    method: "GET",
    headers: { accept: "application/json", ...headers },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error(`DOSSIER_REQUEST_FAILED:${response.status}`);
  }
  let body;
  try {
    body = await readBoundedJsonResponse(response, { maxBytes: MAX_RESPONSE_BYTES });
  } catch (error) {
    const tooLarge = error instanceof Error && error.message.endsWith("_TOO_LARGE");
    throw new Error(tooLarge ? "DOSSIER_RESPONSE_TOO_LARGE" : "DOSSIER_RESPONSE_INVALID");
  }
  if (body === null || typeof body !== "object") throw new Error("DOSSIER_RESPONSE_INVALID");
  return body;
}

/** The signed payload inside a `GET /v1/protocol/dossiers/{id}` response. */
export function signedPayload(body) {
  const payload = body?.dossier?.dossier_payload;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("DOSSIER_PAYLOAD_MISSING");
  }
  return payload;
}

export async function verifyDossier({
  dossierId,
  env = process.env,
  fetchImpl = globalThis.fetch,
  out = process.stdout,
  savePath,
}) {
  // A key in the environment first; else the credential a hosted run stored.
  const stored = (env.DECIONIS_API_KEY ?? "").trim() === "" ? await storedCredentials(env) : null;
  const apiKey = (env.DECIONIS_API_KEY ?? "").trim() || stored?.apiKey || "";
  const tenantId = (env.DECIONIS_TENANT_ID ?? "").trim() || stored?.tenantId || "";
  if (apiKey === "") throw new Error("DECIONIS_API_KEY_MISSING");
  if (tenantId === "") throw new Error("DECIONIS_TENANT_ID_MISSING");
  if (!DOSSIER_ID_PATTERN.test(dossierId)) throw new Error("DOSSIER_ID_INVALID");
  const apiUrl = authorityUrl(
    (env.DECIONIS_API_URL ?? "").trim() === "" && stored?.endpoint
      ? { ...env, DECIONIS_API_URL: stored.endpoint }
      : env,
  );

  const recordUrl = `${apiUrl}/v1/protocol/dossiers/${encodeURIComponent(dossierId)}?org_id=${encodeURIComponent(tenantId)}`;
  const payload = signedPayload(
    await fetchJson(fetchImpl, recordUrl, { authorization: `Bearer ${apiKey}` }),
  );
  if (savePath !== undefined) {
    await writeFile(savePath, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
  }

  // The keys are public and may live on another host: no credential goes with this request.
  const jwksUrl = resolveJwksUrl(payload, `${apiUrl}/`);
  if (jwksUrl === null) throw new Error("DOSSIER_PROOF_BUNDLE_MISSING");
  const jwks = await fetchJson(fetchImpl, jwksUrl, {});

  const result = verifyDossierProofBundle({ dossier_payload: payload, public_jwks: jwks });
  // Both assessments count only the document paths the proof bundle verified.
  const verifiedPaths = new Set(result.verified_artifact_paths ?? []);
  const issuer = assessDossierIssuer(payload, verifiedPaths);
  const reproducibility = assessDossierReproducibility(payload, verifiedPaths);

  out.write(`dossier: ${dossierId}\n`);
  out.write(`record:  ${recordUrl}\n`);
  out.write(`keys:    ${jwksUrl}\n`);
  for (const check of result.checks) {
    out.write(`  ${check.verified ? "ok  " : "FAIL"} ${check.label}: ${check.detail}\n`);
  }
  out.write(
    `issuer: ${issuer.label}${issuer.signature_covered ? "" : " (not signature-covered)"}\n`,
  );
  out.write(`reproducibility: ${reproducibility.posture}\n`);
  if (savePath !== undefined) out.write(`saved: ${savePath}\n`);
  out.write(
    `${result.verified ? "VERIFIED" : "NOT VERIFIED"}: ${result.artifacts_checked} signed artifact(s), key ${result.key_id ?? "unknown"}\n`,
  );
  return { verified: result.verified, result, issuer, reproducibility, jwksUrl, recordUrl };
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let parsed;
  try {
    parsed = parseArguments(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n${usage()}\n`);
    process.exit(2);
  }
  if (parsed.help) {
    process.stdout.write(`${usage()}\n`);
    process.exit(0);
  }
  try {
    const outcome = await verifyDossier({
      dossierId: parsed.dossierId,
      ...(parsed.out === undefined ? {} : { savePath: parsed.out }),
    });
    process.exit(outcome.verified ? 0 : 1);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(2);
  }
}
