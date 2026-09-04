import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { readBoundedJsonResponse } from "./BoundedJsonResponse.mjs";
import { creatorDisplayName, loadReleaseMetadata, normalizeOrcid } from "./ReleaseMetadata.mjs";

const zenodoRecordsUrl = "https://zenodo.org/api/records";
const doiResolverUrl = "https://doi.org";
const versionDoiPattern = /^10\.5281\/zenodo\.\d+$/;

class PermanentVerificationError extends Error {}

function permanent(code, detail) {
  throw new PermanentVerificationError(detail === undefined ? code : `${code}: ${detail}`);
}

function object(value, code) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) permanent(code);
  return value;
}

function exact(value, expected, code) {
  if (value !== expected) permanent(code, `expected ${JSON.stringify(expected)}`);
}

function normalizeWhitespace(value, code) {
  if (typeof value !== "string" || value.length === 0) permanent(code);
  return value.replace(/\s+/g, " ").trim();
}

function validDate(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString().slice(0, 10) === value;
}

function stableDigest(value) {
  return `sha256:${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

export function zenodoSearchUrl(conceptDoi, version) {
  const url = new URL(zenodoRecordsUrl);
  url.searchParams.set(
    "q",
    `conceptdoi:${JSON.stringify(conceptDoi)} AND metadata.version:${JSON.stringify(`v${version}`)}`,
  );
  url.searchParams.set("size", "2");
  return url.href;
}

export function validateZenodoRecord(recordValue, release) {
  const record = object(recordValue, "ZENODO_RECORD_INVALID");
  const metadata = object(record.metadata, "ZENODO_RECORD_METADATA_INVALID");
  if (!Number.isSafeInteger(record.id) || record.id < 1) permanent("ZENODO_RECORD_ID_INVALID");
  exact(record.conceptdoi, release.conceptDoi, "ZENODO_CONCEPT_DOI_MISMATCH");
  if (!versionDoiPattern.test(record.doi) || record.doi === release.conceptDoi) {
    permanent("ZENODO_VERSION_DOI_INVALID");
  }
  exact(metadata.doi, record.doi, "ZENODO_VERSION_DOI_MISMATCH");
  exact(metadata.version, `v${release.version}`, "ZENODO_VERSION_MISMATCH");
  exact(
    normalizeWhitespace(metadata.title, "ZENODO_TITLE_INVALID"),
    release.citation.title,
    "ZENODO_TITLE_MISMATCH",
  );
  exact(
    normalizeWhitespace(metadata.description, "ZENODO_DESCRIPTION_INVALID"),
    release.citation.abstract,
    "ZENODO_DESCRIPTION_MISMATCH",
  );
  exact(
    normalizeWhitespace(metadata.notes, "ZENODO_NOTES_INVALID"),
    release.citation.message,
    "ZENODO_NOTES_MISMATCH",
  );
  if (!validDate(metadata.publication_date)) permanent("ZENODO_PUBLICATION_DATE_INVALID");
  exact(
    metadata.publication_date,
    release.citation.publicationDate,
    "ZENODO_PUBLICATION_DATE_MISMATCH",
  );
  exact(metadata.access_right, release.accessRight, "ZENODO_ACCESS_RIGHT_MISMATCH");
  exact(metadata.resource_type?.type, release.resourceType, "ZENODO_RESOURCE_TYPE_MISMATCH");
  exact(
    metadata.custom?.["code:codeRepository"],
    `https://github.com/${release.repository}`,
    "ZENODO_REPOSITORY_MISMATCH",
  );

  if (!Array.isArray(metadata.creators) || metadata.creators.length !== release.creators.length) {
    permanent("ZENODO_CREATORS_MISMATCH");
  }
  metadata.creators.forEach((rawCreator, index) => {
    const creator = object(rawCreator, "ZENODO_CREATOR_INVALID");
    const expected = release.creators[index];
    exact(creator.name, creatorDisplayName(expected), "ZENODO_CREATOR_NAME_MISMATCH");
    exact(creator.affiliation, expected.affiliation, "ZENODO_CREATOR_AFFILIATION_MISMATCH");
    let orcid;
    try {
      orcid = normalizeOrcid(creator.orcid);
    } catch {
      permanent("ZENODO_CREATOR_ORCID_INVALID");
    }
    exact(orcid, expected.orcid, "ZENODO_CREATOR_ORCID_MISMATCH");
  });

  if (
    !Array.isArray(metadata.keywords) ||
    JSON.stringify(metadata.keywords) !== JSON.stringify(release.citation.keywords)
  ) {
    permanent("ZENODO_KEYWORDS_MISMATCH");
  }
  const expectedReleaseUrl = `https://github.com/${release.repository}/tree/v${release.version}`;
  if (
    !Array.isArray(metadata.related_identifiers) ||
    !metadata.related_identifiers.some(
      (identifier) =>
        identifier?.identifier === expectedReleaseUrl &&
        identifier?.relation === "isSupplementTo" &&
        identifier?.resource_type === release.resourceType,
    )
  ) {
    permanent("ZENODO_RELEASE_REFERENCE_MISSING");
  }

  return {
    concept_doi: record.conceptdoi,
    creators: release.creators.map((creator) => ({
      affiliation: creator.affiliation,
      name: creatorDisplayName(creator),
      orcid: creator.orcid,
    })),
    publication_date: metadata.publication_date,
    record_id: String(record.id),
    release_url: expectedReleaseUrl,
    title: release.citation.title,
    version: release.version,
    version_doi: record.doi,
  };
}

async function readZenodoSearch(response) {
  if (!response.ok) {
    const error = new Error(`ZENODO_API_HTTP_ERROR: ${response.status}`);
    error.retryable = response.status === 429 || response.status >= 500;
    throw error;
  }
  try {
    return await readBoundedJsonResponse(response, { maxBytes: 512 * 1024 });
  } catch (error) {
    throw new Error(`ZENODO_API_RESPONSE_INVALID: ${error.message}`);
  }
}

async function assertDoiResolves(doi, fetchImpl, requestTimeoutMs) {
  const response = await fetchImpl(`${doiResolverUrl}/${doi}`, {
    headers: { accept: "text/html" },
    method: "HEAD",
    redirect: "manual",
    signal: globalThis.AbortSignal.timeout(requestTimeoutMs),
  });
  const location = response.headers?.get?.("location");
  if (response.status < 300 || response.status >= 400 || location === null) {
    throw new Error(`DOI_NOT_RESOLVABLE: ${doi}`);
  }
  let destination;
  try {
    destination = new URL(location);
  } catch {
    throw new Error(`DOI_REDIRECT_INVALID: ${doi}`);
  }
  if (destination.protocol !== "https:" || destination.hostname !== "zenodo.org") {
    permanent("DOI_REDIRECT_UNEXPECTED", doi);
  }
}

export async function verifyZenodoRelease({
  attempts = 20,
  delayMs = 10_000,
  fetchImpl = globalThis.fetch,
  requestTimeoutMs = 5_000,
  root = process.cwd(),
  sleep = (milliseconds) => new Promise((resolveSleep) => setTimeout(resolveSleep, milliseconds)),
  version,
} = {}) {
  if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > 60) {
    throw new Error("ZENODO_ATTEMPTS_INVALID");
  }
  if (!Number.isSafeInteger(delayMs) || delayMs < 0 || delayMs > 60_000) {
    throw new Error("ZENODO_DELAY_INVALID");
  }
  if (typeof fetchImpl !== "function") throw new Error("ZENODO_FETCH_INVALID");
  if (
    !Number.isSafeInteger(requestTimeoutMs) ||
    requestTimeoutMs < 1 ||
    requestTimeoutMs > 60_000
  ) {
    throw new Error("ZENODO_REQUEST_TIMEOUT_INVALID");
  }

  const release = await loadReleaseMetadata({ root });
  exact(version, release.version, "ZENODO_REQUESTED_VERSION_MISMATCH");
  const searchUrl = zenodoSearchUrl(release.conceptDoi, release.version);
  let lastError;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const search = object(
        await readZenodoSearch(
          await fetchImpl(searchUrl, {
            headers: { accept: "application/json" },
            signal: globalThis.AbortSignal.timeout(requestTimeoutMs),
          }),
        ),
        "ZENODO_SEARCH_INVALID",
      );
      const hits = search.hits?.hits;
      if (!Array.isArray(hits)) permanent("ZENODO_SEARCH_HITS_INVALID");
      if (hits.length > 1) permanent("ZENODO_RELEASE_AMBIGUOUS");
      if (hits.length === 0) throw new Error("ZENODO_RELEASE_NOT_INDEXED");

      const evidence = validateZenodoRecord(hits[0], release);
      await Promise.all([
        assertDoiResolves(evidence.version_doi, fetchImpl, requestTimeoutMs),
        assertDoiResolves(evidence.concept_doi, fetchImpl, requestTimeoutMs),
      ]);
      return {
        ...evidence,
        metadata_digest: stableDigest(evidence),
        schema_version: "1.0",
        verified_at: new Date().toISOString(),
      };
    } catch (error) {
      if (error instanceof PermanentVerificationError || error?.retryable === false) throw error;
      lastError = error;
      if (attempt < attempts) await sleep(delayMs);
    }
  }
  throw new Error(`ZENODO_VERIFICATION_TIMEOUT: ${lastError?.message ?? "unknown error"}`);
}

function parsePositiveInteger(value, name, { allowZero = false } = {}) {
  if (!/^\d+$/.test(value ?? "")) throw new Error(`${name}_INVALID`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < (allowZero ? 0 : 1)) {
    throw new Error(`${name}_INVALID`);
  }
  return parsed;
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (value === undefined) throw new Error("ZENODO_ARGUMENT_VALUE_MISSING");
    if (name === "--version") options.version = value;
    else if (name === "--attempts")
      options.attempts = parsePositiveInteger(value, "ZENODO_ATTEMPTS");
    else if (name === "--delay-ms") {
      options.delayMs = parsePositiveInteger(value, "ZENODO_DELAY", { allowZero: true });
    } else if (name === "--request-timeout-ms") {
      options.requestTimeoutMs = parsePositiveInteger(value, "ZENODO_REQUEST_TIMEOUT");
    } else if (name === "--output") options.output = value;
    else throw new Error(`ZENODO_ARGUMENT_UNKNOWN: ${name}`);
  }
  if (options.version === undefined) throw new Error("ZENODO_VERSION_REQUIRED");
  return options;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { output, ...options } = parseArguments(process.argv.slice(2));
  const evidence = await verifyZenodoRelease(options);
  const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
  if (output === undefined) process.stdout.write(serialized);
  else await writeFile(resolve(output), serialized, { encoding: "utf8", flag: "wx" });
}
