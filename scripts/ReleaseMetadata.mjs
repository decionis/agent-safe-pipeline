import { access, readFile } from "node:fs/promises";
import { join } from "node:path";
import { parseDocument } from "yaml";

const semverPattern =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[\da-z-]+(?:\.[\da-z-]+)*)?(?:\+[\da-z-]+(?:\.[\da-z-]+)*)?$/i;
const orcidPattern = /^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$/;
const conceptDoiPattern = /^10\.5281\/zenodo\.\d+$/;
const repositoryPattern = /^[\w.-]+\/[\w.-]+$/;

function fail(code, detail) {
  throw new Error(detail === undefined ? code : `${code}: ${detail}`);
}

function object(value, code) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(code);
  return value;
}

function exactString(value, expected, code) {
  if (value !== expected) fail(code, `expected ${JSON.stringify(expected)}`);
}

function nonemptyString(value, code) {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0) fail(code);
  return value;
}

function exactKeys(value, allowed, code) {
  const unexpected = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unexpected.length > 0) fail(code, unexpected.join(", "));
}

function normalizeWhitespace(value) {
  return nonemptyString(value, "RELEASE_METADATA_STRING_INVALID").replace(/\s+/g, " ");
}

export function normalizeOrcid(value) {
  const normalized = nonemptyString(value, "RELEASE_METADATA_ORCID_INVALID").replace(
    /^https:\/\/orcid\.org\//,
    "",
  );
  if (!orcidPattern.test(normalized)) fail("RELEASE_METADATA_ORCID_INVALID", normalized);

  const digits = normalized.replaceAll("-", "");
  let total = 0;
  for (const digit of digits.slice(0, 15)) total = (total + Number(digit)) * 2;
  const remainder = (12 - (total % 11)) % 11;
  const expectedCheckDigit = remainder === 10 ? "X" : String(remainder);
  if (digits.at(-1) !== expectedCheckDigit) fail("RELEASE_METADATA_ORCID_CHECKSUM_INVALID");
  return normalized;
}

export function creatorDisplayName(creator) {
  return `${creator.family_names}, ${creator.given_names}`;
}

function validateDate(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    fail("RELEASE_METADATA_DATE_INVALID");
  }
  const parsed = new Date(`${value}T00:00:00.000Z`);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString().slice(0, 10) !== value) {
    fail("RELEASE_METADATA_DATE_INVALID");
  }
  return value;
}

function validateConfig(rawConfig) {
  const config = object(rawConfig, "RELEASE_METADATA_CONFIG_INVALID");
  exactKeys(
    config,
    ["$schema", "schema_version", "repository", "package_name", "creators", "zenodo"],
    "RELEASE_METADATA_CONFIG_PROPERTY_UNKNOWN",
  );
  exactString(
    config.$schema,
    "./zenodo-release.schema.json",
    "RELEASE_METADATA_SCHEMA_REFERENCE_INVALID",
  );
  exactString(config.schema_version, "1.0", "RELEASE_METADATA_SCHEMA_VERSION_UNSUPPORTED");
  if (!repositoryPattern.test(config.repository)) fail("RELEASE_METADATA_REPOSITORY_INVALID");
  nonemptyString(config.package_name, "RELEASE_METADATA_PACKAGE_INVALID");

  if (!Array.isArray(config.creators) || config.creators.length === 0) {
    fail("RELEASE_METADATA_CREATORS_INVALID");
  }
  const creators = config.creators.map((rawCreator) => {
    const creator = object(rawCreator, "RELEASE_METADATA_CREATOR_INVALID");
    exactKeys(
      creator,
      ["family_names", "given_names", "affiliation", "orcid"],
      "RELEASE_METADATA_CREATOR_PROPERTY_UNKNOWN",
    );
    return {
      family_names: nonemptyString(
        creator.family_names,
        "RELEASE_METADATA_CREATOR_FAMILY_NAMES_INVALID",
      ),
      given_names: nonemptyString(
        creator.given_names,
        "RELEASE_METADATA_CREATOR_GIVEN_NAMES_INVALID",
      ),
      affiliation: nonemptyString(
        creator.affiliation,
        "RELEASE_METADATA_CREATOR_AFFILIATION_INVALID",
      ),
      orcid: normalizeOrcid(creator.orcid),
    };
  });

  const zenodo = object(config.zenodo, "RELEASE_METADATA_ZENODO_INVALID");
  exactKeys(
    zenodo,
    ["concept_doi", "resource_type", "access_right"],
    "RELEASE_METADATA_ZENODO_PROPERTY_UNKNOWN",
  );
  if (!conceptDoiPattern.test(zenodo.concept_doi)) fail("RELEASE_METADATA_CONCEPT_DOI_INVALID");
  exactString(zenodo.resource_type, "software", "RELEASE_METADATA_RESOURCE_TYPE_INVALID");
  exactString(zenodo.access_right, "open", "RELEASE_METADATA_ACCESS_RIGHT_INVALID");

  return { ...config, creators, zenodo: { ...zenodo } };
}

function validateCff(rawCff, config, version) {
  const cff = object(rawCff, "RELEASE_METADATA_CFF_INVALID");
  exactString(cff["cff-version"], "1.2.0", "RELEASE_METADATA_CFF_VERSION_UNSUPPORTED");
  exactString(cff.type, config.zenodo.resource_type, "RELEASE_METADATA_CFF_TYPE_MISMATCH");
  exactString(cff.version, version, "RELEASE_METADATA_CFF_RELEASE_VERSION_MISMATCH");
  const publicationDate = validateDate(cff["date-released"]);
  const repositoryUrl = `https://github.com/${config.repository}`;
  exactString(cff["repository-code"], repositoryUrl, "RELEASE_METADATA_CFF_REPOSITORY_MISMATCH");
  exactString(cff.url, repositoryUrl, "RELEASE_METADATA_CFF_URL_MISMATCH");

  if (!Array.isArray(cff.authors) || cff.authors.length !== config.creators.length) {
    fail("RELEASE_METADATA_CFF_CREATORS_MISMATCH");
  }
  cff.authors.forEach((rawAuthor, index) => {
    const author = object(rawAuthor, "RELEASE_METADATA_CFF_CREATOR_INVALID");
    const creator = config.creators[index];
    exactString(
      author["family-names"],
      creator.family_names,
      "RELEASE_METADATA_CFF_FAMILY_NAMES_MISMATCH",
    );
    exactString(
      author["given-names"],
      creator.given_names,
      "RELEASE_METADATA_CFF_GIVEN_NAMES_MISMATCH",
    );
    exactString(
      author.affiliation,
      creator.affiliation,
      "RELEASE_METADATA_CFF_AFFILIATION_MISMATCH",
    );
    exactString(normalizeOrcid(author.orcid), creator.orcid, "RELEASE_METADATA_CFF_ORCID_MISMATCH");
  });

  if (!Array.isArray(cff.keywords) || cff.keywords.length === 0) {
    fail("RELEASE_METADATA_CFF_KEYWORDS_INVALID");
  }
  const keywords = cff.keywords.map((keyword) =>
    nonemptyString(keyword, "RELEASE_METADATA_CFF_KEYWORD_INVALID"),
  );

  return {
    abstract: normalizeWhitespace(cff.abstract),
    keywords,
    message: normalizeWhitespace(cff.message),
    publicationDate,
    title: normalizeWhitespace(cff.title),
  };
}

async function parseCff(path) {
  const document = parseDocument(await readFile(path, "utf8"), {
    prettyErrors: false,
    strict: true,
    uniqueKeys: true,
  });
  if (document.errors.length > 0) {
    fail("RELEASE_METADATA_CFF_PARSE_INVALID", document.errors[0].message);
  }
  return document.toJS({ maxAliasCount: 20 });
}

async function assertZenodoJsonAbsent(root) {
  try {
    await access(join(root, ".zenodo.json"));
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  fail("RELEASE_METADATA_CFF_SHADOWED_BY_ZENODO_JSON");
}

export async function loadReleaseMetadata({ root = process.cwd() } = {}) {
  await assertZenodoJsonAbsent(root);
  const [rawConfig, workspaceManifest, packageManifest, rawCff] = await Promise.all([
    readFile(join(root, "metadata/zenodo-release.json"), "utf8").then(JSON.parse),
    readFile(join(root, "package.json"), "utf8").then(JSON.parse),
    readFile(join(root, "packages/pipeline/package.json"), "utf8").then(JSON.parse),
    parseCff(join(root, "CITATION.cff")),
  ]);
  const config = validateConfig(rawConfig);
  exactString(
    workspaceManifest.version,
    packageManifest.version,
    "RELEASE_METADATA_PACKAGE_VERSION_MISMATCH",
  );
  const version = nonemptyString(packageManifest.version, "RELEASE_METADATA_VERSION_INVALID");
  if (!semverPattern.test(version)) fail("RELEASE_METADATA_VERSION_INVALID");
  exactString(packageManifest.name, config.package_name, "RELEASE_METADATA_PACKAGE_NAME_MISMATCH");
  const citation = validateCff(rawCff, config, version);

  return {
    accessRight: config.zenodo.access_right,
    citation,
    conceptDoi: config.zenodo.concept_doi,
    creators: config.creators,
    packageName: config.package_name,
    repository: config.repository,
    resourceType: config.zenodo.resource_type,
    version,
  };
}
