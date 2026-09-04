import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { loadReleaseMetadata } from "../../scripts/ReleaseMetadata.mjs";
import {
  validateZenodoRecord,
  verifyZenodoRelease,
  zenodoSearchUrl,
} from "../../scripts/VerifyZenodoRelease.mjs";

const creator = {
  affiliation: "Decionis, Inc.",
  family_names: "Jejelowo",
  given_names: "Festus B.",
  orcid: "0009-0006-4895-6046",
};

function config(overrides = {}) {
  return {
    $schema: "./zenodo-release.schema.json",
    schema_version: "1.0",
    repository: "decionis/agent-safe-pipeline",
    package_name: "@decionis/agent-safe-pipeline",
    creators: [creator],
    zenodo: {
      access_right: "open",
      concept_doi: "10.5281/zenodo.22312955",
      resource_type: "software",
    },
    ...overrides,
  };
}

function citation({
  affiliation = creator.affiliation,
  familyNames = creator.family_names,
  givenNames = creator.given_names,
  orcid = creator.orcid,
  version = "0.1.3",
} = {}) {
  return `cff-version: 1.2.0
message: Cite the archived release.
title: Agent-Safe Pipeline Test Release
type: software
authors:
  - family-names: ${familyNames}
    given-names: ${givenNames}
    affiliation: ${affiliation}
    orcid: https://orcid.org/${orcid}
version: ${version}
date-released: 2026-09-05
license: Apache-2.0
repository-code: https://github.com/decionis/agent-safe-pipeline
url: https://github.com/decionis/agent-safe-pipeline
abstract: A test release.
keywords:
  - execution authority
`;
}

let fixtureRoot;

async function writeFixture({
  citationText = citation(),
  configValue = config(),
  packageVersion = "0.1.3",
  workspaceVersion = "0.1.3",
  zenodoJson = false,
} = {}) {
  const root = await mkdtemp(join(fixtureRoot, "release-"));
  await Promise.all([
    mkdir(join(root, "metadata")),
    mkdir(join(root, "packages/pipeline"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(join(root, "CITATION.cff"), citationText),
    writeFile(join(root, "metadata/zenodo-release.json"), JSON.stringify(configValue)),
    writeFile(join(root, "package.json"), JSON.stringify({ version: workspaceVersion })),
    writeFile(
      join(root, "packages/pipeline/package.json"),
      JSON.stringify({ name: "@decionis/agent-safe-pipeline", version: packageVersion }),
    ),
  ]);
  if (zenodoJson) await writeFile(join(root, ".zenodo.json"), "{}");
  return root;
}

function zenodoRecord(release, overrides = {}) {
  return {
    id: 22312956,
    conceptdoi: release.conceptDoi,
    doi: "10.5281/zenodo.22312956",
    metadata: {
      access_right: release.accessRight,
      creators: release.creators.map((item) => ({
        affiliation: item.affiliation,
        name: `${item.family_names}, ${item.given_names}`,
        orcid: item.orcid,
      })),
      custom: {
        "code:codeRepository": `https://github.com/${release.repository}`,
      },
      description: release.citation.abstract,
      doi: "10.5281/zenodo.22312956",
      keywords: release.citation.keywords,
      notes: release.citation.message,
      publication_date: release.citation.publicationDate,
      related_identifiers: [
        {
          identifier: `https://github.com/${release.repository}/tree/v${release.version}`,
          relation: "isSupplementTo",
          resource_type: release.resourceType,
        },
      ],
      resource_type: { type: release.resourceType },
      title: release.citation.title,
      version: `v${release.version}`,
      ...overrides,
    },
  };
}

before(async () => {
  fixtureRoot = await mkdtemp(join(tmpdir(), "agent-safe-release-metadata-"));
});

after(async () => {
  await rm(fixtureRoot, { recursive: true, force: true });
});

describe("release metadata preflight", () => {
  it("accepts aligned package, citation, and stable creator metadata", async () => {
    const release = await loadReleaseMetadata({ root: await writeFixture() });

    assert.equal(release.version, "0.1.3");
    assert.equal(release.conceptDoi, "10.5281/zenodo.22312955");
    assert.deepEqual(release.creators, [creator]);
  });

  it("rejects a creator name entered in the wrong family/given fields", async () => {
    const root = await writeFixture({
      citationText: citation({ familyNames: "Festus", givenNames: "Jejelowo" }),
    });

    await assert.rejects(
      loadReleaseMetadata({ root }),
      /RELEASE_METADATA_CFF_FAMILY_NAMES_MISMATCH/,
    );
  });

  it("rejects invalid ORCID checksums and affiliation drift", async () => {
    const invalidOrcidRoot = await writeFixture({
      configValue: config({ creators: [{ ...creator, orcid: "0009-0006-4895-6047" }] }),
    });
    const affiliationRoot = await writeFixture({
      citationText: citation({ affiliation: "Decionis Inc." }),
    });

    await assert.rejects(
      loadReleaseMetadata({ root: invalidOrcidRoot }),
      /RELEASE_METADATA_ORCID_CHECKSUM_INVALID/,
    );
    await assert.rejects(
      loadReleaseMetadata({ root: affiliationRoot }),
      /RELEASE_METADATA_CFF_AFFILIATION_MISMATCH/,
    );
  });

  it("rejects package/CFF version drift and competing Zenodo metadata", async () => {
    const versionRoot = await writeFixture({ packageVersion: "0.1.4" });
    const shadowedRoot = await writeFixture({ zenodoJson: true });

    await assert.rejects(
      loadReleaseMetadata({ root: versionRoot }),
      /RELEASE_METADATA_PACKAGE_VERSION_MISMATCH/,
    );
    await assert.rejects(
      loadReleaseMetadata({ root: shadowedRoot }),
      /RELEASE_METADATA_CFF_SHADOWED_BY_ZENODO_JSON/,
    );
  });
});

describe("Zenodo release verification", () => {
  it("queries an exact concept DOI and release version", () => {
    const url = new globalThis.URL(zenodoSearchUrl("10.5281/zenodo.22312955", "0.1.3"));

    assert.equal(url.origin + url.pathname, "https://zenodo.org/api/records");
    assert.equal(
      url.searchParams.get("q"),
      'conceptdoi:"10.5281/zenodo.22312955" AND metadata.version:"v0.1.3"',
    );
    assert.equal(url.searchParams.get("size"), "2");
  });

  it("waits for indexing, validates both DOIs, and emits record-dated evidence", async () => {
    const root = await writeFixture();
    const release = await loadReleaseMetadata({ root });
    const sleeps = [];
    let searches = 0;
    const fetchImpl = async (url) => {
      if (String(url).startsWith("https://zenodo.org/api/records")) {
        searches += 1;
        const hits = searches === 1 ? [] : [zenodoRecord(release)];
        return new globalThis.Response(JSON.stringify({ hits: { hits } }));
      }
      return new globalThis.Response(null, {
        headers: { location: `https://zenodo.org/doi/${String(url).split("/").at(-1)}` },
        status: 302,
      });
    };

    const evidence = await verifyZenodoRelease({
      attempts: 3,
      delayMs: 0,
      fetchImpl,
      root,
      sleep: async (delay) => sleeps.push(delay),
      version: "0.1.3",
    });

    assert.equal(searches, 2);
    assert.deepEqual(sleeps, [0]);
    assert.equal(evidence.publication_date, "2026-09-05");
    assert.equal(evidence.version_doi, "10.5281/zenodo.22312956");
    assert.match(evidence.metadata_digest, /^sha256:[0-9a-f]{64}$/);
  });

  it("rejects a public record with missing creator provenance", async () => {
    const root = await writeFixture();
    const release = await loadReleaseMetadata({ root });
    const record = zenodoRecord(release, {
      creators: [{ affiliation: creator.affiliation, name: "Jejelowo, Festus B." }],
    });

    assert.throws(() => validateZenodoRecord(record, release), /ZENODO_CREATOR_ORCID_INVALID/);
  });

  it("fails after a bounded indexing window", async () => {
    const root = await writeFixture();
    let searches = 0;
    let sleeps = 0;

    await assert.rejects(
      verifyZenodoRelease({
        attempts: 3,
        delayMs: 0,
        fetchImpl: async () => {
          searches += 1;
          return new globalThis.Response(JSON.stringify({ hits: { hits: [] } }));
        },
        root,
        sleep: async () => {
          sleeps += 1;
        },
        version: "0.1.3",
      }),
      /ZENODO_VERIFICATION_TIMEOUT: ZENODO_RELEASE_NOT_INDEXED/,
    );
    assert.equal(searches, 3);
    assert.equal(sleeps, 2);
  });
});
