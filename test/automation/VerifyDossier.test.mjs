import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { extractDossierPayload } from "@decionis/verify";
import {
  authorityUrl,
  parseArguments,
  signedPayload,
  verifyDossier,
} from "../../scripts/VerifyDossier.mjs";

const API_URL = "http://127.0.0.1:3001";
const ORG_ID = "11111111-1111-4111-8111-111111111111";
const ENV = {
  DECIONIS_API_KEY: "synthetic-authority-key",
  DECIONIS_TENANT_ID: ORG_ID,
  DECIONIS_API_URL: API_URL,
  DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
};

const vector = JSON.parse(
  await readFile(new URL("../../dossiers/vectors/allow.json", import.meta.url)),
);
const jwks = JSON.parse(
  await readFile(new URL("../../dossiers/corpus-jwks.json", import.meta.url)),
);
const DOSSIER_ID = vector.dossier_payload.dossier_id;

/** The `GET /v1/protocol/dossiers/{id}` body around the corpus vector's signed payload. */
function recordBody(payload = vector.dossier_payload) {
  return {
    service: "decionis",
    protocol_version: "1.1",
    dossier: {
      dossier_id: DOSSIER_ID,
      org_id: ORG_ID,
      decision_evaluation_id: "00000000-0000-4000-8000-000000000009",
      dossier_payload: payload,
      evidence_hashes: [],
      created_at: "2026-01-01T00:00:00.000Z",
      updated_at: "2026-01-01T00:00:00.000Z",
    },
  };
}

/** A loopback authority that serves the record with a key and the JWKS to anyone. */
function authority({ payload, record, jwksBody } = {}) {
  const requests = [];
  const fetchImpl = async (url, init) => {
    requests.push({ url: String(url), headers: { ...(init?.headers ?? {}) } });
    const { pathname } = new URL(String(url));
    if (pathname === `/v1/protocol/dossiers/${DOSSIER_ID}`) {
      if (init?.headers?.authorization !== `Bearer ${ENV.DECIONIS_API_KEY}`) {
        return new Response(JSON.stringify({ error: "UNAUTHORIZED" }), { status: 401 });
      }
      return record ?? new Response(JSON.stringify(recordBody(payload)), { status: 200 });
    }
    if (pathname === "/.well-known/decision-dossier-jwks.json") {
      return new Response(JSON.stringify(jwksBody ?? jwks), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  };
  return { fetchImpl, requests };
}

function sink() {
  const lines = [];
  return { lines, out: { write: (chunk) => lines.push(String(chunk)) } };
}

describe("pnpm decionis:verify", () => {
  it("fetches the record with the key, the keys without it, and verifies offline", async () => {
    const { fetchImpl, requests } = authority();
    const { lines, out } = sink();

    const outcome = await verifyDossier({ dossierId: DOSSIER_ID, env: ENV, fetchImpl, out });

    assert.equal(outcome.verified, true);
    assert.equal(outcome.result.artifacts_checked, vector.expected.artifacts_checked);
    assert.equal(outcome.result.key_id, vector.expected.key_id);
    assert.equal(outcome.reproducibility.posture, vector.expected.reproducibility);
    for (const [key, value] of Object.entries(vector.expected.issuer)) {
      assert.equal(outcome.issuer[key], value, key);
    }
    assert.equal(outcome.jwksUrl, `${API_URL}/.well-known/decision-dossier-jwks.json`);

    assert.equal(requests.length, 2);
    assert.equal(requests[0].url, `${API_URL}/v1/protocol/dossiers/${DOSSIER_ID}?org_id=${ORG_ID}`);
    assert.equal(requests[0].headers.authorization, `Bearer ${ENV.DECIONIS_API_KEY}`);
    assert.equal(requests[1].url, `${API_URL}/.well-known/decision-dossier-jwks.json`);
    assert.equal(requests[1].headers.authorization, undefined);

    const text = lines.join("");
    assert.match(text, /^dossier: synthetic-dossier-allow-001\n/);
    assert.match(
      text,
      /\nVERIFIED: 4 signed artifact\(s\), key agent-safe-synthetic-dossier-corpus-v1\n$/,
    );
    assert.match(text, /issuer: Issuer not stated/);
    assert.doesNotMatch(text, /synthetic-authority-key/);
  });

  it("reports NOT VERIFIED when a signed byte changed", async () => {
    // The portable artifact is a signed document; the verdict inside it is what a forger would change.
    const tampered = structuredClone(vector.dossier_payload);
    tampered.portable_artifact.routing_decision.outcome = "BLOCK";
    const { fetchImpl } = authority({ payload: tampered });
    const { lines, out } = sink();

    const outcome = await verifyDossier({ dossierId: DOSSIER_ID, env: ENV, fetchImpl, out });

    assert.equal(outcome.verified, false);
    assert.match(lines.join(""), /\nNOT VERIFIED: /);
    assert.match(lines.join(""), /FAIL/);
  });

  it("saves the bare signed payload, in the shape decionis-verify --file reads", async () => {
    const directory = await mkdtemp(join(tmpdir(), "agent-safe-verify-"));
    try {
      const savePath = join(directory, "dossier.json");
      const { fetchImpl } = authority();
      await verifyDossier({
        dossierId: DOSSIER_ID,
        env: ENV,
        fetchImpl,
        out: sink().out,
        savePath,
      });

      const saved = JSON.parse(await readFile(savePath, "utf8"));
      assert.deepEqual(saved, vector.dossier_payload);
      assert.equal(extractDossierPayload(saved), saved);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("refuses to run without the key or the tenant, and never sends a malformed id", async () => {
    const { fetchImpl, requests } = authority();
    const out = sink().out;
    await assert.rejects(
      verifyDossier({
        dossierId: DOSSIER_ID,
        env: { ...ENV, DECIONIS_API_KEY: " " },
        fetchImpl,
        out,
      }),
      /DECIONIS_API_KEY_MISSING/,
    );
    await assert.rejects(
      verifyDossier({
        dossierId: DOSSIER_ID,
        env: { ...ENV, DECIONIS_TENANT_ID: "" },
        fetchImpl,
        out,
      }),
      /DECIONIS_TENANT_ID_MISSING/,
    );
    await assert.rejects(
      verifyDossier({ dossierId: "../other?x=1", env: ENV, fetchImpl, out }),
      /DOSSIER_ID_INVALID/,
    );
    assert.equal(requests.length, 0);
  });

  it("fails on a refused, oversized, malformed, or payload-less record", async () => {
    const out = sink().out;
    const cases = [
      [new Response("forbidden", { status: 403 }), /DOSSIER_REQUEST_FAILED:403/],
      [new Response("{", { status: 200 }), /DOSSIER_RESPONSE_INVALID/],
      [new Response(JSON.stringify({ dossier: {} }), { status: 200 }), /DOSSIER_PAYLOAD_MISSING/],
      [
        new Response(JSON.stringify(recordBody({ dossier_id: DOSSIER_ID })), { status: 200 }),
        /DOSSIER_PROOF_BUNDLE_MISSING/,
      ],
      [
        new Response(`{"pad":"${"x".repeat(2 * 1024 * 1024)}"}`, { status: 200 }),
        /DOSSIER_RESPONSE_TOO_LARGE/,
      ],
    ];
    for (const [record, expected] of cases) {
      const { fetchImpl } = authority({ record });
      await assert.rejects(
        verifyDossier({ dossierId: DOSSIER_ID, env: ENV, fetchImpl, out }),
        expected,
      );
    }
  });

  it("parses its arguments and holds the authority URL to the client's rules", () => {
    assert.deepEqual(parseArguments([]), { help: true });
    assert.deepEqual(parseArguments(["--help"]), { help: true });
    assert.deepEqual(parseArguments([DOSSIER_ID]), { help: false, dossierId: DOSSIER_ID });
    assert.deepEqual(parseArguments([DOSSIER_ID, "--out", "d.json"]), {
      help: false,
      dossierId: DOSSIER_ID,
      out: "d.json",
    });
    assert.throws(() => parseArguments([DOSSIER_ID, "--out"]), /DOSSIER_OUT_PATH_MISSING/);
    assert.throws(() => parseArguments([DOSSIER_ID, "extra"]), /DOSSIER_ARGUMENT_UNEXPECTED/);
    assert.throws(() => parseArguments(["not a valid id"]), /DOSSIER_ID_INVALID/);

    assert.equal(authorityUrl({}), "https://api.decionis.com");
    assert.equal(authorityUrl({ DECIONIS_API_URL: "https://example.com/" }), "https://example.com");
    assert.equal(authorityUrl(ENV), API_URL);
    assert.throws(() => authorityUrl({ DECIONIS_API_URL: API_URL }), /DECIONIS_URL_MUST_USE_HTTPS/);
    assert.throws(
      () => authorityUrl({ DECIONIS_API_URL: "https://user:secret@example.com" }),
      /DECIONIS_URL_MUST_NOT_CONTAIN_CREDENTIALS/,
    );
    assert.throws(
      () => authorityUrl({ DECIONIS_API_URL: "https://example.com/?sig=1" }),
      /DECIONIS_URL_MUST_NOT_CONTAIN_QUERY_OR_FRAGMENT/,
    );
    assert.throws(
      () => signedPayload({ dossier: { dossier_payload: [] } }),
      /DOSSIER_PAYLOAD_MISSING/,
    );
  });
});
