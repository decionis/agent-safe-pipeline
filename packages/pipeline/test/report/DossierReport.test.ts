import { describe, expect, it, vi } from "vitest";
import {
  fetchSignedDossier,
  printSignedDossier,
  summarizeDossier,
} from "../../src/report/DossierReport.js";

const LOOPBACK = "http://127.0.0.1:1";
const ORG = "00000000-0000-4000-8000-000000000003";

function record(overrides: Record<string, unknown> = {}) {
  return {
    service: "decionis",
    dossier: {
      dossier_payload: {
        dossier_id: "synthetic-dossier-7",
        generated_at: "2026-09-18T00:00:00.000Z",
        routing_decision: { outcome: "ALLOW" },
        portable_artifact: { issuer_context: { tier: "provisional_anonymous" } },
        integrity: {
          proof_bundle: {
            algorithm: "Ed25519",
            key_id: "synthetic-key-1",
            issued_at: "2026-09-18T00:00:01.000Z",
            artifacts: [{}, {}, {}],
          },
        },
        ...overrides,
      },
    },
  };
}

function sink() {
  const chunks: string[] = [];
  return { chunks, out: { write: (chunk: string) => chunks.push(chunk) } };
}

describe("summarizeDossier", () => {
  it("reads the proof from the record, and tolerates what is missing", () => {
    expect(summarizeDossier(record(), 1234)).toEqual({
      dossierId: "synthetic-dossier-7",
      outcome: "ALLOW",
      generatedAt: "2026-09-18T00:00:00.000Z",
      algorithm: "Ed25519",
      keyId: "synthetic-key-1",
      issuedAt: "2026-09-18T00:00:01.000Z",
      artifacts: 3,
      issuerTier: "provisional_anonymous",
      bytes: 1234,
    });
    const bare = summarizeDossier(
      record({
        routing_decision: null,
        portable_artifact: null,
        integrity: {},
        issuer_context: { tier: "owned" },
      }),
      10,
    );
    expect(bare).toMatchObject({ outcome: null, keyId: null, artifacts: 0, issuerTier: "owned" });
    expect(summarizeDossier(null, 0)).toBeNull();
    expect(summarizeDossier({ dossier: { dossier_payload: { dossier_id: "" } } }, 0)).toBeNull();
    expect(summarizeDossier({ dossier: { dossier_payload: [] } }, 0)).toBeNull();
  });
});

describe("printSignedDossier", () => {
  it("prints the record in three lines, naming a provisional issuer as such", () => {
    const { chunks, out } = sink();
    printSignedDossier(
      summarizeDossier(record(), 1234) as NonNullable<ReturnType<typeof summarizeDossier>>,
      { out },
    );
    expect(chunks).toEqual([
      "signed dossier: synthetic-dossier-7 (1234 bytes, ALLOW)\n",
      "  Ed25519 by key synthetic-key-1 at 2026-09-18T00:00:01.000Z, 3 signed artifact(s)\n",
      "  issuer: provisional_anonymous (a workspace without an account; claim it to keep it)\n",
    ]);
    const unsigned = sink();
    printSignedDossier(
      {
        dossierId: "d",
        outcome: null,
        generatedAt: null,
        algorithm: null,
        keyId: null,
        issuedAt: null,
        artifacts: 0,
        issuerTier: null,
        bytes: 2,
      },
      { out: unsigned.out },
    );
    expect(unsigned.chunks).toEqual([
      "signed dossier: d (2 bytes)\n",
      "  unsigned record, 0 signed artifact(s)\n",
      "  issuer: not stated\n",
    ]);
    const undated = sink();
    printSignedDossier(
      {
        ...(summarizeDossier(record(), 1) as NonNullable<ReturnType<typeof summarizeDossier>>),
        issuedAt: null,
        algorithm: null,
      },
      { out: undated.out },
    );
    expect(undated.chunks[1]).toBe("  signed by key synthetic-key-1, 3 signed artifact(s)\n");
  });
});

describe("fetchSignedDossier", () => {
  const options = {
    baseUrl: LOOPBACK,
    apiKey: "synthetic-key",
    tenantId: ORG,
    dossierId: "synthetic-dossier-7",
    allowInsecureLoopback: true,
  };

  it("fetches with the key alone in the authorization header, and summarizes", async () => {
    const fetchMock = vi.fn<typeof fetch>(() =>
      Promise.resolve(new Response(JSON.stringify(record()), { status: 200 })),
    );
    const { summary, body } = await fetchSignedDossier({
      ...options,
      fetch: fetchMock,
      source: { example: "basic-agent" },
    });
    expect(summary.dossierId).toBe("synthetic-dossier-7");
    expect((body as { service: string }).service).toBe("decionis");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${LOOPBACK}/v1/protocol/dossiers/synthetic-dossier-7?org_id=${ORG}`);
    const headers = init.headers as Record<string, string>;
    expect(headers["authorization"]).toBe("Bearer synthetic-key");
    expect(headers["user-agent"]).toMatch(/example=basic-agent/);
    expect(init.redirect).toBe("error");
  });

  it("names every way the fetch can fail", async () => {
    const cases: [Response | Error, string, number | null][] = [
      [new Response("{}", { status: 404 }), "DOSSIER_NOT_FOUND", 404],
      [new Response("{}", { status: 401 }), "DOSSIER_REFUSED", 401],
      [new Response("{}", { status: 403 }), "DOSSIER_REFUSED", 403],
      [new Response("down", { status: 502 }), "DOSSIER_UNAVAILABLE", 502],
      [new Response("{}", { status: 202 }), "DOSSIER_RESPONSE_INVALID", 202],
      [new Response("not json", { status: 200 }), "DOSSIER_RESPONSE_INVALID", 200],
      [
        new Response(JSON.stringify({ dossier: {} }), { status: 200 }),
        "DOSSIER_RESPONSE_INVALID",
        200,
      ],
      [new Error("ECONNRESET"), "DOSSIER_UNAVAILABLE", null],
    ];
    for (const [answer, code, status] of cases) {
      const fetchMock = vi.fn<typeof fetch>(() =>
        answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer),
      );
      await expect(fetchSignedDossier({ ...options, fetch: fetchMock })).rejects.toMatchObject({
        name: "DossierFetchError",
        code,
        status,
      });
    }
    await expect(
      fetchSignedDossier({ ...options, dossierId: "../etc", fetch: vi.fn<typeof fetch>() }),
    ).rejects.toMatchObject({ code: "DOSSIER_RESPONSE_INVALID", status: null });
  });

  it("times out on its own bound and refuses a record past its size", async () => {
    const hanging = vi.fn<typeof fetch>(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        }),
    );
    await expect(
      fetchSignedDossier({ ...options, fetch: hanging, timeoutMs: 5 }),
    ).rejects.toMatchObject({ code: "DOSSIER_TIMED_OUT" });
    const huge = new Response(JSON.stringify(record({ pad: "x".repeat(3 * 1024 * 1024) })), {
      status: 200,
    });
    await expect(
      fetchSignedDossier({ ...options, fetch: vi.fn<typeof fetch>(() => Promise.resolve(huge)) }),
    ).rejects.toMatchObject({ code: "DOSSIER_RESPONSE_INVALID" });
  });
});
