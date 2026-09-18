import { describe, expect, it, vi } from "vitest";
import { provisionWorkspace } from "../../src/decision/Provision.js";

const LOOPBACK = "http://127.0.0.1:1";
const ORG = "00000000-0000-4000-8000-000000000002";

function minted(overrides: Record<string, unknown> = {}, status = 201): Response {
  return new Response(
    JSON.stringify({
      org_id: ORG,
      raw_key: "synthetic-provisional-key-aaaaaaaa",
      provisional: true,
      limits: { governed_decisions_per_month: 50 },
      claim: { note: "claim it" },
      next: { evaluate: "/v1/protocol/evaluate-decision" },
      ...overrides,
    }),
    { status, headers: { "content-type": "application/json" } },
  );
}

describe("provisionWorkspace", () => {
  it("posts the client identification and the agent name, and returns the workspace", async () => {
    const fetchMock = vi.fn<typeof fetch>(() => Promise.resolve(minted()));
    const workspace = await provisionWorkspace({
      baseUrl: `${LOOPBACK}/`,
      allowInsecureLoopback: true,
      fetch: fetchMock,
      source: { repo: "decionis/agent-safe-pipeline", example: "basic-agent", surface: "github" },
      agentName: "agent-safe-pipeline basic-agent",
    });
    expect(workspace).toEqual({
      orgId: ORG,
      rawKey: "synthetic-provisional-key-aaaaaaaa",
      provisional: true,
      limits: { governed_decisions_per_month: 50 },
      claim: { note: "claim it" },
    });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${LOOPBACK}/v1/public/agents/provision`);
    expect(init.method).toBe("POST");
    expect(init.redirect).toBe("error");
    const headers = init.headers as Record<string, string>;
    expect(headers["user-agent"]).toMatch(
      /^agent-safe-pipeline\/[\w.-]+ \(repo=decionis\/agent-safe-pipeline; example=basic-agent; surface=github\)$/,
    );
    expect(headers["authorization"]).toBeUndefined();
    expect(JSON.parse(init.body as string)).toEqual({
      agent_name: "agent-safe-pipeline basic-agent",
    });
    const anonymous = vi.fn<typeof fetch>(() => Promise.resolve(minted({}, 200)));
    await provisionWorkspace({ baseUrl: LOOPBACK, allowInsecureLoopback: true, fetch: anonymous });
    expect(
      JSON.parse((anonymous.mock.calls[0] as [string, RequestInit])[1].body as string),
    ).toEqual({});
  });

  it("refuses a plain-HTTP authority off loopback", async () => {
    await expect(
      provisionWorkspace({ baseUrl: "http://authority.example", fetch: vi.fn<typeof fetch>() }),
    ).rejects.toThrow("DECIONIS_URL_MUST_USE_HTTPS");
  });

  it("names every way the mint can fail", async () => {
    const cases: [Response | Error, string, number | null][] = [
      [
        new Response("{}", { status: 429, headers: { "retry-after": "60" } }),
        "PROVISION_LIMIT_REACHED",
        429,
      ],
      [new Response("down", { status: 503 }), "PROVISION_UNAVAILABLE", 503],
      [new Response("{}", { status: 400 }), "PROVISION_REFUSED", 400],
      [new Response("not json", { status: 201 }), "PROVISION_RESPONSE_INVALID", 201],
      [minted({ raw_key: "" }), "PROVISION_RESPONSE_INVALID", 201],
      [minted({ provisional: false }), "PROVISION_RESPONSE_INVALID", 201],
      [new Error("ECONNREFUSED"), "PROVISION_UNAVAILABLE", null],
    ];
    for (const [answer, code, status] of cases) {
      const fetchMock = vi.fn<typeof fetch>(() =>
        answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer),
      );
      await expect(
        provisionWorkspace({ baseUrl: LOOPBACK, allowInsecureLoopback: true, fetch: fetchMock }),
      ).rejects.toMatchObject({ name: "ProvisionError", code, status });
    }
    const limited = new Response("{}", { status: 429, headers: { "retry-after": "soon" } });
    await expect(
      provisionWorkspace({
        baseUrl: LOOPBACK,
        allowInsecureLoopback: true,
        fetch: vi.fn<typeof fetch>(() => Promise.resolve(limited)),
      }),
    ).rejects.toMatchObject({ code: "PROVISION_LIMIT_REACHED", retryAfterSeconds: null });
  });

  it("times out on its own bound and reports it as such", async () => {
    const fetchMock = vi.fn<typeof fetch>(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        }),
    );
    await expect(
      provisionWorkspace({
        baseUrl: LOOPBACK,
        allowInsecureLoopback: true,
        fetch: fetchMock,
        timeoutMs: 5,
      }),
    ).rejects.toMatchObject({ code: "PROVISION_TIMED_OUT" });
  });

  it("refuses a body past its bound", async () => {
    const huge = new Response(
      JSON.stringify({ org_id: ORG, raw_key: "k", provisional: true, pad: "x".repeat(70_000) }),
      { status: 201 },
    );
    await expect(
      provisionWorkspace({
        baseUrl: LOOPBACK,
        allowInsecureLoopback: true,
        fetch: vi.fn<typeof fetch>(() => Promise.resolve(huge)),
      }),
    ).rejects.toMatchObject({ code: "PROVISION_RESPONSE_INVALID" });
  });
});
