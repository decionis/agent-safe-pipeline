import { describe, expect, it, vi } from "vitest";

import {
  CommerceGateClient,
  CommerceGateRequestMapping,
  type FetchLike,
} from "../src/CommerceGateClient.js";
import { CommerceGateConfiguration } from "../src/Configuration.js";

const ORG_ID = "11111111-1111-4111-8111-111111111111";

function configured(): CommerceGateConfiguration {
  return new CommerceGateConfiguration({
    DECIONIS_API_KEY: "top-secret-key",
    DECIONIS_ORG_ID: ORG_ID,
    DECIONIS_API_BASE: "https://api.example.test",
  });
}

function jsonFetch(body: unknown, status = 200) {
  return vi.fn(
    async () =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      }),
  ) as unknown as FetchLike;
}

describe("CommerceGateClient", () => {
  it("maps order acceptance to a tenant-bound, idempotent SHADOW evaluation", async () => {
    const fetchImpl = jsonFetch({ outcome: "REVIEW", dossier_id: "dossier", mode: "SHADOW" });
    const client = new CommerceGateClient(configured(), fetchImpl);

    await client.evaluateAction({
      policy_version: "commerce-7",
      action: {
        action_type: "ORDER_ACCEPTANCE",
        actor: { type: "AGENT", id: "order-agent" },
        platform: "shopify",
        idempotency_key: "order:42:accept",
        payload: {
          order_id: "42",
          gross_amount: 100,
          discount_amount: 10,
          estimated_cost: 60,
          currency: "USD",
        },
      },
    });

    expect(fetchImpl).toHaveBeenCalledOnce();
    const [url, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(String(url)).toBe("https://api.example.test/v1/protocol/evaluate-decision");
    const headers = new Headers(init?.headers);
    expect(headers.get("authorization")).toBe("Bearer top-secret-key");
    expect(headers.get("idempotency-key")).toBe("order:42:accept");
    expect(headers.get("user-agent")).toBe("decionis-commercegate-mcp/0.1.1");
    expect(init?.redirect).toBe("error");
    const body = JSON.parse(String(init?.body));
    expect(body).toMatchObject({
      org_id: ORG_ID,
      decision_type: "ORDER_ACCEPTANCE",
      transaction_type: "order_acceptance",
      workflow_key: "commerce_order_acceptance",
      amount: 100,
      source: "commercegate-mcp",
      channel: "mcp",
      mode: "SHADOW",
      policy_version: "commerce-7",
      require_exact_policy_version: true,
      idempotency_key: "order:42:accept",
      context: {
        action_type: "ORDER_ACCEPTANCE",
        net_revenue: 90,
        net_margin_amount: 30,
        net_margin_fraction: 0.333333,
      },
    });
  });

  it("maps a price change and computes the post-change margin signal", async () => {
    const fetchImpl = jsonFetch({ outcome: "APPROVE", mode: "SHADOW" });
    const client = new CommerceGateClient(configured(), fetchImpl);

    await client.evaluateAction({
      action: {
        action_type: "PRICE_CHANGE",
        actor: { type: "REPRICER", id: "repricer-1" },
        platform: "walmart-marketplace",
        idempotency_key: "sku:1:price:19",
        payload: {
          sku: "SKU-1",
          from_price: 25,
          to_price: 20,
          estimated_cost: 12,
          currency: "USD",
        },
      },
    });

    const [, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(String(init?.body));
    expect(body).toMatchObject({
      org_id: ORG_ID,
      decision_type: "PRICE_CHANGE",
      amount: 20,
      mode: "SHADOW",
      context: {
        sku: "SKU-1",
        price_change_amount: -5,
        net_revenue: 20,
        estimated_cost: 12,
        net_margin_amount: 8,
        net_margin_fraction: 0.4,
      },
    });
  });

  it("builds tenant-scoped evidence and shadow-report URLs", async () => {
    const fetchImpl = jsonFetch({ ok: true });
    const client = new CommerceGateClient(configured(), fetchImpl);
    const dossierId = "22222222-2222-4222-8222-222222222222";

    await client.getDossier(dossierId);
    await client.getProofPacket(dossierId);
    await client.listShadowReports({ days: 30, limit: 25 });
    await client.summarizeShadowReports({ limit: 10 });

    const urls = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls.map(([url]) => String(url));
    expect(urls[0]).toBe(
      `https://api.example.test/v1/protocol/dossiers/${dossierId}?org_id=${ORG_ID}`,
    );
    expect(urls[1]).toBe(
      `https://api.example.test/v1/protocol/dossiers/${dossierId}/proof-packet?org_id=${ORG_ID}`,
    );
    expect(urls[2]).toContain("/v1/protocol/shadow-reports?");
    expect(urls[2]).toContain("days=30");
    expect(urls[2]).toContain("limit=25");
    expect(urls[2]).not.toContain("mode=");
    expect(urls[3]).toContain("/v1/protocol/shadow-reports?");
  });

  it("does not call the network when tenant credentials are absent", async () => {
    const fetchImpl = jsonFetch({ ok: true });
    const client = new CommerceGateClient(new CommerceGateConfiguration({}), fetchImpl);

    await expect(client.listShadowReports({})).rejects.toMatchObject({
      code: "CONFIGURATION_REQUIRED",
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("fails closed if the API does not confirm SHADOW mode", async () => {
    const fetchImpl = jsonFetch({ outcome: "APPROVE", mode: "ENFORCEMENT" });
    const client = new CommerceGateClient(configured(), fetchImpl);

    await expect(
      client.evaluateAction({
        action: {
          action_type: "PRICE_CHANGE",
          actor: { type: "REPRICER", id: "repricer-1" },
          platform: "shopify",
          idempotency_key: "sku:1:price:20",
          payload: {
            sku: "SKU-1",
            from_price: 19,
            to_price: 20,
            estimated_cost: 10,
            currency: "USD",
          },
        },
      }),
    ).rejects.toMatchObject({ code: "INVALID_UPSTREAM_RESPONSE" });
  });

  it("redacts upstream error bodies and credentials", async () => {
    const fetchImpl = jsonFetch({ error: "top-secret-key", debug: ORG_ID }, 401);
    const client = new CommerceGateClient(configured(), fetchImpl);

    let thrown: unknown;
    try {
      await client.getDossier("22222222-2222-4222-8222-222222222222");
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({ code: "AUTHENTICATION_FAILED", options: { status: 401 } });
    expect(JSON.stringify(thrown)).not.toContain("top-secret-key");
    expect(JSON.stringify(thrown)).not.toContain(ORG_ID);
  });

  it("fails closed on invalid JSON from an otherwise successful upstream", async () => {
    const fetchImpl = vi.fn(
      async () => new Response("not-json", { status: 200 }),
    ) as unknown as FetchLike;
    const client = new CommerceGateClient(configured(), fetchImpl);

    await expect(client.listShadowReports({})).rejects.toMatchObject({
      code: "INVALID_UPSTREAM_RESPONSE",
    });
  });

  it("aborts and cancels a chunked response as soon as it exceeds 2 MiB", async () => {
    let responseCancelled = false;
    const observed: { requestSignal: AbortSignal | null } = { requestSignal: null };
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(2 * 1024 * 1024));
        controller.enqueue(new Uint8Array([1]));
      },
      cancel() {
        responseCancelled = true;
      },
    });
    const response = new Response(body, {
      status: 200,
      headers: { "content-type": "application/json" },
    });
    const fetchImpl = vi.fn(async (_input: string | URL, init?: RequestInit) => {
      observed.requestSignal = init?.signal ?? null;
      return response;
    }) as unknown as FetchLike;
    const client = new CommerceGateClient(configured(), fetchImpl);

    expect(response.headers.get("content-length")).toBeNull();
    await expect(client.listShadowReports({})).rejects.toMatchObject({
      code: "INVALID_UPSTREAM_RESPONSE",
    });
    expect(observed.requestSignal?.aborted).toBe(true);
    expect(responseCancelled).toBe(true);
  });

  it("fails closed when the upstream cannot be reached", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("network contained top-secret-key");
    }) as unknown as FetchLike;
    const client = new CommerceGateClient(configured(), fetchImpl);

    await expect(client.listShadowReports({})).rejects.toMatchObject({
      code: "UPSTREAM_UNREACHABLE",
      options: { retryable: true },
    });
  });
});

describe("CommerceGate request mapping", () => {
  it("reports a null fraction when revenue is zero", () => {
    expect(CommerceGateRequestMapping.marginSignal(0, 2)).toEqual({
      net_revenue: 0,
      estimated_cost: 2,
      net_margin_amount: -2,
      net_margin_fraction: null,
    });
  });
});
