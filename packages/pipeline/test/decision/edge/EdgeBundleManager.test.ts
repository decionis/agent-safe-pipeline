import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  EdgeBundleManager,
  type EdgeBundleEvent,
} from "../../../src/decision/edge/EdgeBundleManager.js";
import {
  FileBundleSource,
  UrlBundleSource,
  signedBundleOf,
  type BundleRead,
  type EdgeBundleSource,
} from "../../../src/decision/edge/EdgeBundleSource.js";
import { EdgeModule } from "../../../src/decision/edge/EdgeModule.js";
import {
  doubleClaims,
  edgeModuleDouble,
  signedBundle,
  type DoubleBehaviour,
} from "../../support/EdgeModuleDouble.js";

const START = Date.parse("2026-10-02T00:00:00.000Z");
const API_KEY = "dk_live_synthetic_secret_value_1234567890";

class ScriptedSource implements EdgeBundleSource {
  public readonly kind: "url" | "file";
  public reads = 0;
  public constructor(
    public answers: BundleRead[],
    kind: "url" | "file" = "url",
  ) {
    this.kind = kind;
  }
  public async read(): Promise<BundleRead> {
    this.reads += 1;
    const answer = this.answers.length > 1 ? this.answers.shift() : this.answers[0];
    return answer ?? { ok: false, code: "BUNDLE_FETCH_FAILED" };
  }
}

const bundle = (overrides = {}): BundleRead => ({
  ok: true,
  signedBundle: signedBundle(doubleClaims(overrides)),
});

function manager(
  source: EdgeBundleSource,
  options: { behaviour?: DoubleBehaviour; now?: () => number; refreshSeconds?: number } = {},
) {
  const double = edgeModuleDouble(options.behaviour);
  const module = EdgeModule.fromExports(double.exports);
  const events: EdgeBundleEvent[] = [];
  const bundles = new EdgeBundleManager({
    module,
    source,
    orgId: "org-1",
    clock: options.now ?? (() => Date.now()),
    onEvent: (event) => events.push(event),
    ...(options.refreshSeconds === undefined ? {} : { refreshSeconds: options.refreshSeconds }),
  });
  return { double, module, events, bundles };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("EdgeBundleManager", () => {
  it("loads a verified bundle and reports it", async () => {
    const { bundles, events, double } = manager(new ScriptedSource([bundle()]), {
      now: () => START,
    });
    expect(bundles.current(START)).toBeNull();
    expect(await bundles.refresh()).toBeNull();
    expect(double.loadInputs[0]).toEqual({
      signed_bundle: signedBundle(doubleClaims()),
      org_id: "org-1",
      now: "2026-10-02T00:00:00.000Z",
    });
    expect(bundles.current(START)).toMatchObject({
      handle: 1,
      bundleId: "bundle-1",
      policyVersion: "policy-2026.10",
      kid: "decionis-policy-bundle-test-v1",
      notBeforeMs: Date.parse("2026-10-01T00:00:00.000Z"),
      expiresAtMs: Date.parse("2026-10-05T00:00:00.000Z"),
      expiresAt: "2026-10-05T00:00:00.000Z",
    });
    expect(events).toEqual([
      {
        event: "EDGE_BUNDLE_LOADED",
        bundle_id: "bundle-1",
        policy_version: "policy-2026.10",
        kid: "decionis-policy-bundle-test-v1",
        expires_at: "2026-10-05T00:00:00.000Z",
      },
    ]);
  });

  it("does not reload the bundle it already holds", async () => {
    const source = new ScriptedSource([bundle()]);
    const { bundles, double, events } = manager(source, { now: () => START });
    await bundles.refresh();
    await bundles.refresh();
    expect(source.reads).toBe(2);
    expect(double.loadInputs).toHaveLength(1);
    expect(events).toHaveLength(1);
  });

  it("swaps to a new bundle atomically and releases the old handle", async () => {
    const source = new ScriptedSource([bundle(), bundle({ bundle_id: "bundle-2", jti: "jti-2" })]);
    const { bundles, double } = manager(source, { now: () => START });
    await bundles.refresh();
    expect(double.loaded).toEqual(new Set([1]));
    await bundles.refresh();
    expect(bundles.current(START)?.bundleId).toBe("bundle-2");
    expect(bundles.current(START)?.handle).toBe(2);
    expect(double.loaded).toEqual(new Set([2]));
  });

  it("keeps the last good bundle when a fetch fails or the module refuses the new one", async () => {
    const source = new ScriptedSource([
      bundle(),
      { ok: false, code: "BUNDLE_HTTP_503" },
      bundle({ aud: "org-other" }),
    ]);
    const { bundles } = manager(source, { now: () => START });
    await bundles.refresh();
    expect(await bundles.refresh()).toBe("BUNDLE_HTTP_503");
    expect(bundles.current(START)?.bundleId).toBe("bundle-1");
    expect(await bundles.refresh()).toBe("BUNDLE_AUDIENCE_MISMATCH");
    expect(bundles.current(START)?.bundleId).toBe("bundle-1");
  });

  it("reports a refusal code it cannot vouch for generically", async () => {
    const { bundles } = manager(new ScriptedSource([bundle()]), {
      behaviour: { load: () => ({ ok: false, error: { code: "Weird Code: with spaces" } }) },
    });
    expect(await bundles.refresh()).toBe("BUNDLE_REFUSED");
  });

  it("refuses a load result it cannot read, releasing the handle the module took", async () => {
    const { bundles, double } = manager(new ScriptedSource([bundle()]), {
      behaviour: {
        load: () => ({ ok: true, result: { handle: 7, bundle_id: "b" } }),
      },
    });
    double.loaded.add(7);
    expect(await bundles.refresh()).toBe("BUNDLE_LOAD_RESULT_INVALID");
    expect(double.loaded.has(7)).toBe(false);
    expect(bundles.current(START)).toBeNull();
    const { bundles: other } = manager(new ScriptedSource([bundle()]), {
      behaviour: { load: () => ({ ok: true, result: null }) },
    });
    expect(await other.refresh()).toBe("BUNDLE_LOAD_RESULT_INVALID");
  });

  it("reports a faulted module as a failure", async () => {
    const { bundles } = manager(new ScriptedSource([bundle()]), {
      behaviour: { load: () => ({ nonsense: true }) },
    });
    expect(await bundles.refresh()).toBe("EDGE_MODULE_FAULTED");
  });

  it("releases a bundle at its expiry and never serves it again", async () => {
    let now = START;
    const { bundles, events, double } = manager(new ScriptedSource([bundle()]), {
      now: () => now,
    });
    await bundles.refresh();
    const exp = Date.parse("2026-10-05T00:00:00.000Z");
    expect(bundles.current(exp - 1)?.bundleId).toBe("bundle-1");
    now = exp;
    expect(bundles.current(exp)).toBeNull();
    expect(double.loaded.size).toBe(0);
    expect(events.at(-1)).toEqual({
      event: "EDGE_BUNDLE_EXPIRED",
      bundle_id: "bundle-1",
      policy_version: "policy-2026.10",
    });
    expect(bundles.current(exp - 1)).toBeNull();
  });

  it("does not serve a bundle before its not-before", async () => {
    const { bundles } = manager(new ScriptedSource([bundle()]), { now: () => START });
    await bundles.refresh();
    expect(bundles.current(Date.parse("2026-09-30T00:00:00.000Z"))).toBeNull();
    expect(bundles.current(START)).not.toBeNull();
  });

  it("shares one fetch between concurrent refreshes", async () => {
    const source = new ScriptedSource([bundle()]);
    const { bundles } = manager(source, { now: () => START });
    await Promise.all([bundles.refresh(), bundles.refresh()]);
    expect(source.reads).toBe(1);
  });

  it("refreshes on the schedule, backs off after failures, and stops", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    vi.setSystemTime(START);
    const source = new ScriptedSource([
      { ok: false, code: "BUNDLE_FETCH_FAILED" },
      { ok: false, code: "BUNDLE_HTTP_502" },
      bundle(),
    ]);
    const { bundles, events, double } = manager(source, { refreshSeconds: 600 });
    await bundles.start();
    expect(events).toEqual([
      {
        event: "EDGE_BUNDLE_REFRESH_FAILED",
        code: "BUNDLE_FETCH_FAILED",
        failures: 1,
        retry_ms: 1_000,
      },
    ]);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(events.at(-1)).toEqual({
      event: "EDGE_BUNDLE_REFRESH_FAILED",
      code: "BUNDLE_HTTP_502",
      failures: 2,
      retry_ms: 2_000,
    });
    await vi.advanceTimersByTimeAsync(2_000);
    expect(events.at(-1)?.event).toBe("EDGE_BUNDLE_LOADED");
    expect(source.reads).toBe(3);
    // The routine interval follows a success.
    await vi.advanceTimersByTimeAsync(599_000);
    expect(source.reads).toBe(3);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(source.reads).toBe(4);
    bundles.stop();
    expect(double.loaded.size).toBe(0);
    expect(bundles.current(Date.now())).toBeNull();
    await vi.advanceTimersByTimeAsync(3_600_000);
    expect(source.reads).toBe(4);
  });

  it("does not reschedule after a stop that lands during a fetch", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    vi.setSystemTime(START);
    let release: (read: BundleRead) => void = () => undefined;
    const source: EdgeBundleSource = {
      kind: "url",
      read: vi.fn(
        async () =>
          await new Promise<BundleRead>((resolve) => {
            release = resolve;
          }),
      ),
    };
    const { bundles } = manager(source);
    const started = bundles.start();
    bundles.stop();
    release(bundle());
    await started;
    await vi.advanceTimersByTimeAsync(7_200_000);
    expect(source.read).toHaveBeenCalledTimes(1);
  });

  it("polls a file source at least every ten seconds", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    vi.setSystemTime(START);
    const source = new ScriptedSource([bundle()], "file");
    const { bundles } = manager(source);
    await bundles.start();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(source.reads).toBe(2);
    bundles.stop();
  });

  it("swallows a reporting failure", async () => {
    const double = edgeModuleDouble();
    const bundles = new EdgeBundleManager({
      module: EdgeModule.fromExports(double.exports),
      source: new ScriptedSource([bundle()]),
      orgId: "org-1",
      clock: () => START,
      onEvent: () => {
        throw new Error("log sink down");
      },
    });
    expect(await bundles.refresh()).toBeNull();
    expect(bundles.current(START)).not.toBeNull();
  });
});

describe("signedBundleOf", () => {
  const jws = signedBundle(doubleClaims());
  it("accepts a compact JWS on its own or inside the issuance response", () => {
    expect(signedBundleOf(`  ${jws}\n`)).toEqual({ ok: true, signedBundle: jws });
    expect(signedBundleOf(JSON.stringify({ signed_bundle: jws, bundle_id: "b" }))).toEqual({
      ok: true,
      signedBundle: jws,
    });
  });

  it("refuses anything else", () => {
    for (const text of ["", "{not json", "{}", '{"signed_bundle": 5}', "a.b", "a..c", "a.b.c.d"]) {
      expect(signedBundleOf(text)).toEqual({ ok: false, code: "BUNDLE_RESPONSE_INVALID" });
    }
  });
});

describe("UrlBundleSource", () => {
  function source(fetchImpl: typeof fetch) {
    return new UrlBundleSource({
      baseUrl: "https://authority.decionis.example/",
      apiKey: () => API_KEY,
      fetch: fetchImpl,
    });
  }

  it("asks for the current bundle with the organisation's key", async () => {
    const jws = signedBundle(doubleClaims());
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ signed_bundle: jws })));
    const read = await source(fetchImpl as unknown as typeof fetch).read();
    expect(read).toEqual({ ok: true, signedBundle: jws });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://authority.decionis.example/v1/edge/policy-bundles/current");
    expect(init.method).toBe("GET");
    expect((init.headers as Record<string, string>)["authorization"]).toBe(`Bearer ${API_KEY}`);
    expect((init.headers as Record<string, string>)["user-agent"]).toMatch(
      /^agent-safe-pipeline\//,
    );
  });

  it("answers failures with codes that carry no secret, status text or body", async () => {
    const answers: [() => Promise<Response>, string][] = [
      [async () => new Response(`denied for ${API_KEY}`, { status: 401 }), "BUNDLE_HTTP_401"],
      [async () => new Response(null, { status: 404 }), "BUNDLE_HTTP_404"],
      [async () => new Response("x".repeat(4 * 1024 * 1024 + 1)), "BUNDLE_TOO_LARGE"],
      [async () => new Response(`{"signed_bundle":"${API_KEY}"}`), "BUNDLE_RESPONSE_INVALID"],
      [
        async () => {
          throw new Error(`connect ECONNREFUSED with ${API_KEY}`);
        },
        "BUNDLE_FETCH_FAILED",
      ],
    ];
    for (const [answer, code] of answers) {
      const read = await source(answer as unknown as typeof fetch).read();
      expect(read).toEqual({ ok: false, code });
      expect(JSON.stringify(read)).not.toContain(API_KEY);
    }
  });

  it("gives up on a fetch that does not answer within the timeout", async () => {
    const hanging = vi.fn(
      async (_url: string, init: RequestInit) =>
        await new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        }),
    );
    const read = await new UrlBundleSource({
      baseUrl: "https://authority.decionis.example",
      apiKey: API_KEY,
      fetch: hanging as unknown as typeof fetch,
      timeoutMs: 5,
    }).read();
    expect(read).toEqual({ ok: false, code: "BUNDLE_FETCH_FAILED" });
  });

  it("refuses an authority address that is not https", () => {
    expect(
      () => new UrlBundleSource({ baseUrl: "http://authority.decionis.example", apiKey: API_KEY }),
    ).toThrow("DECIONIS_URL_MUST_USE_HTTPS");
    expect(
      new UrlBundleSource({
        baseUrl: "http://127.0.0.1:9",
        apiKey: API_KEY,
        allowInsecureLoopback: true,
      }).kind,
    ).toBe("url");
  });
});

describe("FileBundleSource", () => {
  it("reads the bundle an operator placed, raw or as the issuance response", async () => {
    const dir = mkdtempSync(join(tmpdir(), "edge-bundle-"));
    const path = join(dir, "bundle.jws");
    const jws = signedBundle(doubleClaims());
    writeFileSync(path, `${jws}\n`);
    const file = new FileBundleSource(path);
    expect(file.kind).toBe("file");
    expect(await file.read()).toEqual({ ok: true, signedBundle: jws });
    writeFileSync(path, JSON.stringify({ signed_bundle: jws }));
    expect(await file.read()).toEqual({ ok: true, signedBundle: jws });
    writeFileSync(path, "x".repeat(4 * 1024 * 1024 + 1));
    expect(await file.read()).toEqual({ ok: false, code: "BUNDLE_TOO_LARGE" });
  });

  it("reports a missing file without its path", async () => {
    const read = await new FileBundleSource("/nonexistent/bundle.jws").read();
    expect(read).toEqual({ ok: false, code: "BUNDLE_FILE_UNREADABLE" });
  });

  it("re-reads on change: a replaced file is loaded at the next poll", async () => {
    const dir = mkdtempSync(join(tmpdir(), "edge-bundle-"));
    const path = join(dir, "bundle.jws");
    writeFileSync(path, signedBundle(doubleClaims()));
    const { bundles } = manager(new FileBundleSource(path), { now: () => START });
    await bundles.refresh();
    expect(bundles.current(START)?.bundleId).toBe("bundle-1");
    writeFileSync(path, signedBundle(doubleClaims({ bundle_id: "bundle-2" })));
    await bundles.refresh();
    expect(bundles.current(START)?.bundleId).toBe("bundle-2");
  });
});
