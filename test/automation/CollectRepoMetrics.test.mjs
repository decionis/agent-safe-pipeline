import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import {
  FILES,
  collectRepoMetrics,
  npmRows,
  popularRows,
  trafficRows,
  upsert,
} from "../../scripts/CollectRepoMetrics.mjs";

const REPOSITORY = "synthetic-owner/synthetic-repo";

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** A GitHub and npm double keyed by URL; anything unknown answers 404. */
function fetchDouble(routes, calls = []) {
  return async (url, init) => {
    calls.push({ url: String(url), headers: init?.headers ?? {} });
    const route = routes[String(url)];
    if (route === undefined) return json({ message: "Not Found" }, 404);
    return typeof route === "function" ? route() : json(route);
  };
}

const traffic = {
  count: 12,
  uniques: 9,
  clones: [
    { timestamp: "2026-09-16T00:00:00Z", count: 5, uniques: 4 },
    { timestamp: "2026-09-17T00:00:00Z", count: 7, uniques: 5 },
  ],
};
const views = {
  count: 40,
  uniques: 20,
  views: [
    { timestamp: "2026-09-17T00:00:00Z", count: 25, uniques: 12 },
    { timestamp: "2026-09-18T00:00:00Z", count: 15, uniques: 8 },
  ],
};
const routes = {
  [`https://api.github.com/repos/${REPOSITORY}`]: {
    stargazers_count: 41,
    forks_count: 57,
    subscribers_count: 6,
  },
  [`https://api.github.com/repos/${REPOSITORY}/traffic/clones`]: traffic,
  [`https://api.github.com/repos/${REPOSITORY}/traffic/views`]: views,
  [`https://api.github.com/repos/${REPOSITORY}/traffic/popular/referrers`]: [
    { referrer: "news.example", count: 30, uniques: 20 },
    { referrer: "", count: 1, uniques: 1 },
  ],
  [`https://api.github.com/repos/${REPOSITORY}/traffic/popular/paths`]: [
    { path: "/synthetic-owner/synthetic-repo", title: "root", count: 50, uniques: 30 },
  ],
  "https://api.npmjs.org/downloads/range/last-month/%40decionis%2Fagent-safe-pipeline": {
    downloads: [
      { day: "2026-09-17", downloads: 3 },
      { day: "2026-09-18", downloads: 4 },
    ],
  },
};

describe("the metrics rows", () => {
  it("shape traffic, popular entries and npm downloads by day, tolerating what is missing", () => {
    assert.deepEqual(trafficRows(traffic, views), [
      { date: "2026-09-16", clones: 5, unique_cloners: 4, views: 0, unique_visitors: 0 },
      { date: "2026-09-17", clones: 7, unique_cloners: 5, views: 25, unique_visitors: 12 },
      { date: "2026-09-18", clones: 0, unique_cloners: 0, views: 15, unique_visitors: 8 },
    ]);
    assert.deepEqual(trafficRows(null, { views: [{ timestamp: 5, count: 1 }] }), []);
    assert.deepEqual(
      popularRows(
        "2026-09-18",
        routes[`https://api.github.com/repos/${REPOSITORY}/traffic/popular/referrers`],
        (e) => e.referrer,
      ),
      [{ date: "2026-09-18", name: "news.example", count: 30, uniques: 20 }],
    );
    assert.deepEqual(
      popularRows("2026-09-18", "not a list", (e) => e.referrer),
      [],
    );
    assert.deepEqual(
      npmRows("pkg", { downloads: [{ day: "2026-09-18", downloads: -1 }, { day: 7 }] }),
      [{ date: "2026-09-18", package: "pkg", downloads: 0 }],
    );
    assert.deepEqual(npmRows("pkg", null), []);
  });

  it("upserts by key, fresh rows winning, sorted", () => {
    const merged = upsert(
      [
        { date: "2026-09-17", clones: 1 },
        { date: "2026-09-15", clones: 2 },
      ],
      [
        { date: "2026-09-17", clones: 7 },
        { date: "2026-09-18", clones: 3 },
      ],
      (row) => row.date,
    );
    assert.deepEqual(merged, [
      { date: "2026-09-15", clones: 2 },
      { date: "2026-09-17", clones: 7 },
      { date: "2026-09-18", clones: 3 },
    ]);
  });
});

describe("collectRepoMetrics", () => {
  let dir;

  before(async () => {
    dir = await mkdtemp(join(tmpdir(), "agentsafe-metrics-"));
  });

  after(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("writes every file, sends the token only to the traffic routes, and summarizes", async () => {
    const calls = [];
    const chunks = [];
    const { summary, notes } = await collectRepoMetrics({
      repository: REPOSITORY,
      token: "synthetic-metrics-token",
      packages: ["@decionis/agent-safe-pipeline", "@decionis/agentsafe"],
      dir,
      fetchImpl: fetchDouble(routes, calls),
      clock: () => new Date("2026-09-18T05:23:00.000Z"),
      out: { write: (chunk) => chunks.push(chunk) },
    });
    assert.deepEqual(summary.repository, { date: "2026-09-18", stars: 41, forks: 57, watchers: 6 });
    assert.deepEqual(summary.traffic, {
      days: 3,
      clones: 12,
      unique_cloners: 9,
      views: 40,
      unique_visitors: 20,
    });
    assert.deepEqual(summary.npm, { "@decionis/agent-safe-pipeline": { days: 2, last_week: 7 } });
    assert.deepEqual(notes, ["npm downloads unavailable for @decionis/agentsafe (404)"]);
    for (const call of calls) {
      const authorized = "authorization" in call.headers;
      assert.equal(authorized, call.url.includes("/traffic/"), call.url);
      assert.equal(call.headers["user-agent"], "agent-safe-pipeline-metrics");
    }
    const written = Object.fromEntries(
      await Promise.all(
        Object.values(FILES).map(async (name) => [
          name,
          (await readFile(join(dir, name), "utf8"))
            .trim()
            .split("\n")
            .map((l) => JSON.parse(l)),
        ]),
      ),
    );
    assert.equal(written[FILES.traffic].length, 3);
    assert.deepEqual(written[FILES.repository], [
      { date: "2026-09-18", stars: 41, forks: 57, watchers: 6 },
    ]);
    assert.deepEqual(written[FILES.referrers], [
      { date: "2026-09-18", name: "news.example", count: 30, uniques: 20 },
    ]);
    assert.deepEqual(written[FILES.paths], [
      { date: "2026-09-18", name: "/synthetic-owner/synthetic-repo", count: 50, uniques: 30 },
    ]);
    assert.deepEqual(written[FILES.npm], [
      { date: "2026-09-17", package: "@decionis/agent-safe-pipeline", downloads: 3 },
      { date: "2026-09-18", package: "@decionis/agent-safe-pipeline", downloads: 4 },
    ]);
    const text = chunks.join("");
    assert.match(text, /^## Repository metrics, 2026-09-18\n/);
    assert.match(text, /Stars 41, forks 57, watchers 6/);
    assert.match(text, /12 clones by 9 unique cloners; 40 views by 20 unique visitors/);
    assert.match(text, /npm @decionis\/agent-safe-pipeline: 7 downloads in the last 7 days/);
    assert.match(text, /Note: npm downloads unavailable for @decionis\/agentsafe \(404\)/);
  });

  it("revises a day GitHub restated and keeps the days it no longer reports", async () => {
    const path = join(dir, FILES.traffic);
    await writeFile(
      path,
      `${JSON.stringify({ date: "2026-09-01", clones: 9, unique_cloners: 9, views: 9, unique_visitors: 9 })}\nnot json\n`,
      "utf8",
    );
    await collectRepoMetrics({
      repository: REPOSITORY,
      token: "synthetic-metrics-token",
      packages: [],
      dir,
      fetchImpl: fetchDouble({
        ...routes,
        [`https://api.github.com/repos/${REPOSITORY}/traffic/clones`]: {
          ...traffic,
          clones: [{ timestamp: "2026-09-17T00:00:00Z", count: 8, uniques: 6 }],
        },
      }),
      clock: () => new Date("2026-09-19T05:23:00.000Z"),
      out: { write: () => undefined },
    });
    const rows = (await readFile(path, "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    assert.deepEqual(
      rows.map((r) => [r.date, r.clones]),
      [
        ["2026-09-01", 9],
        ["2026-09-17", 8],
        ["2026-09-18", 0],
      ],
    );
  });

  it("skips traffic without a token, or when the token cannot read it, and says so", async () => {
    const quiet = { write: () => undefined };
    const without = await collectRepoMetrics({
      repository: REPOSITORY,
      packages: [],
      dir: await mkdtemp(join(tmpdir(), "agentsafe-metrics-")),
      fetchImpl: fetchDouble(routes),
      out: quiet,
    });
    assert.equal(without.summary.traffic, null);
    assert.deepEqual(without.notes, ["traffic skipped: METRICS_GITHUB_TOKEN is not set"]);
    const forbidden = await collectRepoMetrics({
      repository: REPOSITORY,
      token: "synthetic-weak-token",
      packages: [],
      dir: await mkdtemp(join(tmpdir(), "agentsafe-metrics-")),
      fetchImpl: fetchDouble({
        [`https://api.github.com/repos/${REPOSITORY}/traffic/clones`]: () => json({}, 403),
        [`https://api.github.com/repos/${REPOSITORY}/traffic/views`]: () => json({}, 403),
      }),
      out: quiet,
    });
    assert.deepEqual(forbidden.notes, [
      "repository counts unavailable (404)",
      "traffic unavailable (403); the token needs administration read",
    ]);
  });

  it("refuses a repository or package name it cannot put in a URL", async () => {
    await assert.rejects(
      collectRepoMetrics({ repository: "../evil", dir, fetchImpl: fetchDouble({}) }),
      /METRICS_REPOSITORY_INVALID/,
    );
    await assert.rejects(
      collectRepoMetrics({
        repository: REPOSITORY,
        packages: ["../../etc"],
        dir,
        fetchImpl: fetchDouble({}),
      }),
      /METRICS_PACKAGE_INVALID/,
    );
  });
});
