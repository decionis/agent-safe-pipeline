/**
 * What the repository's path looks like in numbers, collected once a day and
 * kept where a question can be answered later: how many clones and unique
 * cloners, views and unique visitors, stars, forks and watchers the
 * repository had on each day, where the visitors came from, and how many
 * times each package was installed from npm. GitHub keeps traffic for
 * fourteen days and nothing else keeps it at all, which is why this appends
 * to files on the `metrics` branch instead of reading the API when asked.
 *
 *   node scripts/CollectRepoMetrics.mjs [--dir metrics]
 *
 * Reads GITHUB_REPOSITORY (owner/name), METRICS_GITHUB_TOKEN (a token with
 * read access to the repository's administration, which the traffic
 * endpoints require; without it the traffic rows are skipped and said so),
 * and NPM_PACKAGES (comma-separated; the two packages here by default).
 * Every file is JSON lines keyed by date, upserted, so a day GitHub revises
 * inside its window is corrected rather than duplicated. The organization
 * side of the same funnel, which workspace a clone went on to create, is
 * the authority's own record, stamped `surface=github` from the client
 * identification the examples send.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { readBoundedJsonResponse } from "./BoundedJsonResponse.mjs";

export const DEFAULT_PACKAGES = ["@decionis/agent-safe-pipeline", "@decionis/agentsafe"];
const GITHUB_API = "https://api.github.com";
const NPM_API = "https://api.npmjs.org";
const TIMEOUT_MS = 15_000;
const REPOSITORY_PATTERN = /^[a-z0-9][\w.-]{0,99}\/[a-z0-9][\w.-]{0,99}$/i;
const PACKAGE_PATTERN = /^(?:@[a-z0-9][\w.-]{0,100}\/)?[a-z0-9][\w.-]{0,200}$/;

export const FILES = {
  traffic: "github-traffic.jsonl",
  repository: "github-repository.jsonl",
  referrers: "github-referrers.jsonl",
  paths: "github-paths.jsonl",
  npm: "npm-downloads.jsonl",
};

/** One GET, bounded and timed, as JSON; null on a 4xx/5xx so a missing permission is a row not written, not a crash. */
async function getJson(fetchImpl, url, headers) {
  const response = await fetchImpl(url, {
    method: "GET",
    headers: {
      accept: "application/json",
      "user-agent": "agent-safe-pipeline-metrics",
      ...headers,
    },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    return { status: response.status, body: null };
  }
  return { status: response.status, body: await readBoundedJsonResponse(response) };
}

function day(value) {
  return typeof value === "string" ? value.slice(0, 10) : null;
}

function count(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? Math.trunc(value) : 0;
}

/** Reads a JSON-lines file into rows; a line that is not an object is dropped, never kept as noise. */
export async function readRows(path) {
  let text;
  try {
    text = await readFile(path, "utf8");
  } catch {
    return [];
  }
  const rows = [];
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    try {
      const parsed = JSON.parse(line);
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed))
        rows.push(parsed);
    } catch {
      // A damaged line is dropped; the next collection rewrites the file whole.
    }
  }
  return rows;
}

/** Merges fresh rows into stored ones by key, fresh winning, and returns them sorted by key. */
export function upsert(stored, fresh, keyOf) {
  const byKey = new Map();
  for (const row of stored) byKey.set(keyOf(row), row);
  for (const row of fresh) byKey.set(keyOf(row), row);
  return [...byKey.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([, row]) => row);
}

async function writeRows(path, rows) {
  await writeFile(path, rows.map((row) => `${JSON.stringify(row)}\n`).join(""), "utf8");
}

/** The traffic GitHub keeps for fourteen days, as one row per day. */
export function trafficRows(clones, views) {
  const rows = new Map();
  for (const entry of clones?.clones ?? []) {
    const date = day(entry.timestamp);
    if (date === null) continue;
    rows.set(date, { date, clones: count(entry.count), unique_cloners: count(entry.uniques) });
  }
  for (const entry of views?.views ?? []) {
    const date = day(entry.timestamp);
    if (date === null) continue;
    rows.set(date, {
      ...(rows.get(date) ?? { date, clones: 0, unique_cloners: 0 }),
      views: count(entry.count),
      unique_visitors: count(entry.uniques),
    });
  }
  return [...rows.values()].map((row) => ({
    views: 0,
    unique_visitors: 0,
    ...row,
  }));
}

/** The top referrers or paths GitHub reports over the trailing fourteen days, dated by the collection day. */
export function popularRows(date, entries, nameOf) {
  return (Array.isArray(entries) ? entries : []).flatMap((entry) => {
    const name = nameOf(entry);
    return typeof name === "string" && name.length > 0 && name.length <= 500
      ? [{ date, name, count: count(entry.count), uniques: count(entry.uniques) }]
      : [];
  });
}

/** npm's daily downloads for one package, as one row per day. */
export function npmRows(name, range) {
  return (range?.downloads ?? []).flatMap((entry) => {
    const date = day(entry.day);
    return date === null ? [] : [{ date, package: name, downloads: count(entry.downloads) }];
  });
}

export async function collectRepoMetrics({
  repository,
  token,
  packages = DEFAULT_PACKAGES,
  dir,
  fetchImpl = globalThis.fetch,
  clock = () => new Date(),
  out = process.stdout,
}) {
  if (!REPOSITORY_PATTERN.test(repository)) throw new Error("METRICS_REPOSITORY_INVALID");
  for (const name of packages) {
    if (!PACKAGE_PATTERN.test(name)) throw new Error(`METRICS_PACKAGE_INVALID: ${name}`);
  }
  const today = clock().toISOString().slice(0, 10);
  await mkdir(dir, { recursive: true });
  const notes = [];
  const summary = { date: today, traffic: null, repository: null, npm: {} };

  // The repository's public counts need no token at all.
  const repo = await getJson(fetchImpl, `${GITHUB_API}/repos/${repository}`, {});
  if (repo.body !== null) {
    summary.repository = {
      date: today,
      stars: count(repo.body.stargazers_count),
      forks: count(repo.body.forks_count),
      watchers: count(repo.body.subscribers_count),
    };
    const path = join(dir, FILES.repository);
    await writeRows(
      path,
      upsert(await readRows(path), [summary.repository], (row) => row.date),
    );
  } else {
    notes.push(`repository counts unavailable (${repo.status})`);
  }

  // Traffic needs a token with administration read; without one the rows are skipped, not faked.
  if (token === undefined || token === "") {
    notes.push("traffic skipped: METRICS_GITHUB_TOKEN is not set");
  } else {
    const auth = { authorization: `Bearer ${token}` };
    const base = `${GITHUB_API}/repos/${repository}/traffic`;
    const [clones, views, referrers, paths] = await Promise.all([
      getJson(fetchImpl, `${base}/clones`, auth),
      getJson(fetchImpl, `${base}/views`, auth),
      getJson(fetchImpl, `${base}/popular/referrers`, auth),
      getJson(fetchImpl, `${base}/popular/paths`, auth),
    ]);
    if (clones.body === null && views.body === null) {
      notes.push(`traffic unavailable (${clones.status}); the token needs administration read`);
    } else {
      const rows = trafficRows(clones.body, views.body);
      const path = join(dir, FILES.traffic);
      const merged = upsert(await readRows(path), rows, (row) => row.date);
      await writeRows(path, merged);
      summary.traffic = {
        days: rows.length,
        clones: rows.reduce((sum, row) => sum + row.clones, 0),
        unique_cloners: count(clones.body?.uniques),
        views: rows.reduce((sum, row) => sum + row.views, 0),
        unique_visitors: count(views.body?.uniques),
      };
      const referrerRows = popularRows(today, referrers.body, (entry) => entry.referrer);
      const referrerPath = join(dir, FILES.referrers);
      await writeRows(
        referrerPath,
        upsert(await readRows(referrerPath), referrerRows, (row) => `${row.date} ${row.name}`),
      );
      const pathRows = popularRows(today, paths.body, (entry) => entry.path);
      const pathsPath = join(dir, FILES.paths);
      await writeRows(
        pathsPath,
        upsert(await readRows(pathsPath), pathRows, (row) => `${row.date} ${row.name}`),
      );
    }
  }

  // npm's counts are public; a package not yet published answers 404 and is noted, not written.
  const npmPath = join(dir, FILES.npm);
  let npmStored = await readRows(npmPath);
  for (const name of packages) {
    const range = await getJson(
      fetchImpl,
      `${NPM_API}/downloads/range/last-month/${encodeURIComponent(name)}`,
      {},
    );
    if (range.body === null) {
      notes.push(`npm downloads unavailable for ${name} (${range.status})`);
      continue;
    }
    const rows = npmRows(name, range.body);
    npmStored = upsert(npmStored, rows, (row) => `${row.package} ${row.date}`);
    const lastWeek = rows.slice(-7).reduce((sum, row) => sum + row.downloads, 0);
    summary.npm[name] = { days: rows.length, last_week: lastWeek };
  }
  await writeRows(npmPath, npmStored);

  const lines = [`## Repository metrics, ${today}`, ""];
  if (summary.repository !== null) {
    lines.push(
      `- Stars ${summary.repository.stars}, forks ${summary.repository.forks}, watchers ${summary.repository.watchers}`,
    );
  }
  if (summary.traffic !== null) {
    lines.push(
      `- Last ${summary.traffic.days} days: ${summary.traffic.clones} clones by ${summary.traffic.unique_cloners} unique cloners; ${summary.traffic.views} views by ${summary.traffic.unique_visitors} unique visitors`,
    );
  }
  for (const [name, counts] of Object.entries(summary.npm)) {
    lines.push(`- npm ${name}: ${counts.last_week} downloads in the last 7 days`);
  }
  for (const note of notes) lines.push(`- Note: ${note}`);
  lines.push("");
  out.write(lines.join("\n"));
  return { summary, notes };
}

function argument(argv, name) {
  const index = argv.indexOf(name);
  return index === -1 ? undefined : argv[index + 1];
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const repository = (process.env.GITHUB_REPOSITORY ?? "").trim();
  const packages = (process.env.NPM_PACKAGES ?? "")
    .split(",")
    .map((name) => name.trim())
    .filter((name) => name !== "");
  collectRepoMetrics({
    repository,
    token: process.env.METRICS_GITHUB_TOKEN?.trim(),
    ...(packages.length === 0 ? {} : { packages }),
    dir: resolve(argument(process.argv, "--dir") ?? "metrics"),
  }).then(
    () => process.exit(0),
    (error) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exit(1);
    },
  );
}
