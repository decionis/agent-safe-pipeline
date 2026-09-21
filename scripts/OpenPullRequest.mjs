import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { readBoundedJsonResponse } from "./BoundedJsonResponse.mjs";

const apiVersion = "2022-11-28";
const defaultTimeoutMs = 10_000;
const defaultMaxAttempts = 2;
const maxTimeoutMs = 15_000;
const maxAttemptsLimit = 3;
const maxPages = 3;
const perPage = 100;
/**
 * The commit listing that stands in for a comparison too large to read. One
 * entry is about 8 KiB here: the message, the signature verification that
 * repeats it as its payload, and the URLs; so a page of twenty is about
 * 160 KiB, inside the wider bound the listing shares with the comparison,
 * with room for messages twice as long. Six pages reach a base within the
 * default branch's last hundred and twenty commits.
 */
const commitsPerPage = 20;
const maxCommitPages = 6;
const branchCreationWorkflow = ".github/workflows/PullRequestBot.yml";
export const compareMaxJsonResponseBytes = 512 * 1024;
/** GitHub accepts a longer title; 72 keeps it readable in a list and in a terminal. */
const maxTitleLength = 72;
/** Well inside GitHub's own limit for a pull request body. */
const maxDescriptionBytes = 48 * 1024;

function jsonResponseOptions(method, pathname) {
  // GitHub embeds textual patches in compare responses, and a commit listing
  // carries each commit's message twice (once as the signature's payload).
  // Keep the wider bound specific to those two read-only endpoints; every
  // other response retains 100 KiB.
  const isCompare = method === "GET" && /^\/repos\/[^/]+\/[^/]+\/compare\/[^/]+$/.test(pathname);
  const isCommitListing = method === "GET" && /^\/repos\/[^/]+\/[^/]+\/commits$/.test(pathname);
  return isCompare || isCommitListing ? { maxBytes: compareMaxJsonResponseBytes } : undefined;
}

export class GitHubApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "GitHubApiError";
    this.status = status;
  }
}

function boundedInteger(value, fallback, maximum, name) {
  const resolved = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(resolved) || resolved < 1) {
    throw new Error(name + " must be a positive safe integer");
  }
  return Math.min(resolved, maximum);
}

export class GitHubApiClient {
  constructor({
    token,
    fetchImpl = globalThis.fetch,
    timeoutMs = defaultTimeoutMs,
    maxAttempts = defaultMaxAttempts,
  }) {
    if (!token) throw new Error("GITHUB_TOKEN is required");
    if (typeof fetchImpl !== "function") throw new Error("A fetch implementation is required");
    this.token = token;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = boundedInteger(timeoutMs, defaultTimeoutMs, maxTimeoutMs, "timeoutMs");
    this.maxAttempts = boundedInteger(
      maxAttempts,
      defaultMaxAttempts,
      maxAttemptsLimit,
      "maxAttempts",
    );
  }

  async request(method, path, { query, body } = {}) {
    const url = new URL(path, "https://api.github.com");
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    }

    let lastError;
    for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
      try {
        const response = await this.fetchImpl(url, {
          method,
          headers: {
            Accept: "application/vnd.github+json",
            Authorization: "Bearer " + this.token,
            "X-GitHub-Api-Version": apiVersion,
            ...(body === undefined ? {} : { "Content-Type": "application/json" }),
          },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        if (response.ok) {
          return await readBoundedJsonResponse(response, jsonResponseOptions(method, url.pathname));
        }

        const error = new GitHubApiError(
          "GitHub API request failed: " +
            method +
            " " +
            url.pathname +
            " (" +
            response.status +
            ")",
          response.status,
        );
        if (!this.isRetryable(response.status) || attempt === this.maxAttempts) throw error;
        lastError = error;
      } catch (error) {
        if (error instanceof GitHubApiError) {
          if (!this.isRetryable(error.status) || attempt === this.maxAttempts) throw error;
        } else if (attempt === this.maxAttempts) {
          throw error;
        }
        lastError = error;
      }
      await this.wait(attempt);
    }
    throw lastError ?? new Error("GitHub API request failed");
  }

  async paginate(path, query = {}) {
    const values = [];
    for (let page = 1; page <= maxPages; page += 1) {
      const response = await this.request("GET", path, {
        query: { ...query, per_page: perPage, page },
      });
      if (!Array.isArray(response)) throw new Error("Expected an array from " + path);
      values.push(...response);
      if (response.length < perPage) return values;
    }
    throw new Error("Pagination limit exceeded for " + path);
  }

  isRetryable(status) {
    return status === 429 || status >= 500;
  }

  async wait(attempt) {
    const delayMs = 200 * attempt + Math.floor(Math.random() * 100);
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
}

export class PullRequestBot {
  constructor({ api, repository, expectedAuthorLogin, defaultBranch }) {
    const [owner, name, extra] = repository.split("/");
    if (!owner || !name || extra) throw new Error("GITHUB_REPOSITORY must be owner/name");
    if (!expectedAuthorLogin) throw new Error("EXPECTED_AUTHOR_LOGIN is required");
    if (!defaultBranch) throw new Error("DEFAULT_BRANCH is required");
    this.api = api;
    this.owner = owner;
    this.name = name;
    this.repository = repository;
    this.expectedAuthorLogin = expectedAuthorLogin.toLowerCase();
    this.defaultBranch = defaultBranch;
  }

  async run(eventName, event) {
    if (eventName === "create" && event?.ref_type !== "branch") {
      return [{ branch: event?.ref, status: "skipped", reason: "non-branch-create-event" }];
    }
    const requestedBranch =
      eventName === "workflow_dispatch"
        ? this.readInput(event, "branch")
        : eventName === "create" && event?.ref_type === "branch"
          ? event.ref
          : undefined;
    const creationRunId =
      eventName === "workflow_dispatch" ? this.readInput(event, "creation_run_id") : undefined;
    const branches = requestedBranch ? [requestedBranch] : await this.listCandidateBranches();
    const outcomes = [];

    for (const branch of branches) {
      outcomes.push(await this.ensurePullRequest(branch, creationRunId));
    }
    return outcomes;
  }

  readInput(event, name) {
    const value = event?.inputs?.[name];
    return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
  }

  async listCandidateBranches() {
    const branches = await this.api.paginate("/repos/" + this.repository + "/branches");
    return branches
      .map(({ name }) => name)
      .filter((name) => typeof name === "string" && name !== this.defaultBranch);
  }

  async ensurePullRequest(branch, creationRunId) {
    if (!branch || branch === this.defaultBranch) {
      return { branch, status: "skipped", reason: "default-or-empty-branch" };
    }

    const existing = await this.findExistingPullRequest(branch);
    if (existing) {
      return { branch, status: "skipped", reason: "pull-request-exists", url: existing.html_url };
    }

    const comparison = await this.compareBranch(branch);
    if (!comparison || comparison.ahead_by < 1) {
      return { branch, status: "skipped", reason: "no-commits-ahead" };
    }
    if (
      !Array.isArray(comparison.commits) ||
      comparison.total_commits !== comparison.commits.length
    ) {
      return { branch, status: "skipped", reason: "incomplete-commit-comparison" };
    }

    const createdByExpectedAuthor = creationRunId
      ? await this.isTrustedCreationRun(creationRunId, branch)
      : await this.hasTrustedCreationRun(branch);
    const commitsByExpectedAuthor = comparison.commits.every(
      (commit) => commit.author?.login?.toLowerCase() === this.expectedAuthorLogin,
    );
    if (!createdByExpectedAuthor && !commitsByExpectedAuthor) {
      return { branch, status: "skipped", reason: "untrusted-branch-and-commit-authors" };
    }

    const reason = createdByExpectedAuthor
      ? "branch creation was attributed to @" + this.expectedAuthorLogin
      : "every commit ahead of " +
        this.defaultBranch +
        " was attributed to @" +
        this.expectedAuthorLogin;
    const messages = comparison.commits.map((commit) => commit?.commit?.message);
    const title = titleFromMessage(messages.at(-1), branch);
    const pullRequest = await this.api.request("POST", "/repos/" + this.repository + "/pulls", {
      body: {
        title,
        head: branch,
        base: this.defaultBranch,
        body: this.buildBody(branch, reason, messages),
        draft: false,
        maintainer_can_modify: true,
      },
    });
    return { branch, status: "created", reason, url: pullRequest.html_url };
  }

  async findExistingPullRequest(branch) {
    // Only an OPEN pull request counts as existing. A closed, unmerged pull
    // request is a decision about that earlier branch, not about a branch of
    // the same name recreated afterwards; asking for every state made the
    // bot skip such a branch forever with "pull-request-exists".
    const pulls = await this.api.request("GET", "/repos/" + this.repository + "/pulls", {
      query: {
        state: "open",
        head: this.owner + ":" + branch,
        base: this.defaultBranch,
        per_page: perPage,
      },
    });
    if (!Array.isArray(pulls)) throw new Error("Expected pull request list");
    return pulls.find((pull) => pull?.state === undefined || pull.state === "open");
  }

  async compareBranch(branch) {
    const base = encodeURIComponent(this.defaultBranch);
    const head = encodeURIComponent(branch);
    try {
      return await this.api.request(
        "GET",
        "/repos/" + this.repository + "/compare/" + base + "..." + head,
        { query: { per_page: perPage } },
      );
    } catch (error) {
      if (error instanceof GitHubApiError && error.status === 404) return null;
      // A comparison carries every changed file's patch, and a large change
      // outgrows the bound; the bot needs only the commits ahead and who made
      // them, which the commit listings say without a patch in sight.
      if (error instanceof Error && error.message === "GITHUB_API_RESPONSE_TOO_LARGE") {
        return this.compareFromCommits(branch);
      }
      throw error;
    }
  }

  /**
   * The commits ahead of the default branch, read from the two commit
   * listings: the branch's, newest first, up to the first commit the default
   * branch's recent history also has, returned oldest first as a comparison
   * lists them. A base beyond that history is reported as an incomplete
   * comparison, exactly as GitHub's own would be, so the bot fails closed
   * rather than guessing at authorship.
   */
  async compareFromCommits(branch) {
    const known = new Set((await this.listCommits(this.defaultBranch)).map(({ sha }) => sha));
    const ahead = [];
    for (const commit of await this.listCommits(branch)) {
      if (typeof commit?.sha !== "string") break;
      if (known.has(commit.sha)) {
        ahead.reverse();
        return { ahead_by: ahead.length, total_commits: ahead.length, commits: ahead };
      }
      ahead.push(commit);
    }
    return { ahead_by: ahead.length, total_commits: ahead.length + 1, commits: ahead };
  }

  async listCommits(ref) {
    const commits = [];
    for (let page = 1; page <= maxCommitPages; page += 1) {
      const response = await this.api.request("GET", "/repos/" + this.repository + "/commits", {
        query: { sha: ref, per_page: commitsPerPage, page },
      });
      if (!Array.isArray(response)) throw new Error("Expected commit list");
      commits.push(...response);
      if (response.length < commitsPerPage) break;
    }
    return commits;
  }

  async isTrustedCreationRun(runId, branch) {
    if (!/^\d+$/.test(String(runId))) return false;
    const run = await this.api.request(
      "GET",
      "/repos/" + this.repository + "/actions/runs/" + runId,
    );
    return this.creationRunMatches(run, branch);
  }

  async hasTrustedCreationRun(branch) {
    const response = await this.api.request("GET", "/repos/" + this.repository + "/actions/runs", {
      query: {
        event: "create",
        branch,
        actor: this.expectedAuthorLogin,
        per_page: perPage,
      },
    });
    const runs = response?.workflow_runs;
    if (!Array.isArray(runs)) throw new Error("Expected workflow run list");
    return runs.some((run) => this.creationRunMatches(run, branch));
  }

  creationRunMatches(run, branch) {
    const workflowPath = run?.path?.split("@")[0];
    return (
      run?.event === "create" &&
      run?.head_branch === branch &&
      run?.actor?.login?.toLowerCase() === this.expectedAuthorLogin &&
      run?.repository?.full_name === this.repository &&
      workflowPath === branchCreationWorkflow
    );
  }

  /**
   * The pull request's description. What the change is comes from the
   * commits themselves, because the author already wrote it there and a
   * reviewer should not have to open the commit list to read it; what the
   * bot did comes after, so provenance never displaces the substance.
   */
  buildBody(branch, reason, messages = []) {
    const quote = String.fromCharCode(96);
    const safeBranch = branch.replaceAll(quote, "\\" + quote);
    return [
      ...describeCommits(messages),
      "## Automated pull request",
      "",
      "Decionis Bot opened this pull request for " +
        quote +
        safeBranch +
        quote +
        " because " +
        reason +
        ".",
      "",
      "- Existing commit authorship is unchanged.",
      "- The target branch is " + quote + this.defaultBranch + quote + ".",
      "- A CODEOWNER review from @" + this.expectedAuthorLogin + " is required before merge.",
      "",
      "The bot only opens pull requests; it cannot push commits or approve reviews.",
    ].join("\n");
  }
}

export function titleFromMessage(message, branch) {
  const headline = message?.split("\n")[0]?.trim() || "Changes from " + branch;
  return headline.length <= maxTitleLength
    ? headline
    : headline.slice(0, maxTitleLength - 3) + "...";
}

/** Trailers belong to the commit, not to a description a person reads. */
const trailerPattern = /^[a-z][\w-]*:\s/i;

/**
 * One commit's description: its body, with the subject line and the trailers
 * removed. A commit whose body is only trailers has no description, and
 * nothing is invented for it.
 */
export function descriptionFromMessage(message) {
  const lines = typeof message === "string" ? message.split("\n") : [];
  const body = lines
    .slice(1)
    .filter((line) => !trailerPattern.test(line.trim()))
    .join("\n")
    .trim();
  return body.length > maxDescriptionBytes
    ? body.slice(0, maxDescriptionBytes) + "\n\n[truncated]"
    : body;
}

/**
 * What the change is, from the commits ahead of the default branch. One
 * commit contributes its own description; several contribute a list of their
 * subjects followed by the newest description, which is the one that
 * summarises the branch in this repository's workflow.
 */
export function describeCommits(messages = []) {
  const present = messages.filter(
    (message) => typeof message === "string" && message.trim() !== "",
  );
  if (present.length === 0) return [];
  const subjects = present.map((message) => message.split("\n")[0].trim());
  const description = descriptionFromMessage(present.at(-1));
  const sections = [];
  if (present.length > 1) {
    sections.push("## Commits", "", ...subjects.map((subject) => "- " + subject), "");
  }
  if (description !== "") sections.push("## What changed", "", description, "");
  return sections.length === 0 ? [] : [...sections, "---", ""];
}

async function main() {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath) throw new Error("GITHUB_EVENT_PATH is required");
  const event = JSON.parse(await readFile(eventPath, "utf8"));
  const api = new GitHubApiClient({ token: process.env.GITHUB_TOKEN });
  const bot = new PullRequestBot({
    api,
    repository: process.env.GITHUB_REPOSITORY,
    expectedAuthorLogin: process.env.EXPECTED_AUTHOR_LOGIN,
    defaultBranch: process.env.DEFAULT_BRANCH,
  });
  const outcomes = await bot.run(process.env.GITHUB_EVENT_NAME, event);
  for (const outcome of outcomes) {
    process.stdout.write(JSON.stringify(outcome) + "\n");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write((error instanceof Error ? error.message : "PR bot failed") + "\n");
    process.exitCode = 1;
  });
}
