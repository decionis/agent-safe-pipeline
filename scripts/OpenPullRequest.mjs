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
const branchCreationWorkflow = ".github/workflows/PullRequestBot.yml";

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
        if (response.ok) return await readBoundedJsonResponse(response);

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
    const latestCommit = comparison.commits.at(-1);
    const title = titleFromMessage(latestCommit?.commit?.message, branch);
    const pullRequest = await this.api.request("POST", "/repos/" + this.repository + "/pulls", {
      body: {
        title,
        head: branch,
        base: this.defaultBranch,
        body: this.buildBody(branch, reason),
        draft: false,
        maintainer_can_modify: true,
      },
    });
    return { branch, status: "created", reason, url: pullRequest.html_url };
  }

  async findExistingPullRequest(branch) {
    const pulls = await this.api.request("GET", "/repos/" + this.repository + "/pulls", {
      query: {
        state: "all",
        head: this.owner + ":" + branch,
        base: this.defaultBranch,
        per_page: perPage,
      },
    });
    if (!Array.isArray(pulls)) throw new Error("Expected pull request list");
    return pulls[0];
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
      throw error;
    }
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

  buildBody(branch, reason) {
    const quote = String.fromCharCode(96);
    const safeBranch = branch.replaceAll(quote, "\\" + quote);
    return [
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
  return headline.length <= 72 ? headline : headline.slice(0, 69) + "...";
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
