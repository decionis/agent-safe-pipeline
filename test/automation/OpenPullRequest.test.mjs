import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  GitHubApiClient,
  GitHubApiError,
  PullRequestBot,
  titleFromMessage,
} from "../../scripts/OpenPullRequest.mjs";

class FakeApiClient {
  constructor(handler) {
    this.handler = handler;
    this.calls = [];
  }

  async request(method, path, options = {}) {
    const call = { method, path, options };
    this.calls.push(call);
    return this.handler(call);
  }

  async paginate(path, query = {}) {
    return this.request("PAGINATE", path, { query });
  }
}

const repository = "decionis/agent-safe-pipeline";
const expectedAuthorLogin = "ocularminds";
const defaultBranch = "master";

function createBot(handler) {
  const api = new FakeApiClient(handler);
  return {
    api,
    bot: new PullRequestBot({
      api,
      repository,
      expectedAuthorLogin,
      defaultBranch,
    }),
  };
}

function comparison(authors = [expectedAuthorLogin]) {
  return {
    ahead_by: authors.length,
    total_commits: authors.length,
    commits: authors.map((login, index) => ({
      author: login === null ? null : { login },
      commit: { message: index === authors.length - 1 ? "Add governed change" : "Earlier change" },
    })),
  };
}

describe("PullRequestBot", () => {
  it("opens a PR when a trusted creation run proves the branch creator", async () => {
    const { api, bot } = createBot(({ method, path }) => {
      if (path.endsWith("/pulls") && method === "GET") return [];
      if (path.includes("/compare/")) return comparison(["someone-else"]);
      if (path.endsWith("/actions/runs/42")) {
        return {
          event: "create",
          head_branch: "feature/owned",
          actor: { login: expectedAuthorLogin },
          repository: { full_name: repository },
          path: ".github/workflows/BranchCandidate.yml",
        };
      }
      if (path.endsWith("/pulls") && method === "POST") {
        return { html_url: "https://github.com/decionis/agent-safe-pipeline/pull/99" };
      }
      throw new Error("Unexpected request: " + method + " " + path);
    });

    const outcomes = await bot.run("workflow_dispatch", {
      inputs: { branch: "feature/owned", creation_run_id: "42" },
    });

    assert.equal(outcomes[0].status, "created");
    const createCall = api.calls.find(({ method }) => method === "POST");
    assert.equal(createCall.options.body.head, "feature/owned");
    assert.match(createCall.options.body.body, /branch creation was attributed to @ocularminds/);
  });

  it("opens a PR when every compared commit belongs to the expected author", async () => {
    const { bot } = createBot(({ method, path }) => {
      if (method === "PAGINATE") return [{ name: defaultBranch }, { name: "fix/owned" }];
      if (path.endsWith("/pulls") && method === "GET") return [];
      if (path.includes("/compare/")) return comparison();
      if (path.endsWith("/actions/runs")) return { workflow_runs: [] };
      if (path.endsWith("/pulls") && method === "POST") {
        return { html_url: "https://github.com/decionis/agent-safe-pipeline/pull/100" };
      }
      throw new Error("Unexpected request: " + method + " " + path);
    });

    const outcomes = await bot.run("schedule", {});

    assert.equal(outcomes.length, 1);
    assert.equal(outcomes[0].status, "created");
    assert.match(outcomes[0].reason, /every commit ahead of master/);
  });

  it("fails closed when neither creator nor every commit is trusted", async () => {
    const { bot } = createBot(({ method, path }) => {
      if (path.endsWith("/pulls") && method === "GET") return [];
      if (path.includes("/compare/")) return comparison([expectedAuthorLogin, "someone-else"]);
      if (path.endsWith("/actions/runs")) return { workflow_runs: [] };
      throw new Error("Unexpected request: " + method + " " + path);
    });

    const outcomes = await bot.run("workflow_dispatch", {
      inputs: { branch: "feature/mixed" },
    });

    assert.deepEqual(outcomes[0], {
      branch: "feature/mixed",
      status: "skipped",
      reason: "untrusted-branch-and-commit-authors",
    });
  });

  it("does not create a duplicate pull request", async () => {
    const { api, bot } = createBot(({ method, path }) => {
      if (path.endsWith("/pulls") && method === "GET") {
        return [{ html_url: "https://github.com/decionis/agent-safe-pipeline/pull/24" }];
      }
      throw new Error("Unexpected request: " + method + " " + path);
    });

    const outcomes = await bot.run("workflow_dispatch", {
      inputs: { branch: "feature/already-open" },
    });

    assert.equal(outcomes[0].reason, "pull-request-exists");
    assert.equal(
      api.calls.some(({ method }) => method === "POST"),
      false,
    );
  });

  it("fails closed when GitHub returns an incomplete comparison", async () => {
    const { bot } = createBot(({ method, path }) => {
      if (path.endsWith("/pulls") && method === "GET") return [];
      if (path.includes("/compare/")) return { ...comparison(), total_commits: 2 };
      throw new Error("Unexpected request: " + method + " " + path);
    });

    const outcomes = await bot.run("workflow_dispatch", {
      inputs: { branch: "feature/too-large" },
    });

    assert.equal(outcomes[0].reason, "incomplete-commit-comparison");
  });
});

describe("titleFromMessage", () => {
  it("uses only the first line and bounds the PR title", () => {
    const title = titleFromMessage("x".repeat(80) + "\nbody", "feature/long");
    assert.equal(title.length, 72);
    assert.equal(title.endsWith("..."), true);
  });
});

describe("GitHubApiClient", () => {
  it("clamps timeout and retry controls", () => {
    const api = new GitHubApiClient({
      token: "x",
      timeoutMs: 60_000,
      maxAttempts: 20,
    });

    assert.equal(api.timeoutMs, 15_000);
    assert.equal(api.maxAttempts, 3);
    assert.throws(
      () => new GitHubApiClient({ token: "x", timeoutMs: Number.POSITIVE_INFINITY }),
      /timeoutMs must be a positive safe integer/,
    );
  });

  it("does not read or retain a failed response body", async () => {
    let bodyRead = false;
    const api = new GitHubApiClient({
      token: "x",
      maxAttempts: 1,
      fetchImpl: async () => ({
        ok: false,
        status: 403,
        get body() {
          bodyRead = true;
          throw new Error("body must remain unread");
        },
      }),
    });

    await assert.rejects(api.request("GET", "/repos/example/project"), (error) => {
      assert.equal(error instanceof GitHubApiError, true);
      assert.equal(error.status, 403);
      assert.equal("responseBody" in error, false);
      return true;
    });
    assert.equal(bodyRead, false);
  });
});
