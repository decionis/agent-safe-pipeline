import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  compareMaxJsonResponseBytes,
  describeCommits,
  descriptionFromMessage,
  GitHubApiClient,
  GitHubApiError,
  PullRequestBot,
  titleFromMessage,
} from "../../scripts/OpenPullRequest.mjs";
import { defaultMaxJsonResponseBytes } from "../../scripts/BoundedJsonResponse.mjs";

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

function comparison(authors = [expectedAuthorLogin], messages) {
  return {
    ahead_by: authors.length,
    total_commits: authors.length,
    commits: authors.map((login, index) => ({
      author: login === null ? null : { login },
      commit: {
        message:
          messages?.[index] ??
          (index === authors.length - 1 ? "Add governed change" : "Earlier change"),
      },
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
          path: ".github/workflows/PullRequestBot.yml",
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

  it("describes the change from the commit itself, above its own provenance note", async () => {
    const message = [
      "feat(agentsafe): journal every attempt",
      "",
      "Nothing executes without a durable record of the attempt.",
      "",
      "The halt is deliberately easy to reach.",
      "",
      "Signed-off-by: Festus B. Jejelowo <mail.festus@gmail.com>",
    ].join("\n");
    const { api, bot } = createBot(({ method, path }) => {
      if (path.endsWith("/pulls") && method === "GET") return [];
      if (path.includes("/compare/")) return comparison([expectedAuthorLogin], [message]);
      if (path.endsWith("/actions/runs")) return { workflow_runs: [] };
      if (path.endsWith("/pulls") && method === "POST") {
        return { html_url: "https://github.com/decionis/agent-safe-pipeline/pull/102" };
      }
      throw new Error("Unexpected request: " + method + " " + path);
    });

    await bot.run("create", { ref: "feat/described", ref_type: "branch" });

    const { title, body } = api.calls.find(({ method }) => method === "POST").options.body;
    assert.equal(title, "feat(agentsafe): journal every attempt");
    assert.match(body, /^## What changed\n\nNothing executes without a durable record/);
    assert.match(body, /The halt is deliberately easy to reach\./);
    // The description comes first; the bot's note follows it.
    assert.ok(body.indexOf("## What changed") < body.indexOf("## Automated pull request"));
    // A trailer is part of the commit, not of a description a person reads.
    assert.doesNotMatch(body, /Signed-off-by/);
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

  it("evaluates only the branch named by a create event", async () => {
    const { api, bot } = createBot(({ method, path }) => {
      if (path.endsWith("/pulls") && method === "GET") return [];
      if (path.includes("/compare/")) return comparison();
      if (path.endsWith("/actions/runs")) return { workflow_runs: [] };
      if (path.endsWith("/pulls") && method === "POST") {
        return { html_url: "https://github.com/decionis/agent-safe-pipeline/pull/101" };
      }
      throw new Error("Unexpected request: " + method + " " + path);
    });

    const outcomes = await bot.run("create", {
      ref: "feature/direct-create",
      ref_type: "branch",
    });

    assert.equal(outcomes[0].status, "created");
    assert.equal(
      api.calls.some(({ method }) => method === "PAGINATE"),
      false,
    );
    const compareCall = api.calls.find(({ path }) => path.includes("/compare/"));
    assert.match(compareCall.path, /feature%2Fdirect-create$/);
  });

  it("ignores non-branch create events without querying GitHub", async () => {
    const { api, bot } = createBot(() => {
      throw new Error("The API must not be called for a tag create event");
    });

    const outcomes = await bot.run("create", { ref: "v1.0.0", ref_type: "tag" });

    assert.deepEqual(outcomes, [
      { branch: "v1.0.0", status: "skipped", reason: "non-branch-create-event" },
    ]);
    assert.equal(api.calls.length, 0);
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
    const { api, bot } = createBot(({ method, path, options }) => {
      if (path.endsWith("/pulls") && method === "GET") {
        // The lookup asks GitHub for open pull requests only.
        assert.equal(options?.query?.state, "open");
        return [
          { state: "open", html_url: "https://github.com/decionis/agent-safe-pipeline/pull/24" },
        ];
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

  it("opens a pull request for a branch recreated after its earlier pull request was closed", async () => {
    // A closed, unmerged pull request must not block the recreated branch:
    // the open-only lookup returns nothing for it, and the branch is judged
    // on its own commits.
    const { api, bot } = createBot(({ method, path }) => {
      if (path.endsWith("/pulls") && method === "GET") return [];
      if (path.includes("/compare/")) return comparison();
      if (path.includes("/actions/runs")) return { workflow_runs: [] };
      if (path.endsWith("/pulls") && method === "POST") {
        return { html_url: "https://github.com/decionis/agent-safe-pipeline/pull/126" };
      }
      throw new Error("Unexpected request: " + method + " " + path);
    });

    const outcomes = await bot.run("workflow_dispatch", {
      inputs: { branch: "docs/recreated" },
    });

    assert.equal(outcomes[0].status, "created");
    assert.equal(
      api.calls.some(({ method, path }) => method === "POST" && path.endsWith("/pulls")),
      true,
    );
  });

  it("reads the commits ahead from the commit listings when the comparison is too large", async () => {
    const commit = (sha, login, message) => ({ sha, author: { login }, commit: { message } });
    const master = [
      commit("m3", "someone", "third"),
      commit("m2", "someone", "second"),
      commit("m1", "someone", "first"),
    ];
    const branch = [
      commit("b2", expectedAuthorLogin, "feat(govern): the rewrite\n\nOne binary for any runner."),
      commit("b1", expectedAuthorLogin, "chore: prepare"),
      ...master,
    ];
    const { api, bot } = createBot(({ method, path, options }) => {
      if (path.endsWith("/pulls") && method === "GET") return [];
      if (path.includes("/compare/")) throw new Error("GITHUB_API_RESPONSE_TOO_LARGE");
      if (path.endsWith("/commits")) {
        assert.equal(options.query.per_page, 40);
        return options.query.sha === defaultBranch ? master : branch;
      }
      if (path.endsWith("/actions/runs")) return { workflow_runs: [] };
      if (path.endsWith("/pulls") && method === "POST") {
        return { html_url: "https://github.com/decionis/agent-safe-pipeline/pull/237" };
      }
      throw new Error("Unexpected request: " + method + " " + path);
    });

    const outcomes = await bot.run("create", { ref: "feat/large", ref_type: "branch" });

    assert.equal(outcomes[0].status, "created");
    const { title, body } = api.calls.find(({ method }) => method === "POST").options.body;
    assert.equal(title, "feat(govern): the rewrite");
    assert.match(body, /One binary for any runner\./);
    assert.match(body, /every commit ahead of master was attributed to @ocularminds/);
  });

  it("fails closed when the branch's base is beyond the default branch's recent history", async () => {
    const commit = (sha, login) => ({ sha, author: { login }, commit: { message: "x" } });
    const { bot } = createBot(({ method, path, options }) => {
      if (path.endsWith("/pulls") && method === "GET") return [];
      if (path.includes("/compare/")) throw new Error("GITHUB_API_RESPONSE_TOO_LARGE");
      if (path.endsWith("/commits")) {
        if (options.query.sha === defaultBranch) return [commit("m1", "someone")];
        return [commit("b1", expectedAuthorLogin), commit("old", "someone")];
      }
      if (path.endsWith("/actions/runs")) return { workflow_runs: [] };
      throw new Error("Unexpected request: " + method + " " + path);
    });

    const outcomes = await bot.run("create", { ref: "feat/ancient", ref_type: "branch" });

    assert.equal(outcomes[0].status, "skipped");
    assert.equal(outcomes[0].reason, "incomplete-commit-comparison");
  });

  it("still fails on any other error the comparison raises", async () => {
    const { bot } = createBot(({ method, path }) => {
      if (path.endsWith("/pulls") && method === "GET") return [];
      if (path.includes("/compare/")) throw new Error("GITHUB_API_RESPONSE_INVALID");
      throw new Error("Unexpected request: " + method + " " + path);
    });
    await assert.rejects(
      bot.run("create", { ref: "feat/odd", ref_type: "branch" }),
      /GITHUB_API_RESPONSE_INVALID/,
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
    assert.equal(titleFromMessage("x".repeat(72) + "\nbody", "b"), "x".repeat(72));
    assert.equal(titleFromMessage(undefined, "feature/named"), "Changes from feature/named");
    assert.equal(titleFromMessage("   ", "feature/blank"), "Changes from feature/blank");
  });
});

describe("descriptionFromMessage", () => {
  it("is the commit body without its subject or its trailers", () => {
    const message = [
      "feat(scope): the subject",
      "",
      "The first paragraph a reviewer should read.",
      "",
      "The second one.",
      "",
      "Co-Authored-By: Someone <someone@example.com>",
      "Signed-off-by: Someone Else <else@example.com>",
    ].join("\n");
    assert.equal(
      descriptionFromMessage(message),
      "The first paragraph a reviewer should read.\n\nThe second one.",
    );
    // A commit with nothing but a subject, or nothing but trailers after it,
    // has no description, and none is invented.
    assert.equal(descriptionFromMessage("feat: subject only"), "");
    assert.equal(
      descriptionFromMessage("feat: subject\n\nSigned-off-by: Someone <a@example.com>"),
      "",
    );
    assert.equal(descriptionFromMessage(undefined), "");
    // A body that would not fit is cut and says so, rather than being refused.
    const long = descriptionFromMessage("subject\n\n" + "x".repeat(60 * 1024));
    assert.equal(long.endsWith("[truncated]"), true);
    assert.ok(long.length < 50 * 1024);
  });
});

describe("describeCommits", () => {
  it("puts one commit's description in front of the bot's own note", () => {
    const sections = describeCommits(["feat: one\n\nWhat it does."]);
    assert.deepEqual(sections, ["## What changed", "", "What it does.", "", "---", ""]);
  });

  it("lists every subject when a branch carries several commits", () => {
    const sections = describeCommits([
      "fix: the first",
      "feat: the second\n\nWhy the branch exists.",
    ]);
    assert.deepEqual(sections, [
      "## Commits",
      "",
      "- fix: the first",
      "- feat: the second",
      "",
      "## What changed",
      "",
      "Why the branch exists.",
      "",
      "---",
      "",
    ]);
  });

  it("contributes nothing when there is nothing to say", () => {
    assert.deepEqual(describeCommits([]), []);
    assert.deepEqual(describeCommits([undefined, "  "]), []);
    assert.deepEqual(describeCommits(["feat: subject only"]), []);
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

  it("allows larger bounded JSON only for compare responses", async () => {
    const padding = "x".repeat(defaultMaxJsonResponseBytes);
    const api = new GitHubApiClient({
      token: "x",
      maxAttempts: 1,
      fetchImpl: async () => new globalThis.Response(JSON.stringify({ padding })),
    });

    const comparison = await api.request(
      "GET",
      "/repos/example/project/compare/master...feature%2Flarge",
    );
    assert.equal(comparison.padding.length, padding.length);
    await assert.rejects(
      api.request("GET", "/repos/example/project/pulls"),
      /GITHUB_API_RESPONSE_TOO_LARGE/,
    );
  });

  it("keeps compare responses bounded at 512 KiB", async () => {
    const api = new GitHubApiClient({
      token: "x",
      maxAttempts: 1,
      fetchImpl: async () =>
        new globalThis.Response(
          JSON.stringify({ padding: "x".repeat(compareMaxJsonResponseBytes) }),
        ),
    });

    await assert.rejects(
      api.request("GET", "/repos/example/project/compare/master...feature%2Ftoo-large"),
      /GITHUB_API_RESPONSE_TOO_LARGE/,
    );
  });
});
