import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  assertDependabotCoverage,
  parseDependabotUpdates,
} from "../../scripts/CheckDependabotCoverage.mjs";

const completeConfig = `
version: 2
updates:
  - package-ecosystem: npm
    directory: "/"
    schedule:
      interval: weekly
  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
`;

const inputs = {
  configSource: completeConfig,
  packageDirectories: [".", "examples/demo", "packages/pipeline"],
  workspaceSource: 'packages:\n  - "packages/*"\n  - "examples/*"\n',
  workflowFiles: ["deploy.yml", "supply-chain.yml"],
};

describe("CheckDependabotCoverage", () => {
  it("parses the configured ecosystems and schedules", () => {
    assert.deepEqual(parseDependabotUpdates(completeConfig), [
      { ecosystem: "npm", directory: "/", interval: "weekly" },
      { ecosystem: "github-actions", directory: "/", interval: "weekly" },
    ]);
  });

  it("accepts root coverage for every workspace and workflow", () => {
    assert.deepEqual(assertDependabotCoverage(inputs), {
      packageDirectories: 3,
      workflowFiles: 2,
      workspacePatterns: 2,
    });
  });

  it("rejects missing GitHub Actions coverage", () => {
    assert.throws(
      () =>
        assertDependabotCoverage({
          ...inputs,
          configSource: completeConfig.replace("github-actions", "docker"),
        }),
      /DEPENDABOT_GITHUB-ACTIONS_ENTRY_INVALID/,
    );
  });

  it("rejects a package outside the declared pnpm workspace", () => {
    assert.throws(
      () =>
        assertDependabotCoverage({
          ...inputs,
          packageDirectories: [...inputs.packageDirectories, "tools/untracked"],
        }),
      /PNPM_WORKSPACE_PACKAGE_UNCOVERED:tools\/untracked/,
    );
  });
});
