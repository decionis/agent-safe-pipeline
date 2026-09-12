import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  evaluationPathProblems,
  linkedFiles,
  namedPackages,
  namedScripts,
} from "../../scripts/EvaluationPathChecks.mjs";

const facts = {
  fileExists: (path) => ["OPEN-CORE.md", "docs/shadow-mode.md"].includes(path),
  rootScripts: { verify: "…", "dossiers:check": "…" },
  workspacePackages: new Set(["@decionis/agent-safe-pipeline", "@decionis/commerce"]),
  declaredDependencies: new Set(["@decionis/verify"]),
};

describe("EvaluationPathChecks", () => {
  it("extracts relative links, scripts and packages", () => {
    const document =
      "See [open core](./OPEN-CORE.md) and [shadow](./docs/shadow-mode.md#rollout), run `pnpm verify` and `pnpm dossiers:check`, install `@decionis/agent-safe-pipeline`; [releases](https://github.com/x/y) are external.";
    assert.deepEqual(linkedFiles(document), ["OPEN-CORE.md", "docs/shadow-mode.md"]);
    assert.deepEqual(namedScripts(document), ["verify", "dossiers:check"]);
    assert.deepEqual(namedPackages(document), ["@decionis/agent-safe-pipeline"]);
  });

  it("accepts a consistent document", () => {
    const document =
      "[open core](./OPEN-CORE.md), `pnpm verify`, `@decionis/commerce`, `@decionis/verify`, DOI [`10.5281/zenodo.1`](https://doi.org/10.5281/zenodo.1).";
    assert.deepEqual(evaluationPathProblems({ document, ...facts }), []);
  });

  it("reports a dead link, an unknown script, and an unknown package", () => {
    const document = "[gone](./GONE.md) `pnpm nope` `@decionis/imaginary`";
    const problems = evaluationPathProblems({ document, ...facts });
    assert.equal(problems.length, 3);
    assert.match(problems[0], /GONE\.md/);
    assert.match(problems[1], /pnpm nope/);
    assert.match(problems[2], /@decionis\/imaginary/);
  });

  it("refuses a version literal and a performance figure in prose", () => {
    assert.deepEqual(
      evaluationPathProblems({ document: "The package is at 0.1.4 today.", ...facts }),
      ["carries a version literal in prose: 0.1.4"],
    );
    assert.deepEqual(
      evaluationPathProblems({ document: "Decisions return in 120 ms.", ...facts }),
      ["carries a performance figure: 120 ms"],
    );
    // Inside code spans a version is a command, not a claim.
    assert.deepEqual(
      evaluationPathProblems({ document: "Run `npx @decionis/verify@0.3.0`.", ...facts }),
      [],
    );
  });
});
