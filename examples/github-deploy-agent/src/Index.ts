import { appendFile } from "node:fs/promises";
import {
  ActionRegistry,
  IntentCapture,
  SafeExecutor,
  createFixtureAuthorityPair,
  createGate,
  printDecision,
  type AgentProposal,
  type GateDecision,
} from "@decionis/agent-safe-pipeline";
import { z } from "zod";

const capture = new IntentCapture();
// With no DECIONIS_API_KEY this is the fixture pair, exactly as before. With
// one, Decionis evaluates the same intents beside it and leaves signed records.
const gate = createGate({
  local: createFixtureAuthorityPair(
    (captured) => {
      if (captured.intent.action === "force_push") return "BLOCK";
      return captured.intent.parameters.environment === "staging" ? "ALLOW" : "ESCALATE";
    },
    { unsafeAllowDevelopmentFixture: true },
  ),
  tenantId: "00000000-0000-4000-8000-000000000003",
  // Client identification on hosted calls only: which example a key was first used from.
  source: { repo: "decionis/agent-safe-pipeline", example: "github-deploy-agent" },
});
const registry = new ActionRegistry()
  .register("deploy", {
    parametersSchema: z
      .object({ environment: z.enum(["staging", "production"]), ref: z.string() })
      .strict(),
    execute: async ({ parameters, dispatch }) =>
      await dispatch.run(async () => ({ dispatched: true, ...parameters })),
  })
  .register("force_push", {
    parametersSchema: z.object({ branch: z.string() }).strict(),
    execute: async ({ parameters, dispatch }) =>
      await dispatch.run(async () => ({ pushed: parameters.branch })),
  })
  .seal();
const executor = new SafeExecutor(registry, gate.verifier);

const proposals: AgentProposal[] = [
  {
    action: "deploy",
    target: "github:decionis/example",
    parameters: { environment: "staging", ref: "abc123" },
  },
  {
    action: "deploy",
    target: "github:decionis/example",
    parameters: { environment: "production", ref: "abc123" },
  },
  { action: "force_push", target: "github:decionis/example:main", parameters: { branch: "main" } },
];
const results = [];
const decisions: Array<{ readonly proposal: AgentProposal; readonly decision: GateDecision }> = [];
for (const [index, proposal] of proposals.entries()) {
  const captured = capture.capture(proposal, {
    tenantId: gate.tenantId,
    actor: { id: "synthetic-deploy-agent", type: "AI_AGENT" },
    downstreamTarget: { system: "github", operation: proposal.action },
    idempotencyKey: `github-example-${index}`,
    context: { repository: "decionis/example" },
  });
  const decision = await gate.authority.evaluate(captured);
  decisions.push({ proposal, decision });
  results.push({
    action: proposal.action,
    environment: proposal.parameters.environment,
    decision: decision.verdict,
    execution: await executor.run(captured, decision),
  });
}

process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);

// Hosted mode only: one block per proposal on the terminal, and the same
// records in the job summary so a reviewer can verify them from the run page.
const summary = process.env["GITHUB_STEP_SUMMARY"];
for (const { proposal, decision } of decisions) {
  if (decision.hosted === undefined) continue;
  process.stdout.write(`${proposal.action} ${JSON.stringify(proposal.parameters)}\n`);
  printDecision(decision);
  if (summary !== undefined && summary !== "" && decision.hosted.dossierId !== null) {
    await appendFile(
      summary,
      `### ${decision.verdict}: ${proposal.action} ${JSON.stringify(proposal.parameters)}\n\n` +
        `Decision Dossier \`${decision.hosted.dossierId}\` (Decionis said ${decision.hosted.verdict}, ${decision.hosted.mode}). ` +
        `Verify it yourself, no account needed: \`pnpm decionis:verify ${decision.hosted.dossierId}\`\n\n`,
    );
  }
}
