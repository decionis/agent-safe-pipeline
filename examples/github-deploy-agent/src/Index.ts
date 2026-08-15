import {
  ActionRegistry,
  IntentCapture,
  SafeExecutor,
  createFixtureAuthorityPair,
  type AgentProposal,
} from "@decionis/agent-safe-pipeline";
import { z } from "zod";

const capture = new IntentCapture();
const { authority, verifier } = createFixtureAuthorityPair(
  (captured) => {
    if (captured.intent.action === "force_push") return "BLOCK";
    return captured.intent.parameters.environment === "staging" ? "ALLOW" : "ESCALATE";
  },
  { unsafeAllowDevelopmentFixture: true },
);
const registry = new ActionRegistry()
  .register("deploy", {
    parametersSchema: z
      .object({ environment: z.enum(["staging", "production"]), ref: z.string() })
      .strict(),
    execute: ({ parameters }) => ({ dispatched: true, ...parameters }),
  })
  .register("force_push", {
    parametersSchema: z.object({ branch: z.string() }).strict(),
    execute: ({ parameters }) => ({ pushed: parameters.branch }),
  })
  .seal();
const executor = new SafeExecutor(registry, verifier);

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
for (const [index, proposal] of proposals.entries()) {
  const captured = capture.capture(proposal, {
    tenantId: "00000000-0000-4000-8000-000000000003",
    actor: { id: "synthetic-deploy-agent", type: "AI_AGENT" },
    downstreamTarget: { system: "github", operation: proposal.action },
    idempotencyKey: `github-example-${index}`,
    context: { repository: "decionis/example" },
  });
  const decision = await authority.evaluate(captured);
  results.push({
    action: proposal.action,
    environment: proposal.parameters.environment,
    decision: decision.verdict,
    execution: await executor.run(captured, decision),
  });
}

process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
