import { JsonObjectSchema } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { ExecutorConfigLoader } from "../src/config/ExecutorConfig.js";
import type { HandlerRegistration } from "../src/handlers/HandlerRegistration.js";
import { HostPosture } from "../src/posture/HostPosture.js";
import type { PostureFacts } from "../src/posture/PostureChecks.js";
import { createTrustedExecutor } from "../src/TrustedExecutor.js";
import {
  collectedEvents,
  LOOPBACK_ORIGIN,
  offlineEnvironment,
  openSecrets,
} from "./support/Environment.js";

describe("createTrustedExecutor", () => {
  it("seals the adopter's handlers behind the listener and reports them on /ready", async () => {
    const handlers: HandlerRegistration = ({ registry }) => {
      registry.register("custom_action", { parametersSchema: JsonObjectSchema, execute: () => 1 });
      return ["custom_action"];
    };
    const config = ExecutorConfigLoader.load(offlineEnvironment());
    const secrets = openSecrets(offlineEnvironment(), config);
    const executor = await createTrustedExecutor({
      config,
      secrets,
      handlers,
      dependencies: { emit: () => undefined, security: collectedEvents() },
    });
    expect(executor.service.actions).toEqual(["custom_action"]);
    expect(executor.posture.mode).toBe("DEVELOPMENT");
    expect(executor.posture.failed).toEqual([]);
    const address = await executor.listen(0, "127.0.0.1");
    const ready = await fetch(`${LOOPBACK_ORIGIN}:${address.port}/ready`);
    expect(await ready.json()).toEqual({
      status: "ready",
      mode: "ENFORCEMENT",
      escalation: "NONE",
      actions: ["custom_action"],
    });
    await executor.close();
    expect(secrets.get("EXECUTOR_CALLER_TOKEN").disposed).toBe(true);
  });

  it("defaults to the reference forwarding handler and the process streams", async () => {
    const config = ExecutorConfigLoader.load(offlineEnvironment());
    const executor = await createTrustedExecutor({
      config,
      secrets: openSecrets(offlineEnvironment(), config),
    });
    expect(executor.service.actions).toEqual(["forward_request"]);
    await executor.close();
  });

  it("verifies an injected posture before anything else and refuses to assemble on a failure", async () => {
    const env = offlineEnvironment();
    delete env["EXECUTOR_POSTURE"];
    const config = ExecutorConfigLoader.load(env);
    const facts = (euid: number): PostureFacts => ({
      euid,
      egid: 65532,
      cwd: "/app",
      writable: () => false,
      fileStat: () => null,
      realpath: (path) => path,
      inspectorActive: () => false,
      permission: () => ({ active: true, has: () => false }),
    });
    const settings = { ...config.posture, environment: { NODE_ENV: "production" } };
    const rooted = new HostPosture(
      { mode: "ENFORCED", intervalSeconds: 60, config: settings, facts: facts(0) },
      collectedEvents(),
    );
    await expect(
      createTrustedExecutor({
        config,
        secrets: openSecrets(env, config),
        dependencies: { posture: rooted, emit: () => undefined, security: collectedEvents() },
      }),
    ).rejects.toThrow("POSTURE_ROOT_UID");
    const hardened = new HostPosture(
      { mode: "ENFORCED", intervalSeconds: 60, config: settings, facts: facts(65532) },
      collectedEvents(),
    );
    const executor = await createTrustedExecutor({
      config,
      secrets: openSecrets(env, config),
      dependencies: { posture: hardened, emit: () => undefined, security: collectedEvents() },
    });
    expect(executor.posture.mode).toBe("ENFORCED");
    expect(executor.posture.waived).toEqual([]);
    await executor.close();
  });
});
