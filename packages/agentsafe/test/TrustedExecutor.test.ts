import { JsonObjectSchema } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { ExecutorConfigLoader } from "../src/config/ExecutorConfig.js";
import type { HandlerRegistration } from "../src/handlers/HandlerRegistration.js";
import { createTrustedExecutor } from "../src/TrustedExecutor.js";
import { LOOPBACK_ORIGIN, offlineEnvironment } from "./support/Environment.js";

describe("createTrustedExecutor", () => {
  it("seals the adopter's handlers behind the listener and reports them on /ready", async () => {
    const handlers: HandlerRegistration = ({ registry }) => {
      registry.register("custom_action", { parametersSchema: JsonObjectSchema, execute: () => 1 });
      return ["custom_action"];
    };
    const executor = await createTrustedExecutor({
      config: ExecutorConfigLoader.load(offlineEnvironment()),
      handlers,
      dependencies: { emit: () => undefined },
    });
    expect(executor.service.actions).toEqual(["custom_action"]);
    const address = await executor.listen(0, "127.0.0.1");
    const ready = await fetch(`${LOOPBACK_ORIGIN}:${address.port}/ready`);
    expect(await ready.json()).toEqual({
      status: "ready",
      mode: "ENFORCEMENT",
      escalation: "NONE",
      actions: ["custom_action"],
    });
    await executor.close();
  });

  it("defaults to the reference forwarding handler", async () => {
    const executor = await createTrustedExecutor({
      config: ExecutorConfigLoader.load(offlineEnvironment()),
    });
    expect(executor.service.actions).toEqual(["forward_request"]);
  });
});
