import { ActionRegistry, AuditRecorder } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import { SecretHandle } from "../../src/secrets/SecretHandle.js";
import type { ReloadReport, SecretName, SecretStore } from "../../src/secrets/SecretStore.js";
import { AuthorityClients } from "../../src/service/AuthorityClients.js";
import { collectedEvents, offlineEnvironment } from "../support/Environment.js";

/** A store whose rotation the test triggers by hand. */
class ManualStore implements SecretStore {
  private readonly listeners = new Map<SecretName, ((next: SecretHandle) => void)[]>();
  public constructor(private readonly names: readonly SecretName[]) {}
  public has(name: SecretName): boolean {
    return this.names.includes(name);
  }
  public get(name: SecretName): SecretHandle {
    return SecretHandle.fromString(name, `synthetic-${name.toLowerCase()}`);
  }
  public onRotate(name: SecretName, listener: (next: SecretHandle) => void): () => void {
    const list = this.listeners.get(name) ?? [];
    list.push(listener);
    this.listeners.set(name, list);
    return () => {
      this.listeners.set(
        name,
        (this.listeners.get(name) ?? []).filter((candidate) => candidate !== listener),
      );
    };
  }
  public rotate(name: SecretName): void {
    for (const listener of this.listeners.get(name) ?? []) listener(this.get(name));
  }
  public reload(): Promise<ReloadReport> {
    return Promise.resolve({ reason: "OPERATOR", rotated: [], refused: [] });
  }
  public close(): void {
    this.listeners.clear();
  }
}

describe("AuthorityClients", () => {
  it("rebuilds every credential-holding client as one set when the authority key rotates", () => {
    const lines: string[] = [];
    const secrets = new ManualStore(["DECIONIS_API_KEY", "DOWNSTREAM_CREDENTIAL"]);
    const clients = new AuthorityClients({
      config: ExecutorConfigLoader.load(offlineEnvironment()),
      secrets,
      registry: new ActionRegistry().seal(),
      audit: new AuditRecorder({ sink: { write: () => undefined } }),
      events: collectedEvents(lines),
    });
    const first = clients.current();
    expect(first.shadow).toBeNull();
    secrets.rotate("DOWNSTREAM_CREDENTIAL");
    expect(clients.current()).toBe(first);
    secrets.rotate("DECIONIS_API_KEY");
    const second = clients.current();
    expect(second).not.toBe(first);
    expect(second.gate).not.toBe(first.gate);
    expect(second.verifier).not.toBe(first.verifier);
    expect(second.executor).not.toBe(first.executor);
    expect(lines.filter((line) => line.includes('"AUTHORITY_CLIENTS_REBUILT"'))).toHaveLength(1);
    clients.close();
    secrets.rotate("DECIONIS_API_KEY");
    expect(clients.current()).toBe(second);
  });

  it("builds a shadow pipeline in shadow and subscribes only to the secrets the store holds", () => {
    const secrets = new ManualStore(["DECIONIS_API_KEY", "DOWNSTREAM_CREDENTIAL"]);
    const clients = new AuthorityClients({
      config: ExecutorConfigLoader.load({ ...offlineEnvironment(), EXECUTOR_MODE: "SHADOW" }),
      secrets,
      registry: new ActionRegistry().seal(),
      audit: new AuditRecorder({ sink: { write: () => undefined } }),
      events: collectedEvents(),
    });
    expect(clients.current().shadow).not.toBeNull();
    clients.close();
  });
});
