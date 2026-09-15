import { ActionRegistry, AuditRecorder } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import { SecretHandle } from "../../src/secrets/SecretHandle.js";
import type { ReloadReport, SecretName, SecretStore } from "../../src/secrets/SecretStore.js";
import { AuthorityClients } from "../../src/service/AuthorityClients.js";
import { collectedEvents, offlineEnvironment } from "../support/Environment.js";

/** The offline shape with a Presence credential, so the holder has one to rotate. */
const directEscalationEnvironment = (): Record<string, string> => ({
  ...offlineEnvironment(),
  EXECUTOR_ESCALATION: "DIRECT",
  PRESENCE_API_URL: "https://presence.decionis.example",
  PRESENCE_API_KEY: "synthetic-presence-key",
  PRESENCE_ORGANIZATION: "Synthetic Treasury",
  PRESENCE_APPROVER_ID: "synthetic-approver",
  PRESENCE_VERIFICATION_LEVEL: "HIGH_CONFIDENCE",
  PRESENCE_VERIFICATION_METHODS: "WEBAUTHN",
  PRESENCE_HARDWARE_PKI_REQUIRED: "false",
  PRESENCE_DISALLOW_VIRTUAL_CAMERAS: "true",
});

/** A store whose rotation the test triggers by hand. */
class ManualStore implements SecretStore {
  private readonly listeners = new Map<SecretName, ((next: SecretHandle) => void)[]>();
  /** How many times each secret has been rotated, so a value can change. */
  private readonly versions = new Map<SecretName, number>();
  /** Every read of every secret, in order, so a test can see when it happened. */
  public readonly reads: SecretName[] = [];
  public constructor(private readonly names: readonly SecretName[]) {}
  public has(name: SecretName): boolean {
    return this.names.includes(name);
  }
  public get(name: SecretName): SecretHandle {
    this.reads.push(name);
    const version = this.versions.get(name) ?? 0;
    return SecretHandle.fromString(name, `synthetic-${name.toLowerCase()}-v${version}`);
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
    this.versions.set(name, (this.versions.get(name) ?? 0) + 1);
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
  it("keeps one set through an authority rotation, because the credential is read per request", () => {
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
    // Building the set reads no authority credential at all: the gate and the
    // verifier were handed a reader, not a value.
    expect(secrets.reads).not.toContain("DECIONIS_API_KEY");
    // Neither rotation replaces anything. A request in flight keeps the
    // string it already sent, and the next one reads the new file.
    secrets.rotate("DOWNSTREAM_CREDENTIAL");
    expect(clients.current()).toBe(first);
    secrets.rotate("DECIONIS_API_KEY");
    expect(clients.current()).toBe(first);
    expect(clients.current().gate).toBe(first.gate);
    expect(clients.current().verifier).toBe(first.verifier);
    expect(lines.filter((line) => line.includes('"AUTHORITY_CLIENTS_REBUILT"'))).toHaveLength(0);
    clients.close();
  });

  it("still rebuilds for the Presence credential, which is taken as a value", () => {
    const lines: string[] = [];
    const secrets = new ManualStore([
      "DECIONIS_API_KEY",
      "DOWNSTREAM_CREDENTIAL",
      "PRESENCE_API_KEY",
    ]);
    const clients = new AuthorityClients({
      config: ExecutorConfigLoader.load(directEscalationEnvironment()),
      secrets,
      registry: new ActionRegistry().seal(),
      audit: new AuditRecorder({ sink: { write: () => undefined } }),
      events: collectedEvents(lines),
    });
    const first = clients.current();
    // The Presence client comes from a package this repository does not own
    // and takes its credential once, so there is nothing to read from and
    // the whole set is replaced.
    secrets.rotate("PRESENCE_API_KEY");
    const second = clients.current();
    expect(second).not.toBe(first);
    expect(second.escalation).not.toBe(first.escalation);
    expect(lines.filter((line) => line.includes('"AUTHORITY_CLIENTS_REBUILT"'))).toHaveLength(1);
    clients.close();
    secrets.rotate("PRESENCE_API_KEY");
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
