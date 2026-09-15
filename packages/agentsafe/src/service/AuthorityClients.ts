import {
  DecionisGate,
  DecionisGrantVerifier,
  SafeExecutor,
  ShadowPipeline,
  type ActionRegistry,
  type AuditRecorder,
  type AuthorizationVerifier,
  type PresenceApprovalClient,
} from "@decionis/agent-safe-pipeline";
import { EffectAwareGrantVerifier } from "../adapters/EffectAwareGrantVerifier.js";
import type { EffectEvidenceRegister } from "../adapters/EffectEvidenceRegister.js";
import type { ExecutorConfig } from "../config/ExecutorConfig.js";
import type { FetchLike } from "../handlers/HandlerRegistration.js";
import type { SecurityEvents } from "../incident/SecurityEvents.js";
import type { SecretName, SecretStore } from "../secrets/SecretStore.js";
import { EscalationResolver } from "./EscalationResolver.js";

/** Everything that holds an authority or Presence credential, built together. */
export interface AuthorityClientSet {
  readonly gate: DecionisGate;
  readonly verifier: AuthorizationVerifier;
  readonly executor: SafeExecutor;
  readonly escalation: EscalationResolver;
  readonly shadow: ShadowPipeline | null;
}

export interface AuthorityClientsOptions {
  readonly config: ExecutorConfig;
  readonly secrets: SecretStore;
  readonly registry: ActionRegistry;
  readonly audit: AuditRecorder;
  readonly events: SecurityEvents;
  readonly fetch?: FetchLike;
  readonly presence?: PresenceApprovalClient;
  /** The effect observations a handler registered, for the verifier to finalize with. */
  readonly effects?: EffectEvidenceRegister;
  readonly observer?: { readonly id: string; readonly version: string };
}

const ROTATING: readonly SecretName[] = ["DECIONIS_API_KEY", "PRESENCE_API_KEY"];

/**
 * The gate, the verifier, the executor around them, the escalation resolver
 * and the shadow pipeline take their credential once, at construction. This
 * holder builds them as one set and rebuilds the whole set when the
 * authority or Presence credential rotates, so a request in flight keeps the
 * set it started with and the next request gets the new one. The registry
 * and the audit recorder are shared: they hold no credential.
 */
export class AuthorityClients {
  private set: AuthorityClientSet;
  private readonly unsubscribe: (() => void)[] = [];

  public constructor(private readonly options: AuthorityClientsOptions) {
    this.set = AuthorityClients.build(options);
    for (const name of ROTATING) {
      if (!options.secrets.has(name)) continue;
      this.unsubscribe.push(
        options.secrets.onRotate(name, () => {
          this.set = AuthorityClients.build(this.options);
          options.events.emit({ event: "AUTHORITY_CLIENTS_REBUILT", name });
        }),
      );
    }
  }

  public current(): AuthorityClientSet {
    return this.set;
  }

  public close(): void {
    for (const stop of this.unsubscribe) stop();
    this.unsubscribe.length = 0;
  }

  private static build(options: AuthorityClientsOptions): AuthorityClientSet {
    const { config, secrets, registry, audit } = options;
    const authority = {
      baseUrl: config.authority.baseUrl,
      apiKey: secrets.get("DECIONIS_API_KEY").use((value) => value.toString("utf8")),
      allowInsecureLoopback: config.authority.allowInsecureLoopback,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    };
    const gate = new DecionisGate({ ...authority, mode: config.mode });
    const grantVerifier = new DecionisGrantVerifier(authority);
    // The verifier the executor runs finalizes with whatever the handler
    // observed; without an effect plane it is the grant verifier itself.
    const verifier =
      options.effects === undefined
        ? grantVerifier
        : new EffectAwareGrantVerifier({
            verifier: grantVerifier,
            register: options.effects,
            observer: options.observer ?? { id: "agentsafe", version: "0.1.0" },
          });
    const presenceApiKey =
      config.escalation.mode === "DIRECT"
        ? secrets.get("PRESENCE_API_KEY").use((value) => value.toString("utf8"))
        : null;
    const escalation = new EscalationResolver(
      config.escalation,
      gate,
      audit,
      {
        ...(options.presence === undefined ? {} : { presence: options.presence }),
        ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
      },
      presenceApiKey,
    );
    return {
      gate,
      verifier,
      executor: new SafeExecutor(registry, verifier, audit),
      escalation,
      shadow: config.mode === "SHADOW" ? new ShadowPipeline(gate, { audit }) : null,
    };
  }
}
