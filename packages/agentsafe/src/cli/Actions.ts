import { resolve } from "node:path";
import {
  ActionManifest,
  ActionManifestError,
  ActionRegistry,
  ApiProfiles,
  McpProfileError,
  McpToolProfile,
  type ActionAnnotation,
  type ActionManifestEntry,
} from "@decionis/agent-safe-pipeline";
import { bankingHandlers } from "../adapters/banking/BankingHandlers.js";
import { registeredActionNames } from "../adapters/banking/BankingAdapter.js";
import { REGISTERED_ACTIONS } from "../adapters/banking/EffectProjections.js";
import { CARD_EFFECT_TYPE } from "../adapters/cards/CardEffect.js";
import { cardHandlers } from "../adapters/cards/CardHandlers.js";
import { EffectEvidenceRegister } from "../adapters/EffectEvidenceRegister.js";
import { HttpParametersSchema } from "../gateway/ForwardHandler.js";
import { forwardRequestHandlers } from "../handlers/ForwardRequestHandler.js";
import type { HandlerRegistration } from "../handlers/HandlerRegistration.js";
import { ArgumentError, optionValues, parseArguments, type ParsedArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";

export const ACTIONS_COMMANDS = ["manifest"] as const;

const SPEC = { valued: ["family", "api", "mcp"], flags: ["digest"] } as const;

interface Family {
  readonly registration: () => HandlerRegistration;
  readonly annotate: (action: string) => ActionAnnotation;
}

/**
 * The families this build registers in code, each with what its registry
 * cannot say: the target scope its intents name (the transport target the
 * family derives from the action, never the agent's, with each placeholder a
 * path into the parameters) and the effect it produces. A banking target's
 * type is written in lower case. The forwarding handler's target is whatever
 * the proposal names, so it has no template and no effect type of its own.
 */
const FAMILIES: Readonly<Record<string, Family>> = {
  forward: {
    registration: forwardRequestHandlers,
    annotate: () => ({ targets: [], effectType: null }),
  },
  banking: {
    registration: bankingHandlers,
    annotate: (action) => ({
      targets: ["{target.type}:{target.ref}"],
      effectType: REGISTERED_ACTIONS[registeredActionNames().indexOf(action)]?.effectType ?? null,
    }),
  },
  cards: {
    registration: cardHandlers,
    annotate: () => ({ targets: ["card:{cardTokenRef}"], effectType: CARD_EFFECT_TYPE }),
  },
};

/**
 * `agentsafe actions manifest` writes the action space this build can run as
 * one `agent-safe.actions/1` document: the families it registers in code
 * (`--family`), the writes of the API profiles it ships (`--api`), and the
 * tools of MCP profile files (`--mcp`), each source named as often as it is
 * needed. A Decionis policy release is held to it: a manifest action that no
 * rule but the default matches is refused before release. `--digest` prints
 * the document's digest instead, which is what the signed release manifest
 * records.
 */
export function runActions(io: CliProcess, argv: readonly string[]): void {
  const refuse = (event: Record<string, unknown>): void => {
    io.stderr(`${JSON.stringify(event)}\n`);
    io.exit(2);
  };
  if (argv[0] !== "manifest") {
    refuse({ event: "ACTIONS_COMMAND_REQUIRED", commands: ACTIONS_COMMANDS });
    return;
  }
  let parsed: ParsedArguments;
  try {
    parsed = parseArguments(argv.slice(1), SPEC);
    if (parsed.positionals.length > 0)
      throw new ArgumentError("VALUE_INVALID", parsed.positionals[0]!);
  } catch (error) {
    refuse({
      event: "ACTIONS_ARGUMENTS_INVALID",
      detail: error instanceof ArgumentError ? error.message : "invalid arguments",
    });
    return;
  }
  const families = optionValues(parsed, "family");
  const apis = optionValues(parsed, "api");
  const mcps = optionValues(parsed, "mcp");
  if (families.length + apis.length + mcps.length === 0) {
    refuse({
      event: "ACTIONS_SOURCE_REQUIRED",
      detail: "--family forward|banking|cards, --api <profile id> or --mcp <file>",
    });
    return;
  }
  const entries: ActionManifestEntry[] = [];
  for (const name of families) {
    const family = Object.hasOwn(FAMILIES, name) ? FAMILIES[name] : undefined;
    if (family === undefined) {
      refuse({ event: "ACTIONS_FAMILY_UNKNOWN", family: name, families: Object.keys(FAMILIES) });
      return;
    }
    entries.push(...ActionManifest.fromRegistry(registered(family), name, family.annotate));
  }
  for (const id of apis) {
    const profile = ApiProfiles.get(id);
    if (profile === null) {
      refuse({ event: "PROFILE_UNKNOWN", profile: id, profiles: ApiProfiles.ids() });
      return;
    }
    entries.push(...ActionManifest.fromApiProfile(profile, HttpParametersSchema));
  }
  for (const file of mcps) {
    const text = io.files.read(resolve(io.cwd, file));
    if (text === null) {
      refuse({ event: "MCP_PROFILE_UNREADABLE", file });
      return;
    }
    try {
      entries.push(...ActionManifest.fromMcpProfile(McpToolProfile.parse(JSON.parse(text))));
    } catch (error) {
      refuse({
        event: "MCP_PROFILE_INVALID",
        file,
        detail: error instanceof McpProfileError ? error.detail : "not JSON",
      });
      return;
    }
  }
  try {
    const document = ActionManifest.document(entries);
    io.stdout(
      parsed.options.has("digest")
        ? `${JSON.stringify({
            manifest: document.manifest,
            digest: ActionManifest.digest(document),
            actions: document.actions.length,
          })}\n`
        : `${JSON.stringify(document, null, 2)}\n`,
    );
  } catch (error) {
    // Every entry was built from a validated source, so what is left is two
    // sources producing one action, or more actions than one manifest lists.
    if (!(error instanceof ActionManifestError)) throw error;
    refuse({ event: error.code, detail: error.detail });
  }
}

/**
 * A family's sealed registry, filled by its own registration: the actions and
 * schemas are exactly what an executor running the family admits against. A
 * registration only builds handlers, and nothing it is handed is used before a
 * dispatch, which a manifest never makes; so the downstream, credential and
 * fetch here are inert, and refuse if anything ever did call them.
 */
function registered(family: Family): ActionRegistry {
  const registry = new ActionRegistry();
  const inert = (): Promise<never> => Promise.reject(new Error("MANIFEST_DOES_NOT_DISPATCH"));
  family.registration()({
    registry,
    downstream: {
      url: "http://127.0.0.1/",
      lookupUrl: null,
      system: "manifest",
      operation: "describe",
      environment: "manifest",
      credential: { kind: "STATIC_HEADER", header: "authorization" },
      redactedHeaders: [],
      timeoutMs: 1000,
    },
    credential: { kind: "STATIC_HEADER", headersFor: inert },
    fetch: inert,
    effects: new EffectEvidenceRegister(),
    banking: {
      adapterId: "manifest",
      adapterVersion: "0",
      onEffectMismatch: "ALERT",
      lookupByReferenceUrl: null,
    },
  });
  return registry.seal();
}
