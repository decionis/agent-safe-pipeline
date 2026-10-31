import {
  ActionManifest,
  type ActionManifestDocument,
  type ActionManifestEntry,
} from "@decionis/agent-safe-pipeline";
import { HttpParametersSchema } from "./ForwardHandler.js";
import type { RouteTable } from "./RouteTable.js";

/** The family name a gateway's own route actions go by in an action manifest. */
export const GATEWAY_FAMILY = "gateway";

/**
 * The action space a gateway with this route table loads, as one
 * `agent-safe.actions/1` document: what `agentsafe actions manifest --gateway`
 * writes for the same configuration, and what the gateway's fingerprint
 * digests. The profile's writes are described exactly as `--api <profile>`
 * describes them, so a release held to that manifest matches a gateway that
 * governs by the profile alone. Every other action a row governs (an explicit
 * route's, or the derived `http.<method>` of the rest) is one entry of the
 * gateway's own family, admitted against the HTTP parameters and naming each
 * method and path that produces it. A route that names one of the profile's
 * actions adds no entry: the action is the unit a release covers.
 */
export function gatewayManifest(routes: RouteTable): ActionManifestDocument {
  const profile = routes.profile;
  const entries: ActionManifestEntry[] =
    profile === null ? [] : ActionManifest.fromApiProfile(profile, HttpParametersSchema);
  const described = new Set(entries.map((entry) => entry.action));
  const targets = new Map<string, Set<string>>();
  for (const row of routes.rows()) {
    if (row.action === null || described.has(row.action)) continue;
    const named = targets.get(row.action) ?? new Set<string>();
    for (const method of row.methods) named.add(`${method} ${row.path}`);
    targets.set(row.action, named);
  }
  const parameters = ActionManifest.parametersJsonSchema(HttpParametersSchema);
  for (const [action, named] of targets) {
    entries.push({
      action,
      source: { kind: "registry", family: GATEWAY_FAMILY },
      parameters,
      targets: [...named].sort(),
      effect_type: null,
    });
  }
  return ActionManifest.document(entries);
}
