/**
 * Which of a gateway's routes the authority decides, and which it does not,
 * by kind: what an acceptance report says is in scope before it says what
 * passed. Computed from the configuration alone, as the fingerprint is, so
 * the two describe the same gateway.
 */
import { ApiProfile } from "@decionis/agent-safe-pipeline";
import type { GatewayConfig } from "../gateway/GatewayConfig.js";
import type { RouteTable } from "../gateway/RouteTable.js";
import type { Coverage } from "./AcceptanceReport.js";

/**
 * A governed route is decided in enforcement and fails closed; one that fails
 * open is decided only while the authority answers, and one in shadow is
 * never decided at all, so both are listed as not governed. A governed write
 * says whether its target is read: only then can its effect, or a refusal,
 * be observed there.
 */
export function coverageOf(routes: RouteTable, config: Pick<GatewayConfig, "authority">): Coverage {
  const reads = new Set(
    // Stryker disable next-line ArrayDeclaration: with no profile there is no operation, and a string in its place names no precondition either.
    (routes.profile?.definition.operations ?? [])
      .filter((operation) => !ApiProfile.isRead(operation) && operation.precondition !== undefined)
      .map((operation) => `${operation.method} ${operation.path} ${operation.action}`),
  );
  const coverage: {
    governed: Coverage["governed"][number][];
    ungoverned: Coverage["ungoverned"][number][];
    refused: Coverage["refused"][number][];
  } = { governed: [], ungoverned: [], refused: [] };
  for (const row of routes.rows()) {
    const route = { methods: [...row.methods], path: row.path, action: row.action };
    if (row.disposition === "REFUSE") {
      coverage.refused.push(route);
    } else if (row.disposition === "PASSTHROUGH") {
      coverage.ungoverned.push({ ...route, kind: "PASSTHROUGH" });
    } else if (config.authority.mode === "SHADOW") {
      coverage.ungoverned.push({ ...route, kind: "SHADOW" });
    } else if (config.authority.failurePolicy === "FAIL_OPEN") {
      coverage.ungoverned.push({ ...route, kind: "FAIL_OPEN" });
    } else {
      // A profile's write is one method; a route of several names no read.
      // Stryker disable next-line StringLiteral: a profile's row has one method, so the separator never joins two.
      const methods = row.methods.join(" ");
      coverage.governed.push({
        ...route,
        target_read: reads.has(`${methods} ${row.path} ${row.action}`),
      });
    }
  }
  return { ...coverage, reads: routes.reads };
}
