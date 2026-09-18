/**
 * How an example ends. A local run ends with its verdict and one line that
 * says what the hosted path adds. A hosted run ends with what Decionis
 * decided, the Decision Dossier it left, the page that verifies it (when
 * the authority attached one), the command that verifies it offline, and
 * the signed record itself, fetched with the run's own key and shown by its
 * proof: the thing the local path cannot produce.
 */
import type { HostedGate } from "../decision/CreateGate.js";
import type { GateDecision } from "../decision/DecisionAuthority.js";
import { printDecision, type DecisionReportOptions } from "./DecisionReport.js";
import { DossierFetchError, printSignedDossier } from "./DossierReport.js";

export interface HostedOutcomeOptions extends DecisionReportOptions {
  /** Whether a local run prints the line about the hosted path; on by default. */
  readonly hint?: boolean;
}

export const HOSTED_HINT =
  "hint: DECIONIS_HOSTED=1 has Decionis evaluate the same intent and sign a Decision Dossier; no account, no card, one variable";

export async function printHostedOutcome(
  gate: HostedGate,
  decision: GateDecision,
  options: HostedOutcomeOptions = {},
): Promise<void> {
  const out = options.out ?? process.stdout;
  if (gate.credentials === null || gate.fetchDossier === null) {
    if (options.hint !== false) out.write(`${HOSTED_HINT}\n`);
    return;
  }
  printDecision(decision, options);
  const dossierId = decision.hosted?.dossierId ?? null;
  if (dossierId === null) return;
  try {
    const { summary } = await gate.fetchDossier(dossierId);
    printSignedDossier(summary, { out });
  } catch (error) {
    const code = error instanceof DossierFetchError ? error.code : "DOSSIER_UNAVAILABLE";
    out.write(`signed dossier: not fetched (${code}); the record is still there under your key\n`);
  }
}
