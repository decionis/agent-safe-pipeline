import type { GateDecision, HostedEvaluation } from "../decision/DecisionAuthority.js";

export interface DecisionReportOptions {
  /** Where the lines go. Defaults to `process.stdout`; a stdio MCP server passes `process.stderr`. */
  readonly out?: { write(chunk: string): unknown };
  /** The command that fetches the record and verifies it; defaults to this repository's script. */
  readonly verifyCommand?: (dossierId: string) => string;
}

/**
 * Prints what Decionis said about a decision, when it was asked. A decision
 * with no `hosted` evaluation prints nothing, so a caller that never set a
 * key sees exactly the output it saw before.
 *
 * The verify lines name the record by identifier only. The page, when the
 * authority attached one, verifies it for anyone who opens it; the command
 * needs the signed record, fetched with the caller's key, and the public
 * JWKS, fetched by anyone; the signature check itself runs offline and needs
 * no account.
 */
export function printDecision(decision: GateDecision, options: DecisionReportOptions = {}): void {
  const hosted = decision.hosted;
  if (hosted === undefined) return;
  const out = options.out ?? process.stdout;
  const verifyCommand =
    options.verifyCommand ?? ((dossierId: string): string => `pnpm decionis:verify ${dossierId}`);

  out.write(`verdict: ${decision.verdict}\n`);
  out.write(`decionis: ${hosted.verdict} (${hosted.mode}, ${standing(hosted)})\n`);
  for (const code of hosted.reasonCodes) out.write(`  - ${code}\n`);
  if (hosted.dossierId === null) {
    out.write("dossier: none\n");
    return;
  }
  out.write(`dossier: ${hosted.dossierId}\n`);
  if (hosted.verificationUrl !== null) {
    out.write(`verify it in a browser, no account needed: ${hosted.verificationUrl}\n`);
  }
  out.write(`verify it yourself, no account needed: ${verifyCommand(hosted.dossierId)}\n`);
}

function standing(hosted: HostedEvaluation): string {
  if (hosted.failClosed) return "failed closed";
  return hosted.governs ? "governs" : "recorded beside the local verdict";
}
