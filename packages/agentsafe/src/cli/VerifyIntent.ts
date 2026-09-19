/**
 * `agentsafe verify intent <file|dir>... [--json]`: Agent-Safe Intent
 * conformance, offline. Each file is a vector from the corpus or a binding
 * of your own; a directory is every `.json` file in it. For a vector the
 * canonical bytes and the hash are recomputed and compared, and every
 * mutation must hash differently from the base and from the others; for a
 * bare binding the bytes and the hash are printed so another implementation
 * can compare. Exit 0 when everything reproduced, 1 when a vector did not,
 * 2 when the command could not do its job: no path, an option it does not
 * know, or a named file that is not there or not JSON.
 */
import { ArgumentError, parseArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import {
  INTENT_PROTOCOL,
  verifyIntentVector,
  type IntentVectorReport,
} from "../verify/VerifyIntentVector.js";
import { packageVersion } from "../Version.js";

export const VERIFY_INTENT_ARGUMENTS = { valued: [], flags: ["json"] } as const;

export interface IntentFileReport extends IntentVectorReport {
  readonly file: string;
}

export interface VerifyIntentReport {
  readonly version: "agent-safe.intent-conformance/1";
  readonly runtime: string;
  readonly protocol: typeof INTENT_PROTOCOL;
  readonly files: readonly IntentFileReport[];
  /** Files that could not be read or parsed; each is a usage error, not a conformance failure. */
  readonly unreadable: readonly string[];
  /** Pinned vectors whose bytes and hash this runtime reproduced. */
  readonly reproduced: number;
  /** Unpinned bindings whose bytes and hash were computed for the caller to compare. */
  readonly computed: number;
  readonly failed: number;
  readonly exit: 0 | 1 | 2;
}

const ESC = String.fromCharCode(27);
const RESET = `${ESC}[0m`;
const BOLD = `${ESC}[1m`;
const DIM = `${ESC}[2m`;
const RED = `${ESC}[31m`;
const GREEN = `${ESC}[32m`;

function join(directory: string, name: string): string {
  return directory.endsWith("/") ? `${directory}${name}` : `${directory}/${name}`;
}

/** The files named, a directory expanded to its `.json` entries; a path that is neither is kept and reported. */
function expand(io: CliProcess, paths: readonly string[]): readonly string[] {
  const files: string[] = [];
  for (const path of paths) {
    const entries = io.files.list(path);
    if (entries === null) {
      files.push(path);
      continue;
    }
    for (const name of entries) if (name.endsWith(".json")) files.push(join(path, name));
  }
  return files;
}

function shape(report: IntentVectorReport): string {
  if (report.kind === "unrecognised") return "not an intent vector";
  const base = report.pinned ? "base" : "base, unpinned";
  return report.mutations === 0 ? base : `${base} + ${String(report.mutations)} mutations`;
}

export function renderVerifyIntentReport(
  report: VerifyIntentReport,
  options: { readonly color: boolean },
): string {
  const bold = (text: string): string => (options.color ? `${BOLD}${text}${RESET}` : text);
  const dim = (text: string): string => (options.color ? `${DIM}${text}${RESET}` : text);
  const tone = (ok: boolean, text: string): string =>
    options.color ? `${ok ? GREEN : RED}${text}${RESET}` : text;
  const row = (label: string, value: string): string => `${label.padEnd(11)} ${value}`;
  const width = Math.max(0, ...report.files.map((file) => file.file.length));
  const lines = [
    `${bold("AgentSafe")} ${dim(report.runtime)} intent conformance ${dim(report.protocol)}`,
    "",
  ];
  for (const file of report.files) {
    const hashes = `${String(file.hashes)} distinct ${file.hashes === 1 ? "hash" : "hashes"}`;
    const outcome = !file.pinned && file.ok ? "COMPUTED" : file.ok ? "REPRODUCED" : "FAILED";
    lines.push(
      `${file.file.padEnd(width)}  ${file.kind.padEnd(10)}  ${shape(file).padEnd(26)}  ${hashes.padEnd(18)}  ${tone(file.ok, outcome)}`,
    );
    for (const finding of file.findings) {
      const where = finding.path === null ? "" : ` at ${finding.path}`;
      const values =
        finding.expected === null && finding.computed === null
          ? ""
          : `: expected ${finding.expected ?? "-"}, computed ${finding.computed ?? "-"}`;
      lines.push(`    ${dim(`${finding.code}${where}${values}`)}`);
    }
    if (!file.pinned && file.ok) {
      lines.push(
        `    ${row("canonical", file.canonical_json ?? "")}`,
        `    ${row("hash", file.intent_hash ?? "")}`,
      );
    }
  }
  for (const path of report.unreadable) {
    lines.push(`${path.padEnd(width)}  ${tone(false, "UNREADABLE: not a file of JSON")}`);
  }
  const verdict =
    report.exit === 2
      ? "NOTHING CHECKED"
      : report.failed > 0
        ? `DOES NOT CONFORM: ${String(report.failed)} of ${String(report.files.length)} did not reproduce`
        : report.reproduced === 0
          ? "COMPUTED: nothing was pinned; compare the bytes and the hash with your implementation's"
          : "CONFORMS: every pinned hash reproduced";
  lines.push(
    "",
    row(
      "Vectors",
      `${String(report.reproduced)} reproduced, ${String(report.computed)} computed, ${String(report.failed)} failed`,
    ),
    row("Verdict", bold(tone(report.exit === 0, verdict))),
    "",
  );
  return lines.join("\n");
}

export function runVerifyIntent(
  io: CliProcess,
  argv: readonly string[],
): VerifyIntentReport | null {
  let json = false;
  let paths: readonly string[];
  try {
    const parsed = parseArguments(argv, VERIFY_INTENT_ARGUMENTS);
    json = parsed.options.get("json") === true;
    paths = parsed.positionals;
  } catch (error) {
    io.stderr(`${error instanceof ArgumentError ? error.message : "ARGUMENTS_INVALID"}\n`);
    io.exit(2);
    return null;
  }
  if (paths.length === 0) {
    io.stderr(
      "Name a vector, a binding, or a directory of them: agentsafe verify intent conformance/vectors\n",
    );
    io.exit(2);
    return null;
  }
  const files: IntentFileReport[] = [];
  const unreadable: string[] = [];
  for (const file of expand(io, paths)) {
    const text = io.files.read(file);
    let document: unknown;
    try {
      if (text === null) throw new Error("UNREADABLE");
      document = JSON.parse(text);
    } catch {
      unreadable.push(file);
      continue;
    }
    files.push({ file, ...verifyIntentVector(document) });
  }
  const failed = files.filter((file) => !file.ok).length;
  const computed = files.filter((file) => file.ok && !file.pinned).length;
  const exit: 0 | 1 | 2 = files.length === 0 || unreadable.length > 0 ? 2 : failed === 0 ? 0 : 1;
  const report: VerifyIntentReport = {
    version: "agent-safe.intent-conformance/1",
    runtime: packageVersion(),
    protocol: INTENT_PROTOCOL,
    files,
    unreadable,
    reproduced: files.length - failed - computed,
    computed,
    failed,
    exit,
  };
  io.stdout(
    json ? `${JSON.stringify(report)}\n` : renderVerifyIntentReport(report, { color: io.color }),
  );
  io.exit(exit);
  return report;
}
