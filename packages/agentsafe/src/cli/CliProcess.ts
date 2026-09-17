import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import process from "node:process";
import { createInterface } from "node:readline";
import type { FetchLike } from "../handlers/HandlerRegistration.js";

/** The files a command touches, behind a seam so a test hands in a directory of its own. */
export interface CliFiles {
  exists(path: string): boolean;
  /** The text, or null when there is no such file. */
  read(path: string): string | null;
  write(path: string, text: string, mode?: number): void;
  mkdir(path: string): void;
  remove(path: string): void;
}

/** The process around a command: where input comes from, where output goes, how it ends. */
export interface CliProcess {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly cwd: string;
  readonly home: string;
  readonly isTTY: boolean;
  readonly color: boolean;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  readonly exit: (code: number) => void;
  readonly onSignal: (signal: "SIGTERM" | "SIGINT" | "SIGHUP", handler: () => void) => void;
  readonly files: CliFiles;
  /** One line from standard input, or a prompt's answer on a terminal. */
  readonly readLine: (prompt: string, secret: boolean) => Promise<string>;
  readonly fetch: FetchLike;
}

export function nodeFiles(): CliFiles {
  return {
    exists: (path) => existsSync(path),
    read: (path) => {
      try {
        return readFileSync(path, "utf8");
      } catch {
        return null;
      }
    },
    write: (path, text, mode) => {
      writeFileSync(
        path,
        text,
        mode === undefined ? { encoding: "utf8" } : { encoding: "utf8", mode },
      );
    },
    mkdir: (path) => {
      mkdirSync(path, { recursive: true, mode: 0o700 });
    },
    remove: (path) => {
      rmSync(path, { force: true });
    },
  };
}

export function nodeCliProcess(): CliProcess {
  return {
    env: process.env,
    cwd: process.cwd(),
    home: homedir(),
    isTTY: process.stdout.isTTY === true,
    color: process.stdout.isTTY === true && process.env["NO_COLOR"] === undefined,
    stdout: (text) => {
      process.stdout.write(text);
    },
    stderr: (text) => {
      process.stderr.write(text);
    },
    exit: (code) => process.exit(code),
    onSignal: (signal, handler) => {
      process.once(signal, handler);
    },
    files: nodeFiles(),
    readLine: (prompt, secret) =>
      new Promise((resolve) => {
        if (process.stdin.isTTY !== true) {
          let text = "";
          process.stdin.setEncoding("utf8");
          process.stdin.on("data", (chunk: string) => {
            text += chunk;
          });
          process.stdin.on("end", () => resolve(text.split("\n")[0]?.trim() ?? ""));
          return;
        }
        const rl = createInterface({
          input: process.stdin,
          output: process.stderr,
          terminal: true,
        });
        if (secret) {
          // A secret is not echoed: the interface writes the prompt and nothing typed after it.
          const output = rl as unknown as { _writeToOutput?: (text: string) => void };
          output._writeToOutput = (text: string): void => {
            if (text.startsWith(prompt)) process.stderr.write(prompt);
          };
        }
        rl.question(prompt, (answer) => {
          rl.close();
          if (secret) process.stderr.write("\n");
          resolve(answer.trim());
        });
      }),
    fetch,
  };
}
