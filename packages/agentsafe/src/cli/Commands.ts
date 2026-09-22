import { packageVersion } from "../Version.js";
import type { CliProcess } from "./CliProcess.js";
import { runConfig } from "./ConfigCommand.js";
import { runDoctor } from "./Doctor.js";
import { runIdentity } from "./Identity.js";
import { usage } from "./Help.js";
import { runInit } from "./Init.js";
import { runIntercept } from "./Intercept.js";
import { runLogin, runLogout } from "./Login.js";
import { runProxy } from "./Proxy.js";
import { runStatus } from "./Status.js";
import { runTest } from "./TestCommand.js";

/** The commands this module owns; the executor's own are dispatched by the entry. */
export const GATEWAY_COMMANDS = [
  "init",
  "proxy",
  "gateway",
  "run",
  "intercept",
  "status",
  "doctor",
  "test",
  "identity",
  "config",
  "login",
  "logout",
  "version",
  "help",
] as const;

export type GatewayCommand = (typeof GATEWAY_COMMANDS)[number];

export function isGatewayCommand(command: string | undefined): command is GatewayCommand {
  return command !== undefined && (GATEWAY_COMMANDS as readonly string[]).includes(command);
}

/** Runs one of the gateway commands; every one ends by calling `exit`. */
export async function runGatewayCommand(
  command: GatewayCommand,
  argv: readonly string[],
  io: CliProcess,
): Promise<void> {
  switch (command) {
    case "init":
      runInit(io, argv);
      return;
    case "proxy":
    case "gateway":
    case "run":
      await runProxy(io, argv);
      return;
    case "intercept":
      await runIntercept(io, argv);
      return;
    case "status":
      await runStatus(io, argv);
      return;
    case "doctor":
      await runDoctor(io, argv);
      return;
    case "identity":
      runIdentity(io, argv);
      return;
    case "test":
      await runTest(io, argv);
      return;
    case "config":
      runConfig(io, argv);
      return;
    case "login":
      await runLogin(io, argv);
      return;
    case "logout":
      runLogout(io);
      return;
    case "version":
      io.stdout(`${packageVersion()}\n`);
      io.exit(0);
      return;
    case "help":
      io.stdout(usage(packageVersion()));
      io.exit(0);
      return;
  }
}
