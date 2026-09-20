import { describe, expect, it } from "vitest";
import { GATEWAY_COMMANDS, isGatewayCommand, runGatewayCommand } from "../../src/cli/Commands.js";
import { usage } from "../../src/cli/Help.js";
import { packageVersion } from "../../src/Version.js";
import { fakeProcess } from "../support/GatewayHarness.js";

describe("the command dispatch", () => {
  it("knows its commands and no others", () => {
    for (const command of GATEWAY_COMMANDS) expect(isGatewayCommand(command)).toBe(true);
    expect(isGatewayCommand("serve")).toBe(false);
    expect(isGatewayCommand(undefined)).toBe(false);
  });

  it("prints the version and the usage", async () => {
    const version = fakeProcess();
    await runGatewayCommand("version", [], version);
    expect(version.out).toEqual([`${packageVersion()}\n`]);
    expect(version.exits).toEqual([0]);
    expect(packageVersion()).toMatch(/^\d+\.\d+\.\d+/);
    const help = fakeProcess();
    await runGatewayCommand("help", [], help);
    expect(help.out.join("")).toBe(usage(packageVersion()));
    expect(usage("9.9.9")).toContain("agentsafe 9.9.9");
    for (const name of [
      "init",
      "proxy",
      "run",
      "intercept",
      "status",
      "doctor",
      "test",
      "config",
      "login",
      "logout",
      "version",
      "verify chain",
      "verify bundle",
      "serve",
      "probe-containment",
    ]) {
      expect(usage("1")).toContain(name);
    }
  });

  it("routes each command to its implementation", async () => {
    const init = fakeProcess();
    await runGatewayCommand("init", ["--config", "/work/a.yaml"], init);
    expect(init.stored.has("/work/a.yaml")).toBe(true);
    for (const command of ["proxy", "gateway", "run"] as const) {
      const io = fakeProcess();
      await runGatewayCommand(command, [], io);
      expect(io.exits).toEqual([2]);
      expect(io.err.join("")).toContain("upstream");
    }
    const intercept = fakeProcess();
    await runGatewayCommand("intercept", ["--nope"], intercept);
    expect(intercept.exits).toEqual([2]);
    const status = fakeProcess();
    await runGatewayCommand("status", [], status);
    expect(status.exits).toEqual([1]);
    const doctor = fakeProcess();
    await runGatewayCommand("doctor", ["--nope"], doctor);
    expect(doctor.exits).toEqual([2]);
    const config = fakeProcess();
    await runGatewayCommand("config", ["--upstream", "http://localhost:1"], config);
    expect(config.exits).toEqual([0]);
    const login = fakeProcess({ lines: ["short"] });
    await runGatewayCommand("login", [], login);
    expect(login.exits).toEqual([1]);
    const logout = fakeProcess();
    await runGatewayCommand("logout", [], logout);
    expect(logout.exits).toEqual([0]);
  });
});
