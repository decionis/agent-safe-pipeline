import { describe, expect, it } from "vitest";
import { ConfigFileError, loadConfigFile, locateConfigFile } from "../../src/cli/ConfigFile.js";
import { fakeProcess } from "../support/GatewayHarness.js";

describe("the configuration file", () => {
  it("is the named one, else the variable, else ./agentsafe.yaml when it exists, else none", () => {
    const none = fakeProcess();
    expect(locateConfigFile(none, undefined)).toBeNull();
    expect(loadConfigFile(none, undefined)).toEqual({ path: null, document: null });
    const conventional = fakeProcess({ files: { "/work/agentsafe.yaml": "version: 1\n" } });
    expect(locateConfigFile(conventional, undefined)).toBe("/work/agentsafe.yaml");
    expect(loadConfigFile(conventional, undefined)).toEqual({
      path: "/work/agentsafe.yaml",
      document: { version: 1 },
    });
    const named = fakeProcess({
      files: { "/work/other.yaml": "version: 1\ngateway:\n  upstream: http://localhost:1\n" },
    });
    expect(locateConfigFile(named, "other.yaml")).toBe("/work/other.yaml");
    expect(loadConfigFile(named, "other.yaml").document).toEqual({
      version: 1,
      gateway: { upstream: "http://localhost:1" },
    });
    const absolute = fakeProcess({
      env: { AGENTSAFE_CONFIG: "/etc/agentsafe/agentsafe.yaml" },
      files: { "/etc/agentsafe/agentsafe.yaml": "" },
    });
    expect(locateConfigFile(absolute, undefined)).toBe("/etc/agentsafe/agentsafe.yaml");
    expect(loadConfigFile(absolute, undefined)).toEqual({
      path: "/etc/agentsafe/agentsafe.yaml",
      document: null,
    });
    expect(
      locateConfigFile(fakeProcess({ env: { AGENTSAFE_CONFIG: "  " } }), undefined),
    ).toBeNull();
  });

  it("refuses a named file that is missing, unreadable, too large, or not a YAML mapping", () => {
    expect(() => loadConfigFile(fakeProcess(), "missing.yaml")).toThrow(
      new ConfigFileError("CONFIG_FILE_NOT_FOUND", "/work/missing.yaml").message,
    );
    const stale = fakeProcess({ files: { "/work/agentsafe.yaml": "version: 1" } });
    stale.files.remove("/work/agentsafe.yaml");
    stale.stored.set("/work/agentsafe.yaml", { text: "x", mode: undefined });
    stale.files.read = () => null;
    expect(() => loadConfigFile(stale, undefined)).toThrow("CONFIG_FILE_UNREADABLE");
    expect(() =>
      loadConfigFile(fakeProcess({ files: { "/work/agentsafe.yaml": "a: [\n" } }), undefined),
    ).toThrow("CONFIG_FILE_NOT_YAML");
    expect(() =>
      loadConfigFile(fakeProcess({ files: { "/work/agentsafe.yaml": "- a\n- b\n" } }), undefined),
    ).toThrow("CONFIG_FILE_NOT_YAML");
    expect(() =>
      loadConfigFile(
        fakeProcess({ files: { "/work/agentsafe.yaml": "x".repeat(300 * 1024) } }),
        undefined,
      ),
    ).toThrow("CONFIG_FILE_UNREADABLE");
  });
});
