import { describe, expect, it } from "vitest";
import {
  INSTALL_SURFACES,
  installSurface,
  processSurface,
  SURFACE_ENVIRONMENT,
} from "../../src/gateway/InstallSurface.js";

const facts = (execPath: string, script?: string, env: Record<string, string> = {}) => ({
  env,
  execPath,
  script,
});

describe("the install surface", () => {
  it("is what the distribution named, when it named one of the surfaces", () => {
    for (const surface of INSTALL_SURFACES) {
      expect(
        installSurface(facts("/anywhere/agentsafe", undefined, { AGENTSAFE_SURFACE: surface })),
      ).toBe(surface);
    }
    expect(
      installSurface(
        facts("/opt/homebrew/Cellar/agentsafe/0.2.0/libexec/agentsafe", undefined, {
          [SURFACE_ENVIRONMENT]: " Docker ",
        }),
      ),
    ).toBe("docker");
    // A name that is not a surface is no surface, never a guess and never sent.
    expect(
      installSurface(facts("/usr/bin/agentsafe", undefined, { AGENTSAFE_SURFACE: "mirror-x" })),
    ).toBeNull();
    expect(installSurface(facts("/usr/bin/agentsafe", undefined, { AGENTSAFE_SURFACE: "" }))).toBe(
      "linux",
    );
  });

  it("recognises where each distribution puts the executable, and nothing else", () => {
    expect(installSurface(facts("/opt/homebrew/Cellar/agentsafe/0.2.0/libexec/agentsafe"))).toBe(
      "homebrew",
    );
    expect(
      installSurface(
        facts(
          "/home/linuxbrew/.linuxbrew/Cellar/agentsafe/0.2.0/libexec/node",
          "/home/linuxbrew/.linuxbrew/Cellar/agentsafe/0.2.0/libexec/agentsafe.cjs",
        ),
      ),
    ).toBe("homebrew");
    expect(installSurface(facts("/usr/local/lib/agentsafe/0.2.0/agentsafe"))).toBe("installer");
    expect(installSurface(facts("/home/synthetic/.local/lib/agentsafe/0.2.0/agentsafe"))).toBe(
      "installer",
    );
    expect(installSurface(facts("/usr/bin/agentsafe"))).toBe("linux");
    expect(
      installSurface(
        facts("/usr/local/bin/node", "/usr/local/lib/node_modules/@decionis/agentsafe/dist/Cli.js"),
      ),
    ).toBe("npm");
    expect(
      installSurface(
        facts("/usr/local/bin/node", "/work/agent-safe-pipeline/packages/agentsafe/dist/Cli.js"),
      ),
    ).toBe("source");
    expect(
      installSurface(
        facts(
          "C:\\\\Program Files\\\\nodejs\\\\node.exe",
          "C:\\\\src\\\\node_modules\\\\@decionis\\\\agentsafe\\\\dist\\\\Cli.js",
        ),
      ),
    ).toBe("npm");
    expect(installSurface(facts("/tmp/agentsafe"))).toBeNull();
    expect(installSurface(facts("/usr/bin/node", "/srv/app/Cli.js"))).toBeNull();
  });

  it("reads the running process", () => {
    expect(processSurface({ AGENTSAFE_SURFACE: "kubernetes" })).toBe("kubernetes");
    const own = processSurface({});
    expect(own === null || (INSTALL_SURFACES as readonly string[]).includes(own)).toBe(true);
  });
});
