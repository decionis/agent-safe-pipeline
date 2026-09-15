import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { HostPosture, PostureError } from "../../src/posture/HostPosture.js";
import {
  DRIFT_CHECKS,
  SERVICE_ACCOUNT_TOKEN,
  WAIVABLE_CHECKS,
  processFacts,
  type PostureCheckId,
  type PostureConfig,
  type PostureFacts,
} from "../../src/posture/PostureChecks.js";
import { collectedEvents } from "../support/Environment.js";

interface FixtureOptions {
  readonly euid?: number;
  readonly writable?: readonly string[];
  readonly files?: Readonly<
    Record<string, { mode: number; uid: number; gid: number; isFile?: boolean }>
  >;
  readonly realpaths?: Readonly<Record<string, string>>;
  readonly inspector?: boolean;
  readonly permission?: { active: boolean; granted?: readonly string[] };
  readonly fetchLocked?: boolean;
}

/** A host as the checks would see it; nothing here touches the real filesystem. */
function facts(options: FixtureOptions = {}): PostureFacts {
  const granted = new Set(options.permission?.granted ?? []);
  return {
    euid: options.euid ?? 65532,
    egid: 65532,
    cwd: "/app",
    writable: (path) => (options.writable ?? []).includes(path),
    fileStat: (path) => {
      const file = options.files?.[path];
      return file === undefined ? null : { isFile: file.isFile ?? true, ...file };
    },
    realpath: (path) => options.realpaths?.[path] ?? path,
    inspectorActive: () => options.inspector ?? false,
    globalFetchLocked: () => options.fetchLocked ?? true,
    permission: () => ({
      active: options.permission?.active ?? true,
      has: (scope) => granted.has(scope),
    }),
  };
}

const SECRET = "/var/run/agent-safe/secrets/decionis-api-key";

function config(overrides: Partial<PostureConfig> = {}): PostureConfig {
  return {
    production: true,
    environment: { NODE_ENV: "production" },
    secretsInEnvironment: [],
    secretFiles: { DECIONIS_API_KEY: SECRET },
    secretsDir: "/var/run/agent-safe/secrets",
    ...overrides,
  };
}

const green = (): FixtureOptions => ({
  files: { [SECRET]: { mode: 0o100440, uid: 0, gid: 65532 } },
});

function posture(
  mode: "ENFORCED" | "DEVELOPMENT",
  fixture: FixtureOptions,
  settings: Partial<PostureConfig> = {},
  lines: string[] = [],
  fetchLocked?: () => boolean,
): HostPosture {
  const host = facts(fixture);
  return new HostPosture(
    {
      mode,
      intervalSeconds: 60,
      config: config(settings),
      facts: fetchLocked === undefined ? host : { ...host, globalFetchLocked: fetchLocked },
    },
    collectedEvents(lines),
  );
}

function refusal(
  fixture: FixtureOptions,
  settings: Partial<PostureConfig> = {},
  mode: "ENFORCED" | "DEVELOPMENT" = "ENFORCED",
): PostureCheckId | null {
  try {
    posture(mode, fixture, settings).assertAtStartup();
    return null;
  } catch (error) {
    if (error instanceof PostureError) return error.check;
    throw error;
  }
}

describe("HostPosture", () => {
  it("verifies a hardened host and says how many checks it ran", () => {
    const lines: string[] = [];
    const report = posture("ENFORCED", green(), {}, lines).assertAtStartup();
    expect(report.failed).toEqual([]);
    expect(report.waived).toEqual([]);
    expect(report.findings.length).toBeGreaterThanOrEqual(18);
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0] ?? "{}")).toMatchObject({
      event: "POSTURE_VERIFIED",
      checks: report.findings.length,
      waived: 0,
    });
  });

  it("refuses each host regression by its own check", () => {
    expect(refusal({ ...green(), euid: 0 })).toBe("ROOT_UID");
    expect(refusal({ ...green(), writable: ["/"] })).toBe("ROOT_WRITABLE");
    expect(refusal({ ...green(), writable: ["/app"] })).toBe("CWD_WRITABLE");
    expect(
      refusal({
        ...green(),
        files: { ...green().files, [SERVICE_ACCOUNT_TOKEN]: { mode: 0o100600, uid: 0, gid: 0 } },
      }),
    ).toBe("SA_TOKEN_PRESENT");
    expect(refusal(green(), { environment: {} })).toBe("NODE_ENV");
    expect(refusal(green(), { environment: { NODE_ENV: "production", https_proxy: "x" } })).toBe(
      "PROXY_ENV",
    );
    expect(refusal(green(), { environment: { NODE_ENV: "production", NODE_OPTIONS: "x" } })).toBe(
      "NODE_OPTIONS",
    );
    expect(
      refusal(green(), { environment: { NODE_ENV: "production", NODE_EXTRA_CA_CERTS: "x" } }),
    ).toBe("EXTRA_CA");
    expect(
      refusal(green(), {
        environment: { NODE_ENV: "production", NODE_TLS_REJECT_UNAUTHORIZED: "0" },
      }),
    ).toBe("TLS_REJECT_DISABLED");
    expect(refusal(green(), { environment: { NODE_ENV: "production", SSLKEYLOGFILE: "x" } })).toBe(
      "KEYLOG",
    );
    expect(refusal({ ...green(), inspector: true })).toBe("INSPECTOR_ACTIVE");
    expect(refusal(green(), { secretsInEnvironment: ["DECIONIS_API_KEY"] })).toBe("SECRET_IN_ENV");
    expect(refusal({ ...green(), permission: { active: false } })).toBe("PERMISSION_MODEL_ABSENT");
    expect(refusal({ ...green(), permission: { active: true, granted: ["fs.write"] } })).toBe(
      "PERMISSION_FS_WRITE",
    );
    expect(refusal({ ...green(), permission: { active: true, granted: ["child"] } })).toBe(
      "PERMISSION_CHILD_PROCESS",
    );
    expect(refusal({ ...green(), permission: { active: true, granted: ["worker"] } })).toBe(
      "PERMISSION_WORKER",
    );
    expect(refusal({ ...green(), fetchLocked: false })).toBe("GLOBAL_FETCH_UNLOCKED");
  });

  it("checks every secret file's place, mode, and owner", () => {
    expect(refusal({ files: { [SECRET]: { mode: 0o100444, uid: 0, gid: 65532 } } })).toBe(
      "SECRET_FILE_MODE",
    );
    expect(refusal({ files: { [SECRET]: { mode: 0o100440, uid: 1000, gid: 1000 } } })).toBe(
      "SECRET_FILE_OWNER",
    );
    expect(refusal({ files: {} })).toBe("SECRET_FILE_MODE");
    expect(refusal({ ...green(), realpaths: { [SECRET]: "/elsewhere/decionis-api-key" } })).toBe(
      "SECRET_FILE_OUTSIDE_DIR",
    );
    expect(refusal({ files: { [SECRET]: { mode: 0o100600, uid: 65532, gid: 65532 } } })).toBeNull();
    expect(refusal(green(), { secretsDir: null })).toBeNull();
  });

  it("waives the host checks under development posture, says so, and never waives the rest", () => {
    const lines: string[] = [];
    const developer: FixtureOptions = {
      ...green(),
      writable: ["/", "/app"],
      inspector: true,
      permission: { active: false },
      fetchLocked: false,
    };
    const report = posture(
      "DEVELOPMENT",
      developer,
      { production: false, environment: { NODE_OPTIONS: "--x" } },
      lines,
    ).assertAtStartup();
    expect(report.failed).toEqual([]);
    expect(report.waived.map((finding) => finding.id).sort()).toEqual(
      [
        "CWD_WRITABLE",
        "GLOBAL_FETCH_UNLOCKED",
        "INSPECTOR_ACTIVE",
        "NODE_ENV",
        "NODE_OPTIONS",
        "PERMISSION_CHILD_PROCESS",
        "PERMISSION_FS_WRITE",
        "PERMISSION_MODEL_ABSENT",
        "PERMISSION_WORKER",
        "ROOT_WRITABLE",
      ].sort(),
    );
    expect(lines.filter((line) => line.includes('"POSTURE_WAIVED"'))).toHaveLength(10);
    expect(refusal({ ...developer, euid: 0 }, { production: false }, "DEVELOPMENT")).toBe(
      "ROOT_UID",
    );
    expect(
      refusal(
        developer,
        { production: false, environment: { NODE_TLS_REJECT_UNAUTHORIZED: "0" } },
        "DEVELOPMENT",
      ),
    ).toBe("TLS_REJECT_DISABLED");
    for (const never of ["ROOT_UID", "SA_TOKEN_PRESENT", "TLS_REJECT_DISABLED", "SECRET_IN_ENV"]) {
      expect(WAIVABLE_CHECKS.has(never as PostureCheckId)).toBe(false);
    }
  });

  it("names the check and the secret in a refusal, never a path or a value", () => {
    try {
      posture("ENFORCED", {
        files: { [SECRET]: { mode: 0o100444, uid: 0, gid: 65532 } },
      }).assertAtStartup();
    } catch (error) {
      expect(error).toBeInstanceOf(PostureError);
      expect((error as PostureError).message).toBe("POSTURE_SECRET_FILE_MODE (DECIONIS_API_KEY)");
      expect((error as PostureError).message).not.toContain("/var/run");
      return;
    }
    throw new Error("expected a refusal");
  });

  it("degrades on drift while running and restores when the host recovers", () => {
    const lines: string[] = [];
    const files: Record<string, { mode: number; uid: number; gid: number }> = {
      [SECRET]: { mode: 0o100440, uid: 0, gid: 65532 },
    };
    const host = posture("ENFORCED", { files }, {}, lines);
    host.assertAtStartup();
    expect(host.degraded).toBe(false);
    files[SECRET] = { mode: 0o100444, uid: 0, gid: 65532 };
    host.tick();
    host.tick();
    expect(host.degraded).toBe(true);
    expect(lines.filter((line) => line.includes('"POSTURE_DRIFT"'))).toHaveLength(1);
    files[SECRET] = { mode: 0o100440, uid: 0, gid: 65532 };
    host.tick();
    expect(host.degraded).toBe(false);
    expect(lines.filter((line) => line.includes('"POSTURE_RESTORED"'))).toHaveLength(1);
    expect(host.report?.failed).toEqual([]);
    const stop = host.start();
    stop();
    for (const check of ["ROOT_UID", "ROOT_WRITABLE", "CWD_WRITABLE", "NODE_ENV"]) {
      expect(DRIFT_CHECKS.has(check as PostureCheckId)).toBe(false);
    }
    expect(DRIFT_CHECKS.has("GLOBAL_FETCH_UNLOCKED")).toBe(true);
  });

  it("treats an unlocked global fetch while running as drift", () => {
    const lines: string[] = [];
    let locked = true;
    const host = posture("ENFORCED", green(), {}, lines, () => locked);
    host.assertAtStartup();
    locked = false;
    host.tick();
    expect(host.degraded).toBe(true);
    expect(lines.filter((line) => line.includes('"GLOBAL_FETCH_UNLOCKED"'))).toHaveLength(1);
  });
});

describe("processFacts", () => {
  const directory = mkdtempSync(join(tmpdir(), "agentsafe-posture-"));
  afterAll(() => rmSync(directory, { recursive: true, force: true }));

  it("reads the real process without the permission model in tests", () => {
    const real = processFacts();
    const file = join(directory, "a-file");
    writeFileSync(file, "x");
    expect(real.euid).toBeTypeOf("number");
    expect(real.cwd).toBeTypeOf("string");
    expect(real.writable(directory)).toBe(true);
    expect(real.fileStat(file)?.isFile).toBe(true);
    expect(real.fileStat(join(directory, "absent"))).toBeNull();
    expect(real.realpath(file)).toContain("a-file");
    expect(real.realpath(join(directory, "absent"))).toBeNull();
    expect(real.inspectorActive()).toBeTypeOf("boolean");
    expect(real.globalFetchLocked()).toBe(false);
    expect(real.permission().active).toBe(false);
    expect(real.permission().has("fs.write", "/")).toBe(true);
  });
});
