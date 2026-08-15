import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";

const staged = spawnSync("git", ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"], {
  encoding: "utf8",
});
if (staged.status !== 0) process.exit(staged.status ?? 1);

const files = staged.stdout.split("\0").filter((path) => path.length > 0 && existsSync(path));
if (files.length === 0) process.exit(0);

const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const run = (arguments_) => {
  const result = spawnSync(pnpm, arguments_, { stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status ?? 1);
};

run(["exec", "prettier", "--check", "--ignore-unknown", ...files]);

const markdownFiles = files.filter((path) => /\.md$/i.test(path));
if (markdownFiles.length > 0) run(["exec", "markdownlint-cli2", ...markdownFiles]);
