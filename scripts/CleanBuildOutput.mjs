import { rm } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const workspaceDirectory = relative(repositoryRoot, process.cwd());

if (!/^(?:examples|packages)[\\/][^\\/]+$/.test(workspaceDirectory)) {
  throw new Error(`Refusing to clean output outside a workspace package: ${workspaceDirectory}`);
}

await rm(join(process.cwd(), "dist"), { force: true, recursive: true });
