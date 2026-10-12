// Pull a Dockerfile's pinned base images before a build, and say which refs
// the build should use.
//
// ECR Public meters anonymous pulls per source address and GitHub's runners
// share addresses, so a pull can fail with 429 before anything of the
// repository's own runs, and a pause does not always outlast the limit. Docker
// Official Images are the same manifests on ECR Public and Docker Hub, so a
// pinned digest that ECR Public will not serve is pulled from Docker Hub at
// the same digest, and the build is told which ref it got through the
// Dockerfile's `<NAME>_BASE_IMAGE` build arguments.
import { spawnSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const OFFICIAL_IMAGE_MIRROR = "public.ecr.aws/docker/library/";
export const DOCKER_HUB_LIBRARY = "docker.io/library/";
const ATTEMPTS = 3;
const PAUSE_MS = 15_000;

/** The `ARG <NAME>_BASE_IMAGE=<ref>` lines of a Dockerfile, in order. */
export function baseImagesOf(dockerfile) {
  const bases = [];
  for (const line of dockerfile.split("\n")) {
    const match = /^ARG ([A-Z][A-Z0-9_]*_BASE_IMAGE)=(\S+)$/.exec(line);
    if (match !== null) {
      bases.push({ name: match[1], ref: match[2] });
    }
  }
  return bases;
}

/**
 * The refs to try for one base, the pinned one first. Only a Docker Official
 * Image has a second: Docker Hub serves it at the same digest.
 */
export function candidatesOf(ref) {
  if (!ref.startsWith(OFFICIAL_IMAGE_MIRROR)) {
    return [ref];
  }
  return [ref, DOCKER_HUB_LIBRARY + ref.slice(OFFICIAL_IMAGE_MIRROR.length)];
}

/** The `--build-arg` words that point a build at the refs that pulled. */
export function buildArgsOf(resolved) {
  return resolved.map(({ name, ref }) => `--build-arg ${name}=${ref}`).join(" ");
}

/**
 * Pulls every base, trying each candidate up to `attempts` times with a
 * growing pause, and returns the refs that pulled. Throws when a base pulled
 * from nowhere.
 */
export async function resolveBaseImages(
  bases,
  { pull, attempts = ATTEMPTS, pause = sleep, log = () => {} },
) {
  const resolved = [];
  for (const base of bases) {
    const got = await firstPulled(base.ref, { pull, attempts, pause });
    if (got === null) {
      throw new Error(
        `could not pull ${base.ref} from any registry after ${attempts} attempts each`,
      );
    }
    if (got !== base.ref) {
      log(`${base.ref} came from ${got}, the same digest`);
    }
    resolved.push({ name: base.name, ref: got });
  }
  return resolved;
}

async function firstPulled(ref, { pull, attempts, pause }) {
  for (const candidate of candidatesOf(ref)) {
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      if (await pull(candidate)) {
        return candidate;
      }
      if (attempt < attempts) {
        await pause(attempt * PAUSE_MS);
      }
    }
  }
  return null;
}

function sleep(ms) {
  return new Promise((done) => setTimeout(done, ms));
}

function dockerPull(ref) {
  const result = spawnSync("docker", ["pull", "--quiet", ref], {
    stdio: ["ignore", "inherit", "inherit"],
  });
  return result.status === 0;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const dockerfile = process.argv[2];
  if (dockerfile === undefined) {
    console.error("usage: node scripts/ResolveBaseImages.mjs <Dockerfile>");
    process.exit(2);
  }
  const resolved = await resolveBaseImages(baseImagesOf(readFileSync(dockerfile, "utf8")), {
    pull: dockerPull,
    log: console.log,
  });
  const lines = resolved.map(({ name, ref }) => `${name}=${ref}`);
  lines.push(`BASE_IMAGE_BUILD_ARGS=${buildArgsOf(resolved)}`);
  if (process.env.GITHUB_ENV !== undefined) {
    appendFileSync(process.env.GITHUB_ENV, `${lines.join("\n")}\n`);
  }
  console.log(lines.join("\n"));
}
