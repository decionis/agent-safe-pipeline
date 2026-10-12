import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import {
  DOCKER_HUB_LIBRARY,
  OFFICIAL_IMAGE_MIRROR,
  baseImagesOf,
  buildArgsOf,
  candidatesOf,
  resolveBaseImages,
} from "../../scripts/ResolveBaseImages.mjs";

const dockerfile = readFileSync(
  new URL("../../packages/agentsafe/Dockerfile", import.meta.url),
  "utf8",
);
const NODE = `${OFFICIAL_IMAGE_MIRROR}node:22-alpine@sha256:${"a".repeat(64)}`;
const DISTROLESS = `gcr.io/distroless/nodejs22-debian12:nonroot@sha256:${"b".repeat(64)}`;

describe("ResolveBaseImages", () => {
  it("reads every pinned base of the executor's Dockerfile", () => {
    const bases = baseImagesOf(dockerfile);
    assert.deepEqual(
      bases.map((base) => base.name),
      ["NODE_BASE_IMAGE", "RUNTIME_BASE_IMAGE", "INIT_BASE_IMAGE"],
    );
    for (const base of bases) {
      assert.match(base.ref, /@sha256:[0-9a-f]{64}$/, `${base.name} is pinned by digest`);
    }
  });

  it("offers Docker Hub only for a Docker Official Image, at the same digest", () => {
    assert.deepEqual(candidatesOf(NODE), [
      NODE,
      `${DOCKER_HUB_LIBRARY}node:22-alpine@sha256:${"a".repeat(64)}`,
    ]);
    assert.deepEqual(candidatesOf(DISTROLESS), [DISTROLESS]);
  });

  it("keeps the pinned ref when it pulls", async () => {
    const pulled = [];
    const resolved = await resolveBaseImages([{ name: "NODE_BASE_IMAGE", ref: NODE }], {
      pull: async (ref) => {
        pulled.push(ref);
        return true;
      },
    });
    assert.deepEqual(resolved, [{ name: "NODE_BASE_IMAGE", ref: NODE }]);
    assert.deepEqual(pulled, [NODE]);
  });

  it("falls back to Docker Hub after the attempts at ECR Public, pausing longer each time", async () => {
    const pulled = [];
    const pauses = [];
    const logged = [];
    const resolved = await resolveBaseImages(
      [
        { name: "NODE_BASE_IMAGE", ref: NODE },
        { name: "RUNTIME_BASE_IMAGE", ref: DISTROLESS },
      ],
      {
        pull: async (ref) => {
          pulled.push(ref);
          return !ref.startsWith(OFFICIAL_IMAGE_MIRROR);
        },
        pause: async (ms) => {
          pauses.push(ms);
        },
        log: (line) => logged.push(line),
      },
    );
    const hub = `${DOCKER_HUB_LIBRARY}node:22-alpine@sha256:${"a".repeat(64)}`;
    assert.deepEqual(resolved, [
      { name: "NODE_BASE_IMAGE", ref: hub },
      { name: "RUNTIME_BASE_IMAGE", ref: DISTROLESS },
    ]);
    assert.deepEqual(pulled, [NODE, NODE, NODE, hub, DISTROLESS]);
    assert.deepEqual(pauses, [15_000, 30_000]);
    assert.deepEqual(logged, [`${NODE} came from ${hub}, the same digest`]);
    assert.equal(
      buildArgsOf(resolved),
      `--build-arg NODE_BASE_IMAGE=${hub} --build-arg RUNTIME_BASE_IMAGE=${DISTROLESS}`,
    );
  });

  it("fails when a base pulls from nowhere", async () => {
    await assert.rejects(
      resolveBaseImages([{ name: "RUNTIME_BASE_IMAGE", ref: DISTROLESS }], {
        pull: async () => false,
        attempts: 2,
        pause: async () => {},
      }),
      /could not pull gcr\.io\/distroless\/nodejs22-debian12:nonroot@sha256:b+ from any registry after 2 attempts each/,
    );
  });
});
