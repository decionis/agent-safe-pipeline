# The trusted executor as one image, built from the repository root as the
# build context:
#
#   docker build -f packages/agentsafe/Dockerfile -t agentsafe .
#
# The image holds no configuration and no credential. Every address, name,
# token and key is supplied at run time (packages/agentsafe/README.md,
# deploy/kubernetes/TrustedExecutor.yaml), and the process refuses to start
# with one missing, naming the variable and never its value. NODE_ENV is
# production, so the loopback doubles, plain HTTP, development posture and
# secrets in the environment are refused here.
#
# The runtime is distroless: no shell, no package manager, a non-root user
# (65532), and node under its permission model, allowed to read the
# application and the secret mounts, to write only the journal directory,
# and to spawn nothing. The executor verifies that posture at start and
# refuses to run without it.

ARG NODE_BASE_IMAGE=public.ecr.aws/docker/library/node:22-alpine
ARG RUNTIME_BASE_IMAGE=gcr.io/distroless/nodejs22-debian12:nonroot@sha256:13593b7570658e8477de39e2f4a1dd25db2f836d68a0ba771251572d23bb4f8e

FROM ${NODE_BASE_IMAGE} AS base
RUN corepack enable && corepack prepare pnpm@9.15.3 --activate
WORKDIR /app

FROM base AS builder
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
# Every workspace manifest: pnpm resolves the whole graph before it installs
# anything, so the frozen install needs each importer the lockfile names.
COPY packages/agentsafe/package.json ./packages/agentsafe/
COPY packages/pipeline/package.json ./packages/pipeline/
COPY packages/commerce-mcp/package.json ./packages/commerce-mcp/
COPY packages/commerce-mcp-claude-extension/package.json ./packages/commerce-mcp-claude-extension/
COPY examples/basic-agent/package.json ./examples/basic-agent/
COPY examples/crm-outreach-demo/package.json ./examples/crm-outreach-demo/
COPY examples/github-deploy-agent/package.json ./examples/github-deploy-agent/
COPY examples/golden-adversarial-demo/package.json ./examples/golden-adversarial-demo/
COPY examples/local-escalation/package.json ./examples/local-escalation/
COPY examples/mcp-tool-gate/package.json ./examples/mcp-tool-gate/
COPY examples/presence-live-approval/package.json ./examples/presence-live-approval/
COPY examples/presence-managed-approval/package.json ./examples/presence-managed-approval/
COPY examples/procurement-agent/package.json ./examples/procurement-agent/
COPY examples/shopify-refund-agent/package.json ./examples/shopify-refund-agent/
COPY examples/trusted-executor/package.json ./examples/trusted-executor/
COPY examples/whisper-boundary-demo/package.json ./examples/whisper-boundary-demo/
COPY tests/integration/contract/package.json ./tests/integration/contract/
RUN pnpm install --frozen-lockfile --ignore-scripts \
  --filter @decionis/agentsafe...

COPY tsconfig.json ./
COPY scripts/CleanBuildOutput.mjs ./scripts/
COPY packages/pipeline ./packages/pipeline
COPY packages/agentsafe ./packages/agentsafe
RUN pnpm --filter @decionis/agent-safe-pipeline build \
  && pnpm --filter @decionis/agentsafe build \
  && pnpm deploy --filter @decionis/agentsafe --prod /app/deploy

# The runtime has no shell, no package manager and no workspace. The base
# image's entrypoint is node itself and its user is `nonroot` (65532); the
# manifest keeps the root filesystem read-only and drops every capability.
FROM ${RUNTIME_BASE_IMAGE} AS runner
LABEL org.opencontainers.image.source="https://github.com/decionis/agent-safe-pipeline" \
      org.opencontainers.image.title="AgentSafe trusted executor" \
      org.opencontainers.image.description="The execution boundary as one process: a proposal in, a verdict from the authority, one execution on a claimed single-use grant." \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/deploy ./
EXPOSE 8080
# Node's permission model: read the application and the mounts under
# /var/run/agent-safe, write only under /var/lib/agent-safe, and never a
# child process, a worker, or an addon. One path per flag.
CMD ["--permission", \
     "--allow-fs-read=/app", "--allow-fs-read=/app/*", \
     "--allow-fs-read=/var/run/agent-safe", "--allow-fs-read=/var/run/agent-safe/*", \
     "--allow-fs-write=/var/lib/agent-safe", "--allow-fs-write=/var/lib/agent-safe/*", \
     "/app/dist/Cli.js", "serve"]
