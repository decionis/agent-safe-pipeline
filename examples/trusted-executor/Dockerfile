# The trusted executor as one image, built from the repository root as the
# build context:
#
#   docker build -f examples/trusted-executor/Dockerfile -t trusted-executor .
#
# The image holds no configuration and no credential. Every address, name,
# token and key is supplied at run time (examples/trusted-executor/README.md,
# deploy/kubernetes/TrustedExecutor.yaml), and the process refuses to start
# with one missing, naming the variable and never its value. NODE_ENV is
# production, so the loopback doubles and plain HTTP are refused here.

ARG NODE_BASE_IMAGE=public.ecr.aws/docker/library/node:22-alpine

FROM ${NODE_BASE_IMAGE} AS base
RUN corepack enable && corepack prepare pnpm@9.15.3 --activate
WORKDIR /app

FROM base AS builder
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
# Every workspace manifest: pnpm resolves the whole graph before it installs
# anything, so the frozen install needs each importer the lockfile names.
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
  --filter @decionis/agent-safe-example-trusted-executor...

COPY tsconfig.json ./
COPY scripts/CleanBuildOutput.mjs ./scripts/
COPY packages/pipeline ./packages/pipeline
COPY examples/trusted-executor ./examples/trusted-executor
RUN pnpm --filter @decionis/agent-safe-pipeline build \
  && pnpm --filter @decionis/agent-safe-example-trusted-executor build \
  && pnpm deploy --filter @decionis/agent-safe-example-trusted-executor --prod /app/deploy

# The runtime has no package manager and no workspace: node runs the built
# entry as a non-root user on a read-only root filesystem (the manifest sets
# the filesystem; the image sets the user).
FROM ${NODE_BASE_IMAGE} AS runner
LABEL org.opencontainers.image.source="https://github.com/decionis/agent-safe-pipeline" \
      org.opencontainers.image.title="Agent-Safe trusted executor" \
      org.opencontainers.image.description="The execution boundary as one process: a proposal in, a verdict from the authority, one execution on a claimed single-use grant." \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/deploy ./
USER node
EXPOSE 8080
CMD ["node", "dist/Serve.js"]
