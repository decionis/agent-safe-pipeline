# AgentOps: CommerceGate MCP for Amazon Bedrock AgentCore Runtime, built
# from the repository root as the build context:
#
#   docker buildx build -f packages/commerce-mcp/Dockerfile --platform linux/arm64 -t agentops-core:latest .
#
# The container is the "AgentOps MCP Server for Amazon Bedrock AgentCore" delivery for buyers who run
# their agents in AgentCore: a stateless streamable-HTTP MCP server on
# 0.0.0.0:8000/mcp, with /ping as its health check, exactly as the runtime
# expects. It holds no credential: the buyer's workspace key and organization
# arrive as DECIONIS_API_KEY and DECIONIS_ORG_ID at launch (the listing names
# them as environment variables), and the server refuses tenant calls until
# both are present. DECIONIS_API_BASE defaults to https://api.decionis.com.
#
#   docker run -p 127.0.0.1:8000:8000 --env-file ./agentops.env agentops-core:latest
#
# The runtime is distroless: no shell, no package manager, a non-root user
# (65532), node under its permission model allowed to read the application
# and nothing else, and no child process.
ARG NODE_BASE_IMAGE=public.ecr.aws/docker/library/node:22-alpine@sha256:b6f26b36c8ff49624cfdac716b8ea1138d606df02586a77d364bb5536a634f85
ARG RUNTIME_BASE_IMAGE=gcr.io/distroless/nodejs22-debian12:nonroot@sha256:13593b7570658e8477de39e2f4a1dd25db2f836d68a0ba771251572d23bb4f8e

# Install and build on the builder's own platform whatever the target: the
# server is JavaScript with no native addon, so the bytes are the same for
# both architectures, and only the runtime stage below is per platform.
FROM --platform=$BUILDPLATFORM ${NODE_BASE_IMAGE} AS base
RUN corepack enable && corepack prepare pnpm@9.15.3 --activate
WORKDIR /app

FROM base AS builder
# Every workspace manifest: pnpm resolves the whole graph before it installs
# anything, so the frozen install needs each importer the lockfile names.
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/agentsafe/package.json ./packages/agentsafe/
COPY packages/pipeline/package.json ./packages/pipeline/
COPY packages/commerce-mcp/package.json ./packages/commerce-mcp/
COPY packages/commerce-mcp-claude-extension/package.json ./packages/commerce-mcp-claude-extension/
COPY examples/basic-agent/package.json ./examples/basic-agent/
COPY examples/crm-outreach-demo/package.json ./examples/crm-outreach-demo/
COPY examples/github-deploy-agent/package.json ./examples/github-deploy-agent/
COPY examples/golden-adversarial-demo/package.json ./examples/golden-adversarial-demo/
COPY examples/infra-scale-demo/package.json ./examples/infra-scale-demo/
COPY examples/local-escalation/package.json ./examples/local-escalation/
COPY examples/mcp-tool-gate/package.json ./examples/mcp-tool-gate/
COPY examples/presence-live-approval/package.json ./examples/presence-live-approval/
COPY examples/presence-managed-approval/package.json ./examples/presence-managed-approval/
COPY examples/procurement-agent/package.json ./examples/procurement-agent/
COPY examples/shopify-refund-agent/package.json ./examples/shopify-refund-agent/
COPY examples/trusted-executor/package.json ./examples/trusted-executor/
COPY examples/whisper-boundary-demo/package.json ./examples/whisper-boundary-demo/
COPY tests/integration/contract/package.json ./tests/integration/contract/
RUN pnpm install --frozen-lockfile --ignore-scripts --filter @decionis/commerce...
COPY tsconfig.json ./
COPY packages/commerce-mcp ./packages/commerce-mcp
RUN pnpm --filter @decionis/commerce build \
  && pnpm deploy --filter @decionis/commerce --prod /app/deploy

FROM ${RUNTIME_BASE_IMAGE} AS runner
LABEL org.opencontainers.image.source="https://github.com/decionis/agent-safe-pipeline" \
      org.opencontainers.image.title="AgentOps MCP Server for Amazon Bedrock AgentCore" \
      org.opencontainers.image.description="The CommerceGate MCP server for Amazon Bedrock AgentCore Runtime: an agent asks before it acts on commerce; allow or hold, the reason, a signed record." \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
ENV NODE_ENV=production
ENV MCP_TRANSPORT=http
ENV PORT=8000
ENV HOST=0.0.0.0
COPY --from=builder /app/deploy ./
EXPOSE 8000
ENTRYPOINT ["/nodejs/bin/node", "--permission", \
     "--allow-fs-read=/app", "--allow-fs-read=/app/*", \
     "/app/dist/Index.js"]
CMD ["--http"]
