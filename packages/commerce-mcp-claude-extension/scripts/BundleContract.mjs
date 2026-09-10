export const MCPB_VERSION = "2.1.2";

export const PACKED_PACKAGE = Object.freeze({
  name: "@decionis/commercegate-claude-extension",
  version: "0.1.3",
  private: true,
  description: "MIT-licensed Claude Desktop extension wrapper for Decionis CommerceGate.",
  author: "Decionis, Inc.",
  license: "MIT",
  type: "module",
  repository: Object.freeze({
    type: "git",
    url: "https://github.com/decionis/agent-safe-pipeline.git",
    directory: "packages/commerce-mcp-claude-extension",
  }),
  homepage:
    "https://github.com/decionis/agent-safe-pipeline/tree/master/packages/commerce-mcp-claude-extension",
  engines: Object.freeze({ node: ">=20" }),
});

export const VENDORED_RUNTIME_PACKAGE = Object.freeze({
  name: "@decionis/commerce",
  version: "0.1.3",
  license: "Apache-2.0",
  type: "module",
  repository: Object.freeze({
    type: "git",
    url: "https://github.com/decionis/agent-safe-pipeline.git",
    directory: "packages/commerce-mcp",
  }),
});

export const BUNDLE_FILES = Object.freeze([
  "LICENSE",
  "README.md",
  "THIRD_PARTY_NOTICES.md",
  "dist/Index.js",
  "icon.png",
  "manifest.json",
  "package.json",
  "vendor/commerce-mcp/Index.js",
  "vendor/commerce-mcp/LICENSE",
  "vendor/commerce-mcp/NOTICE",
  "vendor/commerce-mcp/package.json",
]);

export const TOOL_NAMES = Object.freeze([
  "commercegate_describe_capabilities",
  "commercegate_validate_erp_transaction",
  "commercegate_evaluate_action",
  "commercegate_get_dossier",
  "commercegate_get_proof_packet",
  "commercegate_list_shadow_reports",
  "commercegate_summarize_shadow_reports",
]);
