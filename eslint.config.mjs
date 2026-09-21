import eslint from "@eslint/js";
import tseslint from "@typescript-eslint/eslint-plugin";
import parser from "@typescript-eslint/parser";
import regexp from "eslint-plugin-regexp";
import globals from "globals";

export default [
  {
    ignores: [
      "**/dist/**",
      "**/coverage/**",
      "**/node_modules/**",
      "**/.stryker-tmp/**",
      "packaging/sea/out/**",
      "packaging/sea/cache/**",
      // Maven's build output of the Java verifier, test reports included, and
      // Cargo's of the Rust one, generated documentation included.
      "verifiers/spring/target/**",
      "verifiers/rust/target/**",
      "verifiers/dotnet/**/bin/**",
      "verifiers/dotnet/**/obj/**",
    ],
  },
  eslint.configs.recommended,
  regexp.configs["flat/recommended"],
  { rules: { "regexp/no-super-linear-move": ["error", { report: "potential" }] } },
  {
    files: [
      "scripts/**/*.mjs",
      "test/**/*.mjs",
      "tests/**/*.mjs",
      "packages/*/scripts/**/*.mjs",
      "govern/src/**/*.mjs",
      "govern/test/**/*.mjs",
    ],
    languageOptions: { globals: globals.node },
  },
  {
    files: ["**/*.ts"],
    languageOptions: {
      parser,
      parserOptions: { project: "./tsconfig.json", tsconfigRootDir: import.meta.dirname },
      globals: globals.node,
    },
    plugins: { "@typescript-eslint": tseslint },
    rules: {
      ...tseslint.configs.recommended.rules,
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/no-explicit-any": "error",
      "no-console": "error",
    },
  },
  {
    // The trusted executor opens a socket in two places only: its listener and
    // its guarded egress. Every other module reaches the network through the
    // fetch it is handed, so a stray import here is a review finding, not a
    // style choice. A type import names a shape, not a socket.
    files: ["packages/agentsafe/src/**/*.ts"],
    ignores: ["packages/agentsafe/src/http/**/*.ts", "packages/agentsafe/src/egress/**/*.ts"],
    rules: {
      "@typescript-eslint/no-restricted-imports": [
        "error",
        {
          paths: ["node:http", "node:https", "node:net", "node:tls", "node:dgram", "undici"].map(
            (name) => ({
              name,
              message: "Sockets open only under src/http and src/egress; take a fetch instead.",
              allowTypeImports: true,
            }),
          ),
        },
      ],
    },
  },
  {
    // The CommerceGate MCP came in from decionis/Commerce with underscore-prefixed
    // unused parameters in its test doubles; keep that convention there.
    files: ["packages/commerce-mcp/**/*.ts"],
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" },
      ],
    },
  },
];
