import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "text-summary", "json-summary", "lcov"],
      include: ["src/**/*.ts"],
      // The export surface is asserted by name; the bin is the process the
      // image job runs unconfigured and expects to refuse.
      exclude: ["src/Index.ts", "src/Cli.ts"],
      thresholds: { lines: 90, functions: 90, statements: 90, branches: 85 },
    },
  },
});
