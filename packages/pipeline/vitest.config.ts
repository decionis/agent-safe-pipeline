import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "text-summary", "json-summary", "lcov"],
      include: ["src/**/*.ts"],
      // The loopback doubles are exercised by the wire-contract harness against
      // the packed tarball; their fault-injection paths are not coverage-gated.
      exclude: ["src/Index.ts", "src/testing/**"],
      thresholds: { lines: 90, functions: 90, statements: 90, branches: 85 },
    },
  },
});
