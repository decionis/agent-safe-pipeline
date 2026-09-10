// This MIT-licensed entry point loads the separately bundled Apache-2.0
// CommerceGate runtime. Keeping the artifact separate preserves its license boundary.
const runtimeUrl = new URL("../vendor/commerce-mcp/Index.js", import.meta.url);

await import(runtimeUrl.href);
