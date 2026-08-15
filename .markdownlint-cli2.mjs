export default {
  config: {
    MD013: false,
    MD024: { siblings_only: true },
  },
  globs: ["**/*.md", "!**/node_modules/**", "!**/dist/**", "!**/coverage/**", "!brief.pipeline.md"],
};
