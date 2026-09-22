export default {
  config: {
    MD013: false,
    MD024: { siblings_only: true },
  },
  globs: [
    "**/*.md",
    "!**/node_modules/**",
    "!**/dist/**",
    "!**/coverage/**",
    "!brief.pipeline.md",
    "!brief.docker-ecosystem.md",
  ],
  // Local-only material is ignored by Git and must be ignored here too, or a
  // planning note in the working tree fails the lint of files that are tracked.
  gitignore: true,
};
