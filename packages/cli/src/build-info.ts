/**
 * Build provenance for the compiled CLI.
 *
 * `__BUILD_SHA__` / `__BUILD_TIME__` are replaced with string literals at
 * bundle time by scripts/build.mjs (`bun build --define`). In an unbuilt
 * source run (`bun run dev`, `bun test`) they are undefined, so the values
 * fall back to a source-run marker. The `typeof` guards are required: a bare
 * reference to an undefined identifier would throw, but `typeof` does not.
 *
 * Do not edit manually — provenance is injected by the build, not committed.
 */
declare const __BUILD_SHA__: string | undefined;
declare const __BUILD_TIME__: string | undefined;

export const buildInfo: { gitSha: string; builtAt: string | null } = {
  gitSha: typeof __BUILD_SHA__ === 'string' ? __BUILD_SHA__ : 'source',
  builtAt: typeof __BUILD_TIME__ === 'string' ? __BUILD_TIME__ : null,
};
