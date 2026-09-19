#!/usr/bin/env node
/**
 * Build the CLI with embedded build provenance (git SHA + timestamp).
 *
 * Replaces a bare `bun build` so `cognium-dev --version` can report the exact
 * source the artifact was built from — a version string alone is not enough in
 * a workspace where `dist/` is a symlinked, un-invalidated build artifact
 * (cognium-dev#279 part 3).
 *
 * Pass `--standalone` to produce the compiled single-file binary instead of the
 * dist bundle. The provenance is passed through `bun build --define`, so it is
 * baked into the bundle rather than written to a committed source file (which
 * would dirty the tree on every build).
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, realpathSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function capture(cmd, cmdArgs, fallback) {
  try {
    return execFileSync(cmd, cmdArgs, { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
  } catch {
    return fallback;
  }
}

/**
 * Fail the build if the `circle-ir` that will be BUNDLED is not the workspace
 * one (cognium-dev#383).
 *
 * `circle-ir` is bundled into `dist/cli.js`, not left external — so whatever
 * copy the bundler resolves at build time IS the engine that ships, and the
 * exact pin in package.json has no say in it. A `bun install` run inside
 * `packages/cli` resolves that exact, registry-published pin by DOWNLOADING it
 * instead of linking the workspace, leaving a physical
 * `packages/cli/node_modules/circle-ir` that shadows the root symlink.
 *
 * That happened on 2026-09-10 and went unnoticed for six releases: every CLI
 * bundle from 4.9.12 through 4.9.17 embedded circle-ir 4.9.11 while its
 * package.json claimed the matching version. `--version` was right, the
 * dependency pin was right, the tests passed, and the engine was ten fixes
 * stale. Nothing in the pipeline could see it, because the stale copy is a
 * valid install of a real published version.
 *
 * So the check is on the resolved PATH, not the version string: a version
 * match would also be satisfied by a downloaded copy of the same number,
 * which is still the wrong artifact (it lacks anything unreleased).
 */
function assertWorkspaceEngine() {
  const here = dirname(fileURLToPath(import.meta.url));
  const cliRoot = resolve(here, '..');
  const workspaceEngine = realpathSync(resolve(cliRoot, '..', 'circle-ir'));

  const nested = join(cliRoot, 'node_modules', 'circle-ir');
  const resolvedRoot = existsSync(nested)
    ? realpathSync(nested)
    : realpathSync(join(cliRoot, '..', '..', 'node_modules', 'circle-ir'));

  if (resolvedRoot !== workspaceEngine) {
    const v = (dir) => {
      try { return JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).version; }
      catch { return '?'; }
    };
    console.error(`
ERROR: the CLI bundle would embed a non-workspace circle-ir.

  would bundle : ${resolvedRoot}  (${v(resolvedRoot)})
  workspace    : ${workspaceEngine}  (${v(workspaceEngine)})

circle-ir is bundled into dist/cli.js, so this copy — not the package.json
pin — is the engine that ships. Remove the shadowing install and rebuild:

  rm -rf packages/cli/node_modules/circle-ir
  npm run build -w packages/circle-ir

See cognium-dev#383. Do not publish a bundle built this way.`);
    process.exit(1);
  }
}

assertWorkspaceEngine();

const sha = capture('git', ['rev-parse', '--short', 'HEAD'], 'unknown');
const dirty = capture('git', ['status', '--porcelain'], '') ? '-dirty' : '';
const builtAt = new Date().toISOString();

// bun's define flag is `--define K=V` (space-separated; the esbuild-style
// `--define:K=V` colon form is silently ignored). JSON.stringify yields a valid
// JS string literal for V, e.g. `__BUILD_SHA__="a1b2c3d"`. Each value is its own
// argv element, so no shell quoting is involved.
const defines = [
  '--define', `__BUILD_SHA__=${JSON.stringify(sha + dirty)}`,
  '--define', `__BUILD_TIME__=${JSON.stringify(builtAt)}`,
];

const standalone = process.argv.includes('--standalone');
const base = ['build', 'src/cli.ts', '--external', 'pino-pretty', ...defines];
const buildArgs = standalone
  ? [...base, '--compile', '--outfile', 'cognium-dev']
  : [...base, '--outdir', 'dist', '--target', 'node', '--format', 'esm'];

execFileSync('bun', buildArgs, { stdio: 'inherit' });
console.log(`✓ built with provenance ${sha}${dirty} @ ${builtAt}`);
