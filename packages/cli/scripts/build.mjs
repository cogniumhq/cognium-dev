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

function capture(cmd, cmdArgs, fallback) {
  try {
    return execFileSync(cmd, cmdArgs, { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
  } catch {
    return fallback;
  }
}

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
