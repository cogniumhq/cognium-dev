#!/usr/bin/env node
/**
 * Copy the tree-sitter runtime and grammar wasm files into dist/wasm
 * (cognium-dev#990).
 *
 * `analyze()` loads its grammars from dist/wasm. They used to be copied only by
 * `build:browser`, so a plain `npm run build` produced a dist the CLI could not
 * run ("ENOENT … dist/wasm/web-tree-sitter.wasm"). `build` now runs this too.
 * Fails loudly if a source file is missing rather than leaving a partial dist.
 */
import { copyFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(pkgRoot, 'dist', 'wasm');
mkdirSync(out, { recursive: true });

const require = createRequire(join(pkgRoot, 'package.json'));
let runtime;
try {
  // The package's `exports` hide package.json, so resolve its entry and look beside it.
  runtime = join(dirname(require.resolve('web-tree-sitter')), 'web-tree-sitter.wasm');
} catch {
  runtime = undefined;
}
if (!runtime || !existsSync(runtime)) {
  console.error('copy-wasm: web-tree-sitter.wasm not found — run `npm ci` first');
  process.exit(1);
}
copyFileSync(runtime, join(out, 'web-tree-sitter.wasm'));

const grammars = readdirSync(join(pkgRoot, 'wasm')).filter((f) => f.endsWith('.wasm'));
if (grammars.length === 0) {
  console.error('copy-wasm: no grammar files in wasm/');
  process.exit(1);
}
for (const g of grammars) copyFileSync(join(pkgRoot, 'wasm', g), join(out, g));
console.log(`copy-wasm: ${grammars.length + 1} file(s) → dist/wasm`);
