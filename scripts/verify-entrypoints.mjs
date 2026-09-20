/**
 * Assert that a package's declared entrypoints exist in the built tree.
 *
 * `npm publish` does not check this: a stale `main`, a `types` pointing at a
 * path the build stopped emitting, or a `bin` whose file moved all publish
 * cleanly and fail at install time for whoever runs `npx cognium-dev`. This
 * repo ships two packages from one release script, so the failure would land
 * on users rather than in CI.
 *
 * Usage: node scripts/verify-entrypoints.mjs packages/<name> [--warn-only]
 *
 * `--warn-only` reports problems as GitHub warning annotations and exits 0.
 * That is for known-pending breaks: `continue-on-error` cannot be used for
 * this, because it masks the step's conclusion to success, so the report
 * becomes invisible in the checks UI — which is worse than not running.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';

const args = process.argv.slice(2);
const warnOnly = args.includes('--warn-only');
const dir = args.find(a => !a.startsWith('--'));
if (!dir) {
  console.error('usage: verify-entrypoints.mjs <package-dir>');
  process.exit(2);
}

const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
const missing = [];

const check = (label, rel) => {
  if (rel && !existsSync(join(dir, rel))) missing.push(`${label} -> ${rel}`);
};

check('main', pkg.main);
check('types', pkg.types ?? pkg.typings);

for (const [name, rel] of Object.entries(pkg.bin ?? {})) check(`bin.${name}`, rel);

// `exports` nests arbitrarily deep (conditions, subpaths); walk it rather than
// assuming the shape, and skip the `null` sentinel that blocks a subpath.
const walkExports = (node, path) => {
  if (node === null) return;
  if (typeof node === 'string') return check(`exports${path}`, node);
  if (typeof node === 'object') {
    for (const [key, value] of Object.entries(node)) walkExports(value, `${path}.${key}`);
  }
};
walkExports(pkg.exports, '');

if (missing.length) {
  const detail = missing.join(', ');
  if (warnOnly) {
    // GitHub renders this as an annotation on the run, so the finding is
    // visible without failing the job.
    console.log(`::warning title=${pkg.name} entrypoints missing::${detail} — declared in package.json but absent after build (see #403)`);
    console.error(`${pkg.name}: declared entrypoints missing after build: ${detail}`);
    process.exit(0);
  } else {
    console.error(`${pkg.name}: declared entrypoints missing after build:`);
    for (const m of missing) console.error(`  ${m}`);
    process.exit(1);
  }
}
console.log(`${pkg.name}: all declared entrypoints present`);
