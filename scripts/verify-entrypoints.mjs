/**
 * Assert that a package's declared entrypoints exist in the built tree.
 *
 * `npm publish` does not check this: a stale `main`, a `types` pointing at a
 * path the build stopped emitting, or a `bin` whose file moved all publish
 * cleanly and fail at install time for whoever runs `npx cognium-dev`. This
 * repo ships two packages from one release script, so the failure would land
 * on users rather than in CI.
 *
 * Usage: node scripts/verify-entrypoints.mjs packages/<name>
 */
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';

const dir = process.argv[2];
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
  console.error(`${pkg.name}: declared entrypoints missing after build:`);
  for (const m of missing) console.error(`  ${m}`);
  process.exit(1);
}
console.log(`${pkg.name}: all declared entrypoints present`);
