/**
 * #1003: files run as programs, not imported, were reported entirely dead.
 * Files named in `package.json` scripts, files in script directories and
 * files starting with `#!` are `main` entries.
 */

import { describe, it, expect } from 'vitest';
import { buildTsCallGraph, DEFAULT_ENTRY_TABLES } from '../../src/navigation/index.js';
import { deadCode } from '../../src/graph-facts/index.js';

const pkg = JSON.stringify({
  name: 'tool',
  scripts: {
    build: 'node scripts/build.mjs && tsc -p .',
    bench: 'tsx ./bench/speed.ts --runs 3',
    lint: 'eslint "src/**/*.ts"',
  },
});

const files = [
  { path: 'packages/tool/scripts/build.mjs', code: 'function step() { return 1; }\nstep();\n' },
  { path: 'packages/tool/scripts/helper.mjs', code: 'export function help() { return 2; }\n' },
  { path: 'packages/tool/bench/speed.ts', code: 'function measure() { return 3; }\nmeasure();\n' },
  { path: 'packages/tool/bench/unused.ts', code: 'export function idle() { return 4; }\n' },
  { path: 'packages/tool/tools/run.js', code: '#!/usr/bin/env node\nfunction go() { return 5; }\ngo();\n' },
];

describe('dead code: programs are entry points (#1003)', () => {
  it('script arguments, script directories and shebang files are main entries', async () => {
    const g = await buildTsCallGraph(files, { packages: [{ root: 'packages/tool', packageJson: pkg }] });
    const rows = g.entries.filter(e => e.kind === 'main').map(e => `${e.certainty} ${e.file} ${e.evidence}`).sort();
    // One entry per file: build.mjs is both named by a script and in scripts/; the named one is kept.
    expect(rows).toEqual([
      'conventional packages/tool/scripts/helper.mjs file in a script directory',
      'conventional packages/tool/tools/run.js file starts with #!',
      'declared packages/tool/bench/speed.ts package.json script bench',
      'declared packages/tool/scripts/build.mjs package.json script build',
    ]);
    const v = Object.fromEntries(deadCode(g).facts.map(f => [f.qualified_name, f.verdict]));
    expect(Object.entries(v).filter(([q]) => q.includes('step') || q.includes('measure') || q.includes(':go')).every(([, x]) => x === 'live')).toBe(true);
    expect(Object.entries(v).find(([q]) => q.includes('idle'))?.[1]).toBe('dead');
  });

  it('without the scripts table nothing changes', async () => {
    const g = await buildTsCallGraph(files, {
      packages: [{ root: 'packages/tool', packageJson: pkg }],
      entryTables: { ...DEFAULT_ENTRY_TABLES, scripts: undefined },
    });
    expect(g.entries.filter(e => e.kind === 'main')).toEqual([]);
  });
});
