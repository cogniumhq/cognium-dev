/**
 * cognium-dev#1305 E4 — JS/TS: a name rejected when it is absolute or has a
 * `..` segment cannot leave the directory it is joined onto.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function pathTraversalFlows(code: string, file = 'probe.ts', lang = 'typescript') {
  const r = await analyze(code, file, lang);
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'path_traversal');
}

const head = [
  "import fs from 'fs';",
  "import path from 'path';",
  "const ROOT = '/srv/data';",
];

describe('cognium-dev#1305 E4 — absolute-path and `..`-segment guard', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('single-line reject guard clears the joined read', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('bad name');",
      'const full = path.join(ROOT, name);',
      "console.log(fs.readFileSync(full, 'utf-8'));",
    ].join('\n');
    expect(await pathTraversalFlows(code)).toHaveLength(0);
  });

  it('block reject guard with the clauses swapped clears the read', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (name.split('/').includes('..') || path.isAbsolute(name)) {",
      "  throw new Error('bad name');",
      '}',
      "console.log(fs.readFileSync(path.join(ROOT, name), 'utf-8'));",
    ].join('\n');
    expect(await pathTraversalFlows(code)).toHaveLength(0);
  });

  it('recall: only the absolute check still reports', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (path.isAbsolute(name)) throw new Error('bad name');",
      'const full = path.join(ROOT, name);',
      "console.log(fs.readFileSync(full, 'utf-8'));",
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('recall: only the `..` check still reports', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (name.split('/').includes('..')) throw new Error('bad name');",
      "console.log(fs.readFileSync(name, 'utf-8'));",
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('recall: a guard that does not reject still reports', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.split('/').includes('..')) { console.warn('odd'); }",
      'const full = path.join(ROOT, name);',
      "console.log(fs.readFileSync(full, 'utf-8'));",
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('recall: a different variable on the guarded line still reports', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      'const other = process.argv[3];',
      "if (path.isAbsolute(name) || name.split('/').includes('..')) throw new Error('bad name');",
      "console.log(fs.readFileSync(other, 'utf-8'));",
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('plain JS with the substring `..` check clears the read', async () => {
    const code = [
      "const fs = require('fs');",
      "const path = require('path');",
      "const ROOT = '/srv/data';",
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.includes('..')) return;",
      "fs.readFileSync(path.join(ROOT, name), 'utf-8');",
    ].join('\n');
    expect(await pathTraversalFlows(code, 'probe.js', 'javascript')).toHaveLength(0);
  });

  it('recall: the two checks on different variables still report', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      'const other = process.argv[3];',
      "if (path.isAbsolute(other) || name.split('/').includes('..')) throw new Error('bad name');",
      "console.log(fs.readFileSync(path.join(ROOT, name), 'utf-8'));",
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('recall: a negated check (accept polarity) still reports', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (!path.isAbsolute(name) || !name.split('/').includes('..')) throw new Error('bad name');",
      "console.log(fs.readFileSync(path.join(ROOT, name), 'utf-8'));",
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });
});
