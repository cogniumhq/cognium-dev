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
      "if (name.split(/[/\\\\]/).includes('..') || path.isAbsolute(name)) {",
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

  // #1416 review 1: the guard checked the raw value; a decoded or rewritten one is not covered.
  it('recall: a decoded value after the guard still reports (%2e%2e/ passes the raw check)', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      'const full = path.join(ROOT, decodeURIComponent(name));',
      'fs.readFileSync(full);',
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('recall: a .replace-derived value after the guard still reports', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.includes('..')) throw new Error('x');",
      // inline: the engine carries taint through `.replace(…)` only as a call argument here, not
      // into a separate `const n2 = name.replace(…)` (that form reports nothing with or without a guard)
      "const full = path.join(ROOT, name.replace(/%2e/gi, '.'));",
      'fs.readFileSync(full);',
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('a plain alias of the guarded value is still credited', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.includes('..')) throw new Error('x');",
      'const safe = name;',
      'fs.readFileSync(path.join(ROOT, safe));',
    ].join('\n');
    expect(await pathTraversalFlows(code)).toHaveLength(0);
  });

  // #1416 re-review 1: an alias is followed, so decoding it later is the same as decoding the name.
  it('recall: a plain alias decoded after the guard still reports', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      'const safe = name;',
      'fs.readFileSync(path.join(ROOT, decodeURIComponent(safe)));',
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('an alias of an alias used as is is still credited', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.includes('..')) throw new Error('x');",
      'const safe = name;',
      'const safer = safe;',
      'fs.readFileSync(path.join(ROOT, safer));',
    ].join('\n');
    expect(await pathTraversalFlows(code)).toHaveLength(0);
  });

  // #1416 re-review 2: only path calls and path sinks are credited; any other callee may rewrite.
  it('recall: a local decoding wrapper after the guard still reports', async () => {
    const code = [
      ...head,
      'const dec = (s: string) => decodeURIComponent(s);',
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      'fs.readFileSync(path.join(ROOT, dec(name)));',
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('recall: a local wrapper on the alias still reports', async () => {
    const code = [
      ...head,
      'const dec = (s: string) => decodeURIComponent(s);',
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.includes('..')) throw new Error('x');",
      'const safe = name;',
      'fs.readFileSync(path.join(ROOT, dec(safe)));',
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('path.resolve and a direct fs read of the guarded name are credited', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.includes('..')) throw new Error('x');",
      'fs.createReadStream(path.resolve(ROOT, name));',
    ].join('\n');
    expect(await pathTraversalFlows(code)).toHaveLength(0);
  });

  // #1416 re-review 3, point 1: every call around the guarded value must be a path call.
  it('recall: a decode around the path builder still reports', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      'fs.readFileSync(decodeURIComponent(path.join(ROOT, name)));',
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('recall: a rewrite of the path builder result on the same line still reports', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.includes('..')) throw new Error('x');",
      "fs.readFileSync(path.join(ROOT, name).replace(/%2e/gi, '.'));",
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  // #1416 re-review 3, point 2: the builder's result is followed like an alias.
  it('recall: the path builder result decoded on a later line still reports', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      'const full = path.join(ROOT, name);',
      'fs.readFileSync(decodeURIComponent(full));',
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('the path builder result used as is by a sink is still credited', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.includes('..')) throw new Error('x');",
      'const full = path.join(ROOT, name);',
      'const again = full;',
      'fs.readFileSync(path.resolve(again));',
    ].join('\n');
    expect(await pathTraversalFlows(code)).toHaveLength(0);
  });

  // #1416 re-review 3, point 3: a bare builder counts only when it comes from `path` / `node:path`.
  it('recall: a local `normalize` that decodes still reports', async () => {
    const code = [
      ...head,
      'const normalize = (s: string) => decodeURIComponent(s);',
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      'fs.readFileSync(path.join(ROOT, normalize(name)));',
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('recall: a `path` receiver that is not the path module still reports', async () => {
    const code = [
      "import fs from 'fs';",
      "const ROOT = '/srv/data';",
      'const path = { isAbsolute: (s: string) => s.startsWith("/"), join: (a: string, b: string) => a + "/" + decodeURIComponent(b) };',
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.includes('..')) throw new Error('x');",
      'fs.readFileSync(path.join(ROOT, name));',
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('a bare builder imported from `path` or `node:path` is credited', async () => {
    for (const imp of [
      "import { isAbsolute, join } from 'path';",
      "import { isAbsolute, join as pjoin } from 'node:path';",
      "const { isAbsolute, join } = require('path');",
      "const { isAbsolute, resolve: pjoin } = require('node:path');",
    ]) {
      const call = imp.includes('pjoin') ? 'pjoin' : 'join';
      const code = [
        "import fs from 'fs';",
        imp,
        "const ROOT = '/srv/data';",
        'const name = process.argv[2];',
        "if (isAbsolute(name) || name.includes('..')) throw new Error('x');",
        `fs.readFileSync(${call}(ROOT, name));`,
      ].join('\n');
      expect(await pathTraversalFlows(code), imp).toHaveLength(0);
    }
  });

  // #1416 re-review 3, point 4: only the guarded argument is credited.
  it('recall: another tainted argument of the path builder still reports', async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      'const other = process.argv[3];',
      "if (path.isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      'fs.readFileSync(path.join(ROOT, name, other));',
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('literal and constant arguments beside the guarded one are credited', async () => {
    const code = [
      ...head,
      "const SUB = 'files';",
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.includes('..')) throw new Error('x');",
      "fs.readFileSync(path.join(ROOT, SUB, 'v1', name));",
    ].join('\n');
    expect(await pathTraversalFlows(code)).toHaveLength(0);
  });

  // #1416 review 2: path.join on Windows splits on `\` too, so a POSIX-only segment test is not a guard.
  it("recall: a POSIX-only split('/') segment test still reports (`..\\x` passes it)", async () => {
    const code = [
      ...head,
      'const name = process.argv[2];',
      "if (path.isAbsolute(name) || name.split('/').includes('..')) throw new Error('x');",
      'fs.readFileSync(path.join(ROOT, name));',
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('a split on both separators, in either order or as an alternation, is credited', async () => {
    for (const split of ['/[\\\\/]/', '/[/\\\\]/', '/\\/|\\\\/']) {
      const code = [
        ...head,
        'const name = process.argv[2];',
        `if (path.isAbsolute(name) || name.split(${split}).includes('..')) throw new Error('x');`,
        'fs.readFileSync(path.join(ROOT, name));',
      ].join('\n');
      expect(await pathTraversalFlows(code), split).toHaveLength(0);
    }
  });
});
