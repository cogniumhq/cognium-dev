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

  // #1416 re-review 6, note 3: an import list over several lines binds its names too.
  it('a bare builder from an import list over several lines is credited', async () => {
    for (const imp of [
      ['import {', '  isAbsolute,', '  join,', "} from 'path';"],
      ['import {', '  isAbsolute,', '  join as pjoin,', "} from 'node:path';"],
      // a comment inside the list does not hide the names after it
      ['import {', '  isAbsolute, // was: normalize', '  join,', "} from 'path';"],
      ['import {', '  isAbsolute, /* was: normalize */', '  join,', "} from 'path';"],
    ]) {
      const call = imp.join(' ').includes('pjoin') ? 'pjoin' : 'join';
      const code = [
        "import fs from 'fs';",
        ...imp,
        "const ROOT = '/srv/data';",
        'const name = process.argv[2];',
        "if (isAbsolute(name) || name.includes('..')) throw new Error('x');",
        `fs.readFileSync(${call}(ROOT, name));`,
      ].join('\n');
      expect(await pathTraversalFlows(code), imp.join(' ')).toHaveLength(0);
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

  // #1416 re-review 4: a name declared again in an inner scope loses its file-level meaning.
  it('recall: an inner `let` over a top-level constant still reports', async () => {
    const code = [
      ...head,
      "const SUB = 'files';",
      'function serve() {',
      '  let SUB = process.argv[3];',
      '  const name = process.argv[2];',
      "  if (path.isAbsolute(name) || name.includes('..')) throw new Error('x');",
      '  return fs.readFileSync(path.join(ROOT, SUB, name));',
      '}',
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('recall: an inner `const join` that decodes, over `join` from path, still reports', async () => {
    const code = [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'function serve() {',
      "  const join = (a: string, b: string) => a + '/' + decodeURIComponent(b);",
      '  const name = process.argv[2];',
      "  if (isAbsolute(name) || name.includes('..')) throw new Error('x');",
      '  return fs.readFileSync(join(ROOT, name));',
      '}',
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('recall: an inner `const path = {join}` over the imported path module still reports', async () => {
    const code = [
      ...head,
      'function serve() {',
      "  const path = { isAbsolute: (s: string) => s.startsWith('/'), join: (a: string, b: string) => a + '/' + decodeURIComponent(b) };",
      '  const name = process.argv[2];',
      "  if (path.isAbsolute(name) || name.includes('..')) throw new Error('x');",
      '  return fs.readFileSync(path.join(ROOT, name));',
      '}',
    ].join('\n');
    expect((await pathTraversalFlows(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('recall: a parameter or `var` that shadows a path name still reports', async () => {
    for (const fn of [
      'function serve(path: { join: (a: string, b: string) => string }) {',
      'function serve(opts: object, { SUB }: { SUB: string }) {',
      'const serve = (SUB: string) => {',
      'function serve() { var SUB = process.argv[3];',
      'const serve = function (SUB: string) {',
    ]) {
      const code = [
        ...head,
        "const SUB = 'files';",
        fn,
        '  const name = process.argv[2];',
        "  if (path.isAbsolute(name) || name.includes('..')) throw new Error('x');",
        '  return fs.readFileSync(path.join(ROOT, SUB, name));',
        '}',
      ].join('\n');
      expect((await pathTraversalFlows(code)).length, fn).toBeGreaterThanOrEqual(1);
    }
  });

  it('the same guard inside a function, with no shadowing, is still credited', async () => {
    const code = [
      ...head,
      "const SUB = 'files';",
      'function serve(req: { query: { name: string } }) {',
      '  const name = process.argv[2];',
      "  if (path.isAbsolute(name) || name.includes('..')) throw new Error('x');",
      '  return fs.readFileSync(path.join(ROOT, SUB, name));',
      '}',
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
  // #1416 re-review 5: TypeScript parameter lists and destructuring that the old line-by-line scan missed.
  const tsShadows: Array<[string, string[]]> = [
    ['a method with a return type', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'export class S {',
      '  serve(join: (a: string, b: string) => string): Buffer {',
      '    const name = process.argv[2];',
      "    if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '    return fs.readFileSync(join(ROOT, name));',
      '  }',
      '}',
    ]],
    ['an arrow with a return type', [
      ...head,
      'export const serve = (path: { join(a: string, b: string): string }): Buffer => {',
      '  const name = process.argv[2];',
      "  if (path.isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return fs.readFileSync(path.join(ROOT, name));',
      '};',
    ]],
    ['a parameter list over several lines', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'export function serve(',
      '  join: (a: string, b: string) => string,',
      '  extra: number,',
      ') {',
      '  const name = process.argv[2];',
      "  if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return fs.readFileSync(join(ROOT, name));',
      '}',
    ]],
    ['a generic function', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'function serve<T>(join: (a: string, b: string) => string, t: T) {',
      '  const name = process.argv[2];',
      "  if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return fs.readFileSync(join(ROOT, name));',
      '}',
    ]],
    ['destructuring over several lines', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'function serve(h: { join: (a: string, b: string) => string }) {',
      '  const {',
      '    join,',
      '  } = h;',
      '  const name = process.argv[2];',
      "  if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return fs.readFileSync(join(ROOT, name));',
      '}',
    ]],
    ['a parameter after a regex literal with a lone quote', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      "const quote = /'/;",
      'function serve(join: (a: string, b: string) => string) {',
      '  const name = process.argv[2];',
      "  if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return fs.readFileSync(join(ROOT, name));',
      '}',
    ]],
    // #1416 re-review 6: the `{` of an object return type is not the arrow's body.
    ['an arrow with an object return type', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'export const serve = (join: (a: string, b: string) => string): { data: Buffer } => {',
      '  const name = process.argv[2];',
      "  if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return { data: fs.readFileSync(join(ROOT, name)) };',
      '};',
    ]],
    ['an arrow with an object return type over the default path import', [
      ...head,
      'export const serve = (path: { join(a: string, b: string): string }): { data: Buffer } => {',
      '  const name = process.argv[2];',
      "  if (path.isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return { data: fs.readFileSync(path.join(ROOT, name)) };',
      '};',
    ]],
    ['an arrow with an object return type over several lines', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'export const serve = (join: (a: string, b: string) => string): {',
      '  data: Buffer;',
      '} => {',
      '  const name = process.argv[2];',
      "  if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return { data: fs.readFileSync(join(ROOT, name)) };',
      '};',
    ]],
    ['a class field arrow with an object return type', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'export class S {',
      '  serve = (join: (a: string, b: string) => string): { data: Buffer } => {',
      '    const name = process.argv[2];',
      "    if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '    return { data: fs.readFileSync(join(ROOT, name)) };',
      '  };',
      '}',
    ]],
    // #1416 re-review 6, note 2: a `/*` or `//` inside a regex literal does not open a comment.
    ['a parameter after a regex literal with `/*` in it', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'const glob = /[/*]/;',
      'function serve(join: (a: string, b: string) => string) {',
      '  const name = process.argv[2];',
      "  if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return fs.readFileSync(join(ROOT, name));',
      '}',
      '/** a later doc comment */',
      'export { glob, serve };',
    ]],
    ['a parameter after a regex literal with `//` in it, on the same line', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'const slashes = /[//]/; function serve(join: (a: string, b: string) => string) {',
      '  const name = process.argv[2];',
      "  if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return fs.readFileSync(join(ROOT, name));',
      '}',
    ]],
    // a regex literal after `return`, `=>` or an operator
    ['a parameter after a regex literal returned (`return /[/*]/`)', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'function g() { return /[/*]/; }',
      'function serve(join: (a: string, b: string) => string) {',
      '  const name = process.argv[2];',
      "  if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return fs.readFileSync(join(ROOT, name));',
      '}',
    ]],
    ['a parameter after a regex literal after `=>`', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'const g = () => /[/*]/;',
      'function serve(join: (a: string, b: string) => string) {',
      '  const name = process.argv[2];',
      "  if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return fs.readFileSync(join(ROOT, name));',
      '}',
    ]],
    ['a parameter after a regex literal after `+`', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'const h = 1 + /[/*]/.source.length;',
      'function serve(join: (a: string, b: string) => string) {',
      '  const name = process.argv[2];',
      "  if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return fs.readFileSync(join(ROOT, name));',
      '}',
    ]],
    ['a parameter after a regex literal after `typeof`', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'const t = typeof /[/*]/;',
      'function serve(join: (a: string, b: string) => string) {',
      '  const name = process.argv[2];',
      "  if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return fs.readFileSync(join(ROOT, name));',
      '}',
    ]],
    ['a parameter after a regex literal after `yield`', [
      "import fs from 'fs';",
      "import { isAbsolute, join } from 'path';",
      "const ROOT = '/srv/data';",
      'function* gen() { yield /[/*]/; }',
      'function serve(join: (a: string, b: string) => string) {',
      '  const name = process.argv[2];',
      "  if (isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
      '  return fs.readFileSync(join(ROOT, name));',
      '}',
    ]],
  ];

  for (const [shape, lines] of tsShadows) {
    it(`recall: ${shape} that declares a path name again still reports`, async () => {
      expect(await pathTraversalFlows(lines.join('\n'))).toHaveLength(1);
    });
  }

  it('the same TypeScript shapes with no shadowing are still credited', async () => {
    for (const fn of [
      ['export class S {', '  serve(req: { q: string }): Buffer {'],
      ['export const serve = (req: { q: string }): Buffer => {'],
      ['export function serve(', '  req: { q: string },', '  extra: number,', ') {'],
      ['function serve<T>(req: { q: string }, t: T) {'],
      ['export const serve = (req: { q: string }): { data: Buffer } => {'],
      ['export function serve(req: { q: string }): { data: Buffer } {'],
      ['export class S {', '  serve(req: { q: string }): { data: Buffer } {'],
    ]) {
      const code = [
        ...head,
        ...fn,
        '  const name = process.argv[2];',
        "  if (path.isAbsolute(name) || name.split(/[\\\\/]/).includes('..')) throw new Error('x');",
        '  return fs.readFileSync(path.join(ROOT, name));',
        ...(fn[0] === 'export class S {' ? ['  }', '}'] : ['}']),
      ].join('\n');
      expect(await pathTraversalFlows(code), fn.join(' ')).toHaveLength(0);
    }
  });
});
