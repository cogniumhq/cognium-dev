/**
 * `StableIdFile.parseError`: the first error, in source order, that made a
 * file partial (cognium-dev#1004), for every language with stable ids.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadLanguage } from '../../src/core/parser.js';
import { deriveStableIds } from '../../src/stable-ids/index.js';

const wasmDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist', 'wasm');

beforeAll(async () => {
  for (const l of ['tsx', 'java', 'python', 'go'] as const) await loadLanguage(l, join(wasmDir, `tree-sitter-${l}.wasm`));
});

const ts = (code: string) => deriveStableIds(code, 'src/a.ts', 'typescript', { packageName: 'pkg' });

describe('parseError', () => {
  it('is absent on a clean file, and on a file whose only errors cannot hide a declaration', async () => {
    const clean = await ts('export function f() {}');
    expect(clean.partial).toBe(false);
    expect('parseError' in clean).toBe(false);
    const benign = await ts(`export function f(xs: import('./t').T[]) { return xs; }`);
    expect(benign.partial).toBe(false);
    expect(benign.parseError).toBeUndefined();
  });

  it('is the first blocking error in source order, 1-based', async () => {
    const f = await ts(['export function f(xs: import(\'./t\').T[]) {}', 'function ok() {}', 'function broken( {', 'const later = ;'].join('\n'));
    expect(f.partial).toBe(true);
    expect(f.parseError).toMatchObject({ line: 3 });
    expect(f.parseError!.column).toBeGreaterThanOrEqual(1);
    expect(f.parseError!.nodeKind === 'ERROR' || f.parseError!.nodeKind.startsWith('MISSING ')).toBe(true);
    expect(typeof f.parseError!.parent).toBe('string');
  });

  it('names a missing token', async () => {
    const f = await ts('function g() {\n  return (1 + 2;\n}');
    expect(f.partial).toBe(true);
    expect(f.parseError!.line).toBe(2);
  });

  it('looks inside a root the grammar gave up on', async () => {
    // A parameter named `using` makes the whole program an ERROR node.
    const code = ['export function a() {}', '', 'export function b() {}', 'const c = (body: string, using = \'\') => body;', 'export function d() {}'].join('\n');
    const f = await ts(code);
    expect(f.partial).toBe(true);
    expect(f.parseError!.line).toBe(4);
    expect(f.parseError!.parent).not.toBe('ERROR');
  });

  it('is set for Java, Python and Go', async () => {
    const j = await deriveStableIds('class A {\n  void m() {}\n  void n( {\n}\n', 'src/A.java', 'java', {});
    expect(j.partial).toBe(true);
    expect(j.parseError!.line).toBe(3);
    const p = await deriveStableIds('def ok():\n    return 1\n\ndef bad(:\n    pass\n', 'app/m.py', 'python', {});
    expect(p.partial).toBe(true);
    expect(p.parseError!.line).toBe(4);
    const g = await deriveStableIds('package main\n\nfunc ok() {}\n\nfunc bad( {\n}\n', 'main.go', 'go', {});
    expect(g.partial).toBe(true);
    expect(g.parseError!.line).toBe(5);
  });
});
