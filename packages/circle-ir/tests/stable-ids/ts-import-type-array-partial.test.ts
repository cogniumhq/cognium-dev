/**
 * cognium-ai #855: the TypeScript grammar does not parse `import('m').T[]`,
 * and two of circle-ir's own passes use it. The recovery keeps every
 * declaration, so the file must not be marked partial, which would hold back
 * every dead-code verdict that depends on it. Real syntax errors still are.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadLanguage } from '../../src/core/parser.js';
import { deriveStableIds, type StableIdFile } from '../../src/stable-ids/index.js';

const wasmDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist', 'wasm');

beforeAll(async () => {
  await loadLanguage('tsx', join(wasmDir, 'tree-sitter-tsx.wasm'));
});

const ts = (code: string, file = 'src/a.ts') => deriveStableIds(code, file, 'typescript', { packageName: 'pkg' });
const names = (f: StableIdFile) => f.decls.map(d => d.name);

describe('import-type arrays do not make a TypeScript file partial', () => {
  const cases: Array<[string, string, string[]]> = [
    ['parameter', `function f(xs: import('./t').T[], n: number) { return n; }\nfunction after() {}`, ['f', 'after']],
    ['return type', `function f(): import('./t').T[] { return []; }\nfunction after() {}`, ['f', 'after']],
    ['class field', `class C { xs: import('./t').T[] = []; m() {} }\nfunction after() {}`, ['C', 'm', 'after']],
    ['interface member', `interface I { xs: readonly import('./t').T[]; }\nfunction after() {}`, ['I', 'after']],
    ['local const', `function f(c: boolean) {\n  const xs: import('./t').T[] = c ? [] : [];\n  return xs;\n}\nfunction after() {}`, ['f', 'after']],
    ['exported const', `export const xs: import('./t').T[] = [];\nexport function after() {}`, ['xs', 'after']],
    ['type alias', `export type A = import('./t').T[];\nfunction after() {}`, ['A', 'after']],
  ];

  for (const [label, code, expected] of cases) {
    it(`in a ${label}`, async () => {
      const f = await ts(code);
      expect(f.partial).toBe(false);
      for (const n of expected) expect(names(f)).toContain(n);
    });
  }

  it('still marks a genuinely broken file partial', async () => {
    const f = await ts(`function f(xs: import('./t').T[]) {}\nfunction broken( {`);
    expect(f.partial).toBe(true);
  });

  it('still marks an error outside a type partial', async () => {
    const f = await ts(`const a = ;\nfunction after() {}`);
    expect(f.partial).toBe(true);
  });

  it('still marks a const with a non-import missing semicolon partial', async () => {
    const f = await ts(`const a: Foo.Bar\n[] = 1 +;\nfunction after() {}`);
    expect(f.partial).toBe(true);
  });
});
