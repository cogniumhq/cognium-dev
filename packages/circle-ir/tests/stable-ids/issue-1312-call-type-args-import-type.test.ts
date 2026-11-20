/**
 * cognium-dev #1312: import type inside a call's type arguments must not mark
 * the file partial when every declaration survives tree-sitter recovery.
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
const names = (f: StableIdFile) => f.decls.map((d) => d.name);

describe('#1312 import type in call type arguments', () => {
  it('g<typeof import("m")>() does not mark the file partial', async () => {
    const code = `import { g } from './g';
function run() {
  return g<typeof import('./m')>();
}
export function after() {}
`;
    const f = await ts(code);
    expect(f.partial).toBe(false);
    for (const n of ['run', 'after']) expect(names(f)).toContain(n);
  });

  it('g<import("m").T>() does not mark the file partial', async () => {
    const code = `import { g } from './g';
function run() {
  return g<import('./m').T>();
}
export function after() {}
`;
    const f = await ts(code);
    expect(f.partial).toBe(false);
    for (const n of ['run', 'after']) expect(names(f)).toContain(n);
  });

  it('g<typeof import("m")>() in a block does not mark partial', async () => {
    const code = `import { g } from './g';
function run() {
  g<typeof import('./m')>();
}
function after() {}
`;
    const f = await ts(code);
    expect(f.partial).toBe(false);
    for (const n of ['run', 'after']) expect(names(f)).toContain(n);
  });

  it('return g<typeof import("m")>() does not mark partial', async () => {
    const code = `import { g } from './g';
function f() {
  return g<typeof import('./m')>();
}
function after() {}
`;
    const f = await ts(code);
    expect(f.partial).toBe(false);
    for (const n of ['f', 'after']) expect(names(f)).toContain(n);
  });
});