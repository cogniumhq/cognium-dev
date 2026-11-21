/**
 * cognium-dev#1338 — localBinding must not rescan a block per call site.
 * Correctness: many member calls in one function still resolve callees.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadLanguage } from '../../src/core/parser.js';
import { buildTsCallGraph, type TsSourceFile } from '../../src/navigation/index.js';

const wasmDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist', 'wasm');
beforeAll(async () => {
  await loadLanguage('tsx', join(wasmDir, 'tree-sitter-tsx.wasm'));
});

const opts = { packageName: 'p' };
const src = (files: Record<string, string>): TsSourceFile[] =>
  Object.entries(files).map(([path, code]) => ({ path, code, ids: opts }));

describe('cognium-dev #1338 block binding index', () => {
  it('resolves many member calls in one function (negative: stays fast enough to finish)', async () => {
    const n = 400;
    const body = Array.from({ length: n }, (_, i) => `  k.m${i}(1);`).join('\n');
    const code = `export function heavy(k: any): void {\n${body}\n}\n`;
    const g = await buildTsCallGraph(src({ 'src/t.ts': code }));
    expect(g.sites).toBe(n);
    expect(g.unresolved.length).toBeGreaterThan(0);
    expect(g.unresolved.every(u => u.methodName.startsWith('m'))).toBe(true);
  }, 60_000);
});