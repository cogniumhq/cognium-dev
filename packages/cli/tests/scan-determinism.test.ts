/**
 * #1032 — the same tree gives the same scan on every run and runtime.
 *
 * Under Bun, `node:v8`'s `heap_size_limit` is JavaScriptCore's current heap
 * size (~190 MB, different per run), so the heap-derived source ceiling cut
 * each scan at a different file. The ceiling is now fixed under Bun, and the
 * walk is in name order.
 */
import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, relative, sep } from 'path';
import { collectFiles, defaultMaxProjectSourceChars, FIXED_MAX_PROJECT_SOURCE_CHARS } from '../src/cli';

const CLI = join(import.meta.dir, '..', 'src', 'cli.ts');
const FILES = 30;
let root: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'cog-det-'));
  // ~10M chars: over the 1–5M ceiling Bun's heap figure used to give,
  // well under the fixed 32M.
  for (let f = 0; f < FILES; f++) {
    // Long string literals: many chars, few syntax nodes, so analysis is quick.
    const lines = [`import { readFileSync } from 'fs';`];
    for (let i = 0; i < 200; i++) lines.push(`export const s${f}_${i} = '${'x'.repeat(1600)}';`);
    lines.push(`export function read${f}(p: string): string { return readFileSync(p, 'utf-8'); }`);
    const dir = join(root, 'src', f % 2 ? 'b' : 'a');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, `file${String(FILES - f).padStart(2, '0')}.ts`), lines.join('\n') + '\n');
  }
});

afterAll(() => rmSync(root, { recursive: true, force: true }));

describe('source ceiling', () => {
  test('fixed under Bun, whatever the heap figure says', () => {
    expect(defaultMaxProjectSourceChars({ bun: '1.4.4' }, () => 195_256_320)).toBe(FIXED_MAX_PROJECT_SOURCE_CHARS);
    expect(defaultMaxProjectSourceChars({ bun: '1.4.4' }, () => 194_560_000)).toBe(FIXED_MAX_PROJECT_SOURCE_CHARS);
  });

  test('heap-derived under Node', () => {
    expect(defaultMaxProjectSourceChars({}, () => 2048 * 1024 * 1024)).toBe(2048 * 7_000);
    expect(defaultMaxProjectSourceChars({}, () => Number.NaN)).toBe(FIXED_MAX_PROJECT_SOURCE_CHARS);
    expect(defaultMaxProjectSourceChars({}, () => { throw new Error('no v8'); })).toBe(FIXED_MAX_PROJECT_SOURCE_CHARS);
  });
});

test('collectFiles walks in name order', async () => {
  const files = (await collectFiles(root, { basePath: root })).map((f) => relative(root, f).split(sep).join('/'));
  expect(files).toEqual([...files].sort());
  expect(files.length).toBe(FILES);
});

test('three scans give the same complete result', async () => {
  const outs: string[] = [];
  for (let i = 0; i < 3; i++) {
    const proc = Bun.spawn([process.execPath, 'run', CLI, 'scan', join(root, 'src'), '-f', 'json', '-q'], {
      cwd: root, stdout: 'pipe', stderr: 'pipe',
    });
    const text = await new Response(proc.stdout).text();
    await proc.exited;
    const j = JSON.parse(text);
    expect(j.summary.filesScanned).toBe(FILES);
    expect(j.project_size_budget_exceeded).toBeFalsy();
    delete j.timestamp;
    outs.push(JSON.stringify(j));
  }
  expect(outs[1]).toBe(outs[0]);
  expect(outs[2]).toBe(outs[0]);
}, 180_000);
