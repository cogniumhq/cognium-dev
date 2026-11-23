/**
 * #1137 (dogfood 2026-11-03, circle-pack `trust-runner.ts:337`):
 * `jobStore.updateMetrics(jobId, { files_analyzed: results.length })` passes
 * only the length of a tainted array, but the callee's sink was reported with
 * the array's `file_input` origin. In JS/TS, `name.length` is a number.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const reader = `import * as fs from 'fs';
export function loadSpec(p: string): string {
  const text = fs.readFileSync(p, 'utf8');
  return text;
}`;

const writer = `import * as fs from 'fs';
export function openAt(target: any): string {
  return fs.readFileSync(target, 'utf8');
}`;

const caller = (arg: string) => `import { loadSpec } from './reader';
import { openAt } from './writer';
export function run(input: string): void {
  const data = loadSpec(input);
  openAt(${arg});
}`;

async function pathsFor(arg: string): Promise<number> {
  const r = await analyzeProject([
    { code: reader, filePath: 'reader.ts', language: 'typescript' },
    { code: writer, filePath: 'writer.ts', language: 'typescript' },
    { code: caller(arg), filePath: 'caller.ts', language: 'typescript' },
  ]);
  return r.taint_paths.filter(t => t.source.file === 'reader.ts' && t.sink.file === 'writer.ts').length;
}

describe('#1137 JS/TS: .length of a tainted value carries no taint across a call', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('control: the tainted value itself reaches the callee sink', async () => {
    expect(await pathsFor('data')).toBeGreaterThan(0);
  });

  it('does not report data.length', async () => {
    expect(await pathsFor('data.length')).toBe(0);
  });

  it('does not report data?.length inside an object literal', async () => {
    expect(await pathsFor('{ files_analyzed: data?.length }')).toBe(0);
  });

  it('still reports the value when it is used besides its length', async () => {
    expect(await pathsFor('data.length + data')).toBeGreaterThan(0);
    expect(await pathsFor('{ n: data.length, body: data }')).toBeGreaterThan(0);
  });

  it('still reports a method call or index named like length', async () => {
    expect(await pathsFor('data.lengthy')).toBeGreaterThan(0);
  });
});
