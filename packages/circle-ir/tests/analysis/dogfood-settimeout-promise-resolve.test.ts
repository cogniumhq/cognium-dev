/**
 * Dogfood 2026-10-31 (controldeck harness): `new Promise((r) => setTimeout(r, ms))`,
 * the sleep idiom, was reported as CWE-94 code_injection. The Promise
 * executor's resolve / reject parameter is a function, never a string, so
 * setTimeout's eval-on-string sink does not apply to it.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const sinksAt = async (code: string, line: number) =>
  (await analyze(code, 'sleep.ts', 'typescript')).taint.sinks.filter(s => s.type === 'code_injection' && s.line === line);

describe('setTimeout with a Promise executor callback is not code injection', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('drops the sink for (r) => setTimeout(r, ms)', async () => {
    expect(await sinksAt(`function sleep(ms: number) {\n  return new Promise((r) => setTimeout(r, ms));\n}`, 2)).toHaveLength(0);
  });

  it('drops it for reject and for a function executor', async () => {
    expect(await sinksAt(`function t(ms: number) {\n  return new Promise(function (ok, fail) { setTimeout(fail, ms); });\n}`, 2)).toHaveLength(0);
  });

  it('keeps it for a string variable', async () => {
    expect((await sinksAt(`function run(code: string) {\n  setTimeout(code, 10);\n}`, 2)).length).toBeGreaterThan(0);
  });
});
