/**
 * Dogfood 2026-10-31 (cognium-ai benchmarks/lib/csharp-oracle-scoring.ts):
 * `tps.get(path.posix.join(...))` with `tps: ReadonlyMap<string, OracleCase>`
 * matched the `https.get` SSRF sink (`tps` ~ `https`). #997's in-memory Map
 * evidence now applies to every `.get` sink, not only SQL.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const ssrf = async (code: string) =>
  (await analyze(code, 's.ts', 'typescript')).taint.sinks.filter(s => s.type === 'ssrf');

describe('a Map-typed receiver .get() is not an SSRF sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('drops it for a ReadonlyMap parameter', async () => {
    const code = `import * as path from 'path';\nexport function paired(file: string, tps: ReadonlyMap<string, number>) {\n  return tps.get(path.posix.join(path.posix.dirname(file), 'x.cs'));\n}`;
    expect(await ssrf(code)).toHaveLength(0);
  });

  it('keeps https.get', async () => {
    const code = `import * as https from 'https';\nexport function f(u: string) {\n  return https.get(u);\n}`;
    expect((await ssrf(code)).length).toBeGreaterThan(0);
  });
});
