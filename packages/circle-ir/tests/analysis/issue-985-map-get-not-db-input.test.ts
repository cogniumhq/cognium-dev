/**
 * cognium-dev#985 (dogfood): `this.memoryCache.get(digest)` on a field the
 * class initialises with `new Map()` matched the JS/TS `cache.get` db_input
 * source by receiver name. It then paired with an unrelated `.get()` SQL sink
 * on the next line (`this.backend.get(cacheKey)`, backend untyped) and was
 * reported as a critical sql_injection. #1061 dropped Map receivers as sinks;
 * this is the source side.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const run = async (code: string, lang: 'javascript' | 'typescript') => {
  const ir = await analyze(code, lang === 'typescript' ? 'c.ts' : 'c.js', lang);
  return {
    dbSources: ir.taint.sources.filter(s => s.type === 'db_input'),
    sqlFlows: ir.taint.flows.filter(f => f.sink_type === 'sql_injection'),
  };
};

const cacheClass = (field: string) => `class Cache {
  constructor(backend) {
    this.backend = backend;
    ${field}
  }
  async get(digest) {
    const cacheKey = 'cls:' + digest;
    const a = this.memoryCache.get(digest);
    const raw = await this.backend.get(cacheKey);
    return a || raw;
  }
}
module.exports = { Cache };`;

describe('#985 a Map receiver .get() is not a db_input source', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('JS: this.memoryCache = new Map() — no db_input source, no sql_injection flow', async () => {
    const r = await run(cacheClass('this.memoryCache = new Map();'), 'javascript');
    expect(r.dbSources).toHaveLength(0);
    expect(r.sqlFlows).toHaveLength(0);
  });

  it('TS: a Map-typed class field', async () => {
    const code = `export class C {\n  private sessionCache: Map<string, string> = new Map();\n  read(k: string) { return this.sessionCache.get(k); }\n}`;
    expect((await run(code, 'typescript')).dbSources).toHaveLength(0);
  });

  it('TS: a WeakMap class field', async () => {
    const code = `export class C {\n  private resultCache = new WeakMap<object, string>();\n  read(o: object) { return this.resultCache.get(o); }\n}`;
    expect((await run(code, 'typescript')).dbSources).toHaveLength(0);
  });

  it('keeps the source for an untyped (injected) cache field', async () => {
    const code = `class S {\n  constructor(c) { this.redisCache = c; }\n  r(k) { return this.redisCache.get(k); }\n}\nmodule.exports = { S };`;
    expect((await run(code, 'javascript')).dbSources.length).toBeGreaterThan(0);
  });
});
