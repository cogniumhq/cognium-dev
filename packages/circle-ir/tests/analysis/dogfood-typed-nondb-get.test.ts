/**
 * cognium-dev#985 follow-up (dogfood 2026-10-31, cognium-ai classification-cache.ts):
 * `this.backend.get(cacheKey)` with `private backend: CacheBackend` was still a
 * critical sql_injection (the sqlite `Connection.get` entry with an unresolved
 * receiver). An explicitly typed, non-database receiver is not a SQL sink.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const sqlSinks = async (code: string) =>
  (await analyze(code, 'c.ts', 'typescript')).taint.sinks.filter(s => s.type === 'sql_injection');

describe('typed non-DB receiver .get() is not a SQL sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('drops it for a CacheBackend field', async () => {
    const code = `interface CacheBackend { get(k: string): Promise<string | null> }\nexport class C {\n  private backend: CacheBackend;\n  constructor(b: CacheBackend) { this.backend = b; }\n  async read(key: string) {\n    return this.backend.get(key);\n  }\n}`;
    expect(await sqlSinks(code)).toHaveLength(0);
  });

  it('drops it when a same-named parameter elsewhere has another type (real shape)', async () => {
    const code = `interface CacheBackend { kind: string; get(k: string): Promise<string | null> }\nexport class C {\n  private backend: CacheBackend;\n  constructor(b: CacheBackend) { this.backend = b; }\n  async read(key: string) {\n    return this.backend.get(key);\n  }\n  stats() { return { backend: this.backend.kind }; }\n}\nfunction countersFor(namespace: string, backend: string) { return namespace + backend; }`;
    expect(await sqlSinks(code)).toHaveLength(0);
  });

  it('keeps it for a Database-typed receiver', async () => {
    const code = `import { Database } from 'sqlite3';\nexport class R {\n  private db: Database;\n  constructor(d: Database) { this.db = d; }\n  find(q: string) {\n    return this.db.get(q);\n  }\n}`;
    expect((await sqlSinks(code)).length).toBeGreaterThan(0);
  });

  it('keeps it for an untyped receiver', async () => {
    const code = `export function f(db: any, q: string) {\n  return db.get(q);\n}`;
    expect((await sqlSinks(code)).length).toBeGreaterThan(0);
  });
});
