/**
 * cognium-dev#985 — TS/JS in-memory Map / property-bag `.get()` must not match the
 * sqlite `Connection.get` CWE-89 sink (`allow_unresolved_receiver`).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const flowTypes = async (code: string, file = 'helper.ts') => {
  const r = await analyze(code, file, 'typescript');
  return (r.taint.flows ?? []).map(f => f.sink_type);
};

const findingTypes = async (code: string, file = 'helper.ts') => {
  const r = await analyze(code, file, 'typescript');
  return generateFindings(r.taint.sources, r.taint.sinks, r.dfg).map(f => f.type);
};

describe('#985 — Map / properties .get is not a SQL Connection.get sink', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('properties.get on a pom property map has no sql_injection flow', async () => {
    const code = `
type Pom = { properties: Map<string, string> };
function resolve(p: Pom, prop: string) {
  const v = p.properties.get(prop);
  return v ?? null;
}
`;
    expect(await flowTypes(code)).toEqual([]);
    expect(await findingTypes(code)).not.toContain('sql_injection');
  });

  it('memoryCache.get on a local Map has no sql_injection flow', async () => {
    const code = `
const memoryCache = new Map<string, string>();
function load(digest: string) {
  return memoryCache.get(digest);
}
`;
    expect(await flowTypes(code)).toEqual([]);
    expect(await findingTypes(code)).not.toContain('sql_injection');
  });

  it('STILL fires for a real db.get with tainted SQL text', async () => {
    expect(
      await findingTypes(`function q(db: { get: (sql: string) => unknown }, name: string) {
  return db.get("SELECT * FROM t WHERE n='" + name + "'");
}`)
    ).toContain('sql_injection');
  });
});
