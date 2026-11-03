/**
 * cognium-dev#985 S2 — TS/JS literal-only local `Map` reads are not `plugin_param` sources
 * (port of #584 `isUnwrittenLocalMapKeyRead`).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

type IR = Awaited<ReturnType<typeof analyze>>;
const mapSources = (r: IR) =>
  (r.taint.sources ?? []).filter(s => s.type === 'plugin_param' && /\.get\(\)/.test(s.location ?? ''));

describe('#985 S2 — literal-only local Map reads are not plugin_param sources', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('literal-only Map.get has no plugin_param source or sql_injection finding', async () => {
    const code = `
export function labels() {
  const labels = new Map<string, string>();
  labels.set('title', 'Welcome');
  const title = labels.get('title');
  return title;
}
`;
    const r = await analyze(code, 'labels.ts', 'typescript');
    expect(mapSources(r)).toHaveLength(0);
    const types = generateFindings(r.taint.sources, r.taint.sinks, r.dfg).map(f => f.type);
    expect(types).not.toContain('sql_injection');
  });

  it('rename-proof: zz.get after literal sets has no source', async () => {
    const code = `
export function out() {
  const zz = new Map<string, string>();
  zz.set('k1', 'v1');
  zz.set('k2', 'v2');
  const got = zz.get('k2');
  return got;
}
`;
    const r = await analyze(code, 'out.ts', 'typescript');
    expect(mapSources(r)).toHaveLength(0);
  });

  it('tainted set on a key still reaches sql_injection sink', async () => {
    const code = `
export function handler(req: { query: { o: string } }) {
  const m = new Map<string, string>();
  m.set('title', 'Welcome');
  m.set('other', req.query.o);
  const db = { get: (sql: string) => sql };
  return db.get('SELECT ' + m.get('other'));
}
`;
    const r = await analyze(code, 'handler.ts', 'typescript');
    const types = generateFindings(r.taint.sources, r.taint.sinks, r.dfg).map(f => f.type);
    expect(types).toContain('sql_injection');
  });

  it('unwritten literal key on local Map has no source', async () => {
    const code = `
export function miss() {
  const m = new Map<string, string>();
  return m.get('missing');
}
`;
    const r = await analyze(code, 'miss.ts', 'typescript');
    expect(mapSources(r)).toHaveLength(0);
  });
});
