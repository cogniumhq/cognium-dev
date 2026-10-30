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

  // cognium-dev#997 — Cognium-on-Cognium baseline: class-field Maps read through
  // `this.` (63 critical sql_injection false positives on our own code).
  it('#997: this.<field>.get on a class-field Map has no sql_injection', async () => {
    const code = `
export class Cache {
  private memoryCache = new Map<string, string>();
  private readonly nested = new Map<string, Set<string>>();
  private readonly weak = new WeakMap<object, Map<string, string>>();
  private tryCatchMap: Map<string, number> = new Map();
  private readonly helperCache: ReadonlyMap<string, string>;
  private entries: Map<string, Buffer>;
  constructor() { this.helperCache = new Map(); this.entries = new Map(); }
  lookup(req: any) {
    const k = req.query.key;
    return [this.memoryCache.get(k), this.tryCatchMap.get(k), this.helperCache.get(k), this.entries.get(k), this.nested.get(k), this.weak.get(req)];
  }
}
`;
    expect(await flowTypes(code)).not.toContain('sql_injection');
    expect(await findingTypes(code)).not.toContain('sql_injection');
  });

  it('#997: a member chain whose last property is a Map-typed interface field has no sql_injection', async () => {
    const code = `
interface FileImport { resolved: Map<string, string>; }
interface Ctx { imports: Map<string, string>; }
export function look(req: any, fileImport: FileImport, ctx: Ctx) {
  const name = req.query.name;
  return [fileImport.resolved.get(name), ctx.imports.get(name)];
}
`;
    expect(await findingTypes(code)).not.toContain('sql_injection');
  });

  it('#997: STILL fires for this.db.get with tainted SQL text', async () => {
    const code = `
export class Repo {
  constructor(private db: any) {}
  byName(req: any) {
    const name = req.query.name;
    return this.db.get("SELECT * FROM t WHERE n='" + name + "'");
  }
}
`;
    expect(await findingTypes(code)).toContain('sql_injection');
  });

  it('STILL fires for a real db.get with tainted SQL text', async () => {
    expect(
      await findingTypes(`function q(db: { get: (sql: string) => unknown }, name: string) {
  return db.get("SELECT * FROM t WHERE n='" + name + "'");
}`)
    ).toContain('sql_injection');
  });
});
