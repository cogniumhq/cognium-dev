/**
 * Dogfood 2026-11-01 (circle-pack findings store): `.get` / `.all` / `.run` /
 * `.each` / `.iterate` / `.pluck` on a prepared statement take bound
 * parameters, so a request value passed as a `?` binding is not SQL
 * injection. The `Connection` rows for sqlite3's `db.get(sql)` matched
 * `db.prepare(sql).get(...params)` as well. sqlite3's own `db.get(sql)` /
 * `db.all(sql)` (SQL in argument 0) stay sinks.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze, analyzeProject } from '../../src/analyzer.js';

const sqlSinks = async (code: string) =>
  (await analyze(code, 's.ts', 'typescript')).taint.sinks.filter(s => s.type === 'sql_injection');

const store = (body: string) => `import Database from 'better-sqlite3';
export class Store {
  private db: Database.Database;
  private byId: Database.Statement;
  constructor(p: string) {
    this.db = new Database(p);
    this.byId = this.db.prepare('SELECT * FROM f WHERE id = ?');
  }
  find(id: string, params: string[]) {
${body}
  }
}
`;

describe('prepared statement methods take bound parameters', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('chained off prepare(): not a sql_injection sink', async () => {
    expect(await sqlSinks(store(`    return this.db.prepare('SELECT * FROM f WHERE id = ?').get(id);`))).toHaveLength(0);
    expect(await sqlSinks(store(`    return this.db.prepare(\`SELECT COUNT(*) FROM f \${id ? 'WHERE id = ?' : ''}\`).all(...params);`))).toHaveLength(0);
    expect(await sqlSinks(store(`    return this.db\n      .prepare('UPDATE f SET n = ? WHERE id = ?')\n      .run(params[0], id);`))).toHaveLength(0);
  });

  it('a variable or field assigned from prepare(): not a sink', async () => {
    expect(await sqlSinks(store(`    return this.byId.get(id);`))).toHaveLength(0);
    expect(await sqlSinks(store(`    const st = this.db.prepare('SELECT * FROM f WHERE id = ?');\n    return st.all(id);`))).toHaveLength(0);
  });

  it("sqlite3's Database.get / all / run with SQL in argument 0 stay sinks", async () => {
    const code = `import sqlite3 from 'sqlite3';
const db = new sqlite3.Database('x.db');
export function q(req: any) {
  db.get('SELECT * FROM f WHERE id = ' + req.query.id, () => {});
  db.all(\`SELECT * FROM f WHERE n = '\${req.body.n}'\`, () => {});
}
`;
    expect((await sqlSinks(code)).length).toBe(2);
  });

  it('the cross-file shape from the store: a route value bound as a parameter is no path', async () => {
    const st = `import Database from 'better-sqlite3';
export class FindingsStore {
  private db: Database.Database;
  constructor(dbPath: string = 'x.db') { this.db = new Database(dbPath); }
  getStats(options: { job_id?: string } = {}) {
    const where = options.job_id ? 'WHERE job_id = ?' : '';
    const params = options.job_id ? [options.job_id] : [];
    return this.db.prepare(\`SELECT COUNT(*) FROM f \${where}\`).get(...params);
  }
}
export const store = new FindingsStore();
`;
    const route = `import { Hono } from 'hono';\nimport { store } from './store';\nconst app = new Hono();\napp.get('/stats', (c) => {\n  const job_id = c.req.query('job_id');\n  return c.json(store.getStats({ job_id }));\n});\n`;
    const r = await analyzeProject([
      { code: st, filePath: 'src/store.ts', language: 'typescript' },
      { code: route, filePath: 'src/routes.ts', language: 'typescript' },
    ]);
    expect((r.taint_paths ?? []).filter(p => p.sink?.type === 'sql_injection')).toHaveLength(0);
  });
});
