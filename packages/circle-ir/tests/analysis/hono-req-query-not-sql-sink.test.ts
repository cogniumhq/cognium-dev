/**
 * Hono `c.req.query(key)` reads a URL query parameter. It is a taint source,
 * never a SQL sink: the SQL `query` sink needs a database-client receiver
 * (pg / mysql / knex / drizzle shaped), not a request object.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const run = async (code: string, file = 'app.ts') => {
  const r = await analyze(code, file, 'typescript');
  return {
    sinks: r.taint.sinks.map(s => ({ type: s.type, line: s.line })),
    sources: r.taint.sources.map(s => ({ type: s.type, line: s.line })),
    flows: (r.taint.flows ?? []).map(f => f.sink_type),
    findings: generateFindings(r.taint.sources, r.taint.sinks, r.dfg).map(f => f.type),
  };
};

describe('Hono c.req.query is not a SQL sink', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('c.req.query("x") alone gives no SQL sink', async () => {
    const r = await run(`
import { Hono } from 'hono';
const app = new Hono();
app.get('/search', (c) => {
  const q = c.req.query('q');
  return c.text(q ?? '');
});
`);
    expect(r.sinks.filter(s => s.type === 'sql_injection')).toEqual([]);
    expect(r.flows).not.toContain('sql_injection');
    expect(r.findings).not.toContain('sql_injection');
  });

  it('c.req.query(key) with a non-literal key gives no SQL sink', async () => {
    const r = await run(`
import { Hono } from 'hono';
const app = new Hono();
app.get('/s/:k', (c) => {
  const k = c.req.param('k');
  const name = c.req.query('name');
  const a = c.req.query(k);
  const b = c.req.query(\`f_\${name}\`);
  return c.json({ a, b });
});
`);
    expect(r.sinks.filter(s => s.type === 'sql_injection')).toEqual([]);
    expect(r.flows).not.toContain('sql_injection');
    expect(r.findings).not.toContain('sql_injection');
  });

  it('c.req.query(key) inside a plain helper gives no SQL finding', async () => {
    const r = await run(`
export function h(c: any, key: string) { return c.req.query(key); }
`);
    expect(r.sinks.filter(s => s.type === 'sql_injection')).toEqual([]);
    expect(r.findings).not.toContain('sql_injection');
  });

  it('c.req.query(name) in a .js file gives no SQL finding', async () => {
    const code = `
const app = new Hono();
app.get('/s', (c) => { const name = c.req.query('name'); const v = c.req.query(name); return c.json({ v }); });
`;
    const res = await analyze(code, 'app.js', 'javascript');
    expect(res.taint.sinks.filter(s => s.type === 'sql_injection')).toEqual([]);
    expect(generateFindings(res.taint.sources, res.taint.sinks, res.dfg).map(f => f.type)).not.toContain('sql_injection');
  });

  it('req / request / ctx.req / ctx.request / this.req .query(key) give no SQL sink', async () => {
    const r = await run(`
export class H {
  constructor(private req: any) {}
  a(req: any, request: any, ctx: any, k: string) {
    return [req.query(k), request.query(k), ctx.req.query(k), ctx.request.query(k), this.req.query(k)];
  }
}
`);
    expect(r.sinks.filter(s => s.type === 'sql_injection')).toEqual([]);
  });

  it('c.req.query is still a source', async () => {
    const r = await run(`
import { Hono } from 'hono';
const app = new Hono();
app.get('/search', (c) => {
  const q = c.req.query('q');
  return c.text(q ?? '');
});
`);
    expect(r.sources.some(s => s.line === 5)).toBe(true);
  });

  it('c.req.query value into client.query template still flows to SQL', async () => {
    const r = await run(`
import { Hono } from 'hono';
import { Client } from 'pg';
const client = new Client();
const app = new Hono();
app.get('/user', async (c) => {
  const id = c.req.query('id');
  const rows = await client.query(\`SELECT * FROM users WHERE id = \${id}\`);
  return c.json(rows);
});
`);
    const sql = r.sinks.filter(s => s.type === 'sql_injection');
    expect(sql.map(s => s.line)).toEqual([8]);
    expect(r.findings).toContain('sql_injection');
  });

  it('client.query(`... ${x}`) is still a SQL sink', async () => {
    const r = await run(`
export async function q(client: any, x: string) {
  return client.query(\`SELECT * FROM t WHERE n = '\${x}'\`);
}
`);
    expect(r.sinks.some(s => s.type === 'sql_injection')).toBe(true);
  });

  it('pool.query / db.query / this.db.query / knex.raw-style receivers still sink', async () => {
    const r = await run(`
export class Repo {
  constructor(private db: any, private pool: any) {}
  a(req: any) {
    const n = req.query.name;
    this.db.query("SELECT * FROM t WHERE n='" + n + "'");
    this.pool.query("SELECT * FROM t WHERE n='" + n + "'");
  }
}
`);
    const lines = r.sinks.filter(s => s.type === 'sql_injection').map(s => s.line);
    expect(lines).toContain(6);
    expect(lines).toContain(7);
  });

  it('req.db.query (runtime-decorated client) still sinks', async () => {
    const r = await run(`
export function h(req: any) {
  const n = req.query.name;
  return req.db.query("SELECT * FROM t WHERE n='" + n + "'");
}
`);
    expect(r.sinks.filter(s => s.type === 'sql_injection').map(s => s.line)).toEqual([4]);
  });

  it('app.locals.pg.query still sinks', async () => {
    const r = await run(`
export function h(app: any, req: any) {
  const n = req.query.name;
  return app.locals.pg.query("SELECT * FROM t WHERE n='" + n + "'");
}
`);
    expect(r.sinks.filter(s => s.type === 'sql_injection').map(s => s.line)).toEqual([4]);
  });

  it('req.app.get("db").query still sinks', async () => {
    const r = await run(`
export function h(req: any) {
  const n = req.query.name;
  return req.app.get("db").query("SELECT * FROM t WHERE n='" + n + "'");
}
`);
    expect(r.sinks.filter(s => s.type === 'sql_injection').map(s => s.line)).toEqual([4]);
  });

  it('req.app.locals.em.query still sinks', async () => {
    const r = await run(`
export function h(req: any) {
  const n = req.query.name;
  return req.app.locals.em.query("SELECT * FROM t WHERE n='" + n + "'");
}
`);
    expect(r.sinks.filter(s => s.type === 'sql_injection').map(s => s.line)).toEqual([4]);
  });

  it('a longer chain ending in a request-like name (c.env.req, this.ctx.request) still sinks', async () => {
    const r = await run(`
export class H {
  constructor(private ctx: any) {}
  a(c: any, req: any) {
    const n = req.query.name;
    c.env.req.query("SELECT * FROM t WHERE n='" + n + "'");
    this.ctx.request.query("SELECT * FROM t WHERE n='" + n + "'");
  }
}
`);
    const lines = r.sinks.filter(s => s.type === 'sql_injection').map(s => s.line);
    expect(lines).toContain(6);
    expect(lines).toContain(7);
  });
});
