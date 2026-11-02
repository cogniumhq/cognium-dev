/**
 * cognium-dev#1073 — `db.prepare(<tainted SQL>)` in better-sqlite3 / sqlite3
 * is a sql_injection sink (argument 0, the SQL text). It was registered only
 * for duckdb, so a query built from a request value into `prepare` was silent.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze, analyzeProject } from '../../src/analyzer.js';

const flows = async (code: string) =>
  (await analyze(code, 'r.ts', 'typescript')).taint.flows.filter(f => f.sink_type === 'sql_injection');

const app = (imp: string, ctor: string, q: string) => `${imp}
import express from 'express';
const db = ${ctor};
const app = express();
app.get('/f', (req, res) => {
  const id = req.query.id as string;
  res.json(${q});
});
`;

describe('#1073 sqlite prepare() takes the SQL text', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('better-sqlite3: concatenated or template SQL into prepare is a flow', async () => {
    expect((await flows(app(`import Database from 'better-sqlite3';`, `new Database('x.db')`, `db.prepare('SELECT * FROM f WHERE id = ' + id).get()`))).length).toBeGreaterThan(0);
    expect((await flows(app(`import Database from 'better-sqlite3';`, `new Database('x.db')`, "db.prepare(`SELECT * FROM f WHERE id = '${id}'`).all()"))).length).toBeGreaterThan(0);
  });

  it('sqlite3: tainted SQL into prepare is a flow', async () => {
    expect((await flows(app(`import sqlite3 from 'sqlite3';`, `new sqlite3.Database('x.db')`, `db.prepare('SELECT * FROM f WHERE id = ' + id)`))).length).toBeGreaterThan(0);
  });

  it('a constant query is no flow into prepare (the value is bound on another statement)', async () => {
    // Bound on its own line so this test is about prepare's argument alone; `.get` on a chained
    // statement is the separate false positive fixed by the prepared-statement PR (Stage 15f3).
    const code = `import Database from 'better-sqlite3';
import express from 'express';
const db = new Database('x.db');
const byId = db.prepare('SELECT * FROM f WHERE id = ?');
const app = express();
app.get('/f', (req, res) => {
  const id = req.query.id as string;
  res.json(byId.get(id));
});
`;
    expect(await flows(code)).toHaveLength(0);
  });

  it('without a sqlite import, an unrelated .prepare() is not a sink', async () => {
    const code = `import express from 'express';\nconst tpl = { prepare: (s: string) => s };\nconst app = express();\napp.get('/f', (req, res) => { res.send(tpl.prepare('x' + req.query.id)); });\n`;
    expect(await flows(code)).toHaveLength(0);
  });

  it('the cross-file shape from the dogfood: a route value into a store method building the query', async () => {
    const store = `import Database from 'better-sqlite3';
export class Store {
  private db = new Database('x.db');
  find(options: { job_id?: string } = {}) {
    const id = options.job_id;
    return this.db.prepare('SELECT * FROM f WHERE job_id = ' + id).get();
  }
}
export const store = new Store();
`;
    const route = `import { Hono } from 'hono';\nimport { store } from './store';\nconst app = new Hono();\napp.get('/f', (c) => c.json(store.find({ job_id: c.req.query('job_id') })));\n`;
    const r = await analyzeProject([
      { code: store, filePath: 'src/store.ts', language: 'typescript' },
      { code: route, filePath: 'src/routes.ts', language: 'typescript' },
    ]);
    const perFile = r.files.flatMap(f => f.analysis.taint.sinks.filter(s => s.type === 'sql_injection'));
    expect(perFile.length).toBeGreaterThan(0);
  });
});
