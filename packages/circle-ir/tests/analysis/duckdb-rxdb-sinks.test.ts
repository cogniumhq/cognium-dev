/**
 * SQL built in TS strings for DuckDB (`@duckdb/node-api`, `duckdb`,
 * `react-native-duckdb`) and RxDB query objects. Import-gated sinks
 * (`requires_import`) with credit for bound parameters.
 */
import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

type R = Awaited<ReturnType<typeof analyze>>;
const flowLines = (r: R, type: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === type).map(f => f.sink_line).sort((a, b) => a - b);

describe('DuckDB and RxDB query sinks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('@duckdb/node-api: interpolated SQL fires, bound values and prepare/bind do not', async () => {
    const code = [
      "import { DuckDBInstance } from '@duckdb/node-api';",
      "import express from 'express';",
      'const app = express();',
      "app.get('/q', async (req, res) => {",
      "  const connection = await (await DuckDBInstance.create(':memory:')).connect();",
      '  const name = req.query.name as string;',
      "  const a = await connection.runAndReadAll(`SELECT * FROM t WHERE name = '${name}'`);",
      "  const b = await connection.run('SELECT * FROM t WHERE name = $1', [name]);",
      "  const stmt = await connection.prepare('SELECT * FROM t WHERE name = $1');",
      '  stmt.bind([name]);',
      "  const c = await connection.stream('SELECT * FROM t WHERE x = ' + name);",
      '  res.json({ a, b, c });',
      '});',
    ].join('\n');
    const r = await analyze(code, 'q.ts', 'typescript');
    expect(flowLines(r, 'sql_injection')).toEqual([7, 11]);
    expect((r.taint.flows ?? []).filter(f => f.sink_line === 8)).toHaveLength(0);
  });

  it('react-native-duckdb: execute/executeSync with built SQL fire; params, named params and prepared statements do not', async () => {
    const code = [
      "import { open } from 'react-native-duckdb';",
      'export async function search() {',
      "  const db = open({ name: 'a.db' });",
      "  const q = new URLSearchParams(location.search).get('q') ?? '';",
      "  const a = await db.execute(`SELECT * FROM items WHERE title LIKE '%${q}%'`);",
      "  const b = await db.execute('SELECT * FROM items WHERE title LIKE ?', [q]);",
      "  const c = db.executeSync('SELECT 1 WHERE x = ' + q);",
      "  const d = await db.executeNamed('SELECT * FROM items WHERE title = $t', { t: q });",
      "  const p = db.prepare('SELECT * FROM items WHERE title = ?');",
      '  const e = await p.execute([q]);',
      '  return [a, b, c, d, e];',
      '}',
    ].join('\n');
    const r = await analyze(code, 'search.ts', 'typescript');
    expect(flowLines(r, 'sql_injection')).toEqual([5, 7]);
  });

  it('classic duckdb: db.all / con.exec are SQL, not command injection; `?` placeholders are not', async () => {
    const code = [
      "const duckdb = require('duckdb');",
      "const express = require('express');",
      'const app = express();',
      "const database = new duckdb.Database(':memory:');",
      "app.get('/x', (req, res) => {",
      '  const id = req.query.id;',
      "  database.all('SELECT * FROM t WHERE id = ' + id, (e, rows) => res.json(rows));",
      "  database.all('SELECT * FROM t WHERE id = ?', id, (e, rows) => res.json(rows));",
      '  const con = database.connect();',
      "  con.exec('DELETE FROM t WHERE id = ' + id);",
      '});',
    ].join('\n');
    const r = await analyze(code, 'x.js', 'javascript');
    expect(flowLines(r, 'sql_injection')).toEqual([7, 10]);
    expect(flowLines(r, 'command_injection')).toEqual([]);
  });

  it('the DuckDB sinks need the import: a generic run/execute elsewhere is unchanged', async () => {
    const code = [
      "import express from 'express';",
      'const app = express();',
      "app.get('/t', async (req, res) => {",
      '  const job = makeJob();',
      '  await job.runAndReadAll(req.query.x);',
      '  res.end();',
      '});',
    ].join('\n');
    const r = await analyze(code, 'job.ts', 'typescript');
    expect(flowLines(r, 'sql_injection')).toEqual([]);
  });

  it('RxDB: a caller-controlled selector or builder field fires; a literal selector and the zero-argument exec() do not', async () => {
    const code = [
      "import { createRxDatabase } from 'rxdb';",
      "import express from 'express';",
      'const app = express();',
      "app.post('/f', async (req, res) => {",
      "  const db = await createRxDatabase({ name: 'x', storage: {} as any });",
      '  const docs = await db.items.find({ selector: req.body.selector }).exec();',
      '  const q = db.items.find().where(req.query.field as string).eq(1);',
      "  const safe = await db.items.find({ selector: { status: 'open' } }).exec();",
      '  res.json({ docs, q, safe });',
      '});',
    ].join('\n');
    const r = await analyze(code, 'f.ts', 'typescript');
    expect(new Set(flowLines(r, 'nosql_injection'))).toEqual(new Set([6, 7]));
    expect(flowLines(r, 'sql_injection')).toEqual([]);
  });
});
