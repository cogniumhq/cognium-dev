import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

/**
 * Sprint 55 — #186 SQLi: sqlite3 (npm) `Database.{all,run,each,get,exec}`
 * methods receiving tainted-concatenated SQL must fire sql_injection.
 *
 * Recall lock: already-shipped node-postgres / mysql shapes must keep
 * firing (assumed via existing tests; we add a pg.query recall here).
 */
describe('Sprint 55 — #186 sqlite3 SQLi', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const countFlows = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
    (r.taint?.flows ?? []).filter(f => f.sink_type === type).length;

  it('FN — sqlite3 db.all(taintedConcat) must fire sql_injection', async () => {
    const code = `const express = require('express');
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database(':memory:');
const app = express();
app.get('/p', (req, res) => {
  db.all('SELECT * FROM t WHERE x="' + req.query.q + '"', (err, rows) => res.json(rows));
});`;
    const r = await analyze(code, 'sqlite-all.js', 'javascript');
    expect(countFlows(r, 'sql_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — sqlite3 db.run(taintedConcat) must fire sql_injection', async () => {
    const code = `const express = require('express');
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database(':memory:');
const app = express();
app.get('/p', (req, res) => {
  db.run('UPDATE t SET v="' + req.query.q + '"');
  res.end();
});`;
    const r = await analyze(code, 'sqlite-run.js', 'javascript');
    expect(countFlows(r, 'sql_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — sqlite3 db.exec(taintedConcat) must fire sql_injection', async () => {
    const code = `const express = require('express');
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database(':memory:');
const app = express();
app.get('/p', (req, res) => {
  db.exec('DELETE FROM t WHERE id=' + req.query.id);
  res.end();
});`;
    const r = await analyze(code, 'sqlite-exec.js', 'javascript');
    expect(countFlows(r, 'sql_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — sqlite3 db.get(taintedConcat) must fire sql_injection', async () => {
    const code = `const express = require('express');
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database(':memory:');
const app = express();
app.get('/p', (req, res) => {
  db.get('SELECT * FROM t WHERE id=' + req.query.id, (err, row) => res.json(row));
});`;
    const r = await analyze(code, 'sqlite-get.js', 'javascript');
    expect(countFlows(r, 'sql_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — sqlite3 db.each(taintedConcat) must fire sql_injection', async () => {
    const code = `const express = require('express');
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database(':memory:');
const app = express();
app.get('/p', (req, res) => {
  db.each('SELECT * FROM t WHERE name="' + req.query.n + '"', (err, row) => {});
  res.end();
});`;
    const r = await analyze(code, 'sqlite-each.js', 'javascript');
    expect(countFlows(r, 'sql_injection')).toBeGreaterThanOrEqual(1);
  });

  it('recall — parameterised db.all($1, [taint]) must NOT fire', async () => {
    const code = `const express = require('express');
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database(':memory:');
const app = express();
app.get('/p', (req, res) => {
  db.all('SELECT * FROM t WHERE x=?', [req.query.q], (err, rows) => res.json(rows));
});`;
    const r = await analyze(code, 'sqlite-param.js', 'javascript');
    expect(countFlows(r, 'sql_injection')).toBe(0);
  });
});
