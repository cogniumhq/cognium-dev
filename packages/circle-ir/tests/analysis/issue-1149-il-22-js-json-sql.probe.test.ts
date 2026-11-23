/**
 * Probe: cognium-dev #1149 IL-22 JSON.parse → sql_injection.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const FIXTURE = `const express = require('express');
const { Pool } = require('pg');

const app = express();
const pool = new Pool();

app.post('/ingest', express.text(), (req, res) => {
  const payload = JSON.parse(req.body);
  const name = payload.name;
  pool.query("SELECT * FROM users WHERE name = '" + name + "'").then((r) => res.json(r.rows));
});

module.exports = app;
`;

describe('#1149 IL-22 probe', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('sql_injection flow to pool.query', async () => {
    const r = await analyze(FIXTURE, 'interop_json_deserialize_sink.js', 'javascript');
    const sql = (r.taint?.flows ?? []).filter((f) => f.sink_type === 'sql_injection');
    expect(sql.length).toBeGreaterThan(0);
  });
});
