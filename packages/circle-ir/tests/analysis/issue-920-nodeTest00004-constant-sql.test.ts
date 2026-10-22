/**
 * cognium-dev #920 — NodeJS synthetic NodeTest00004: constant SQL assigned to a
 * local must not register `db.query()` as an http_param source or emit sqli.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('#920 NodeTest00004 constant SQL variable', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not flag db.query(constantQuery, cb) when query is a literal', async () => {
    const code = `const express = require('express');
const mysql = require('mysql');
const app = express();
const db = mysql.createConnection({});

app.get('/products', (req, res) => {
    const query = "SELECT * FROM products WHERE active = 1";
    db.query(query, (err, results) => {
        res.json(results);
    });
});
`;
    const r = await analyze(code, 'NodeTest00004.js', 'javascript');
    const sqli = (r.taint?.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sqli).toHaveLength(0);
    const bogusSource = (r.taint?.sources ?? []).some(
      s => s.line === 8 && s.type === 'http_param' && s.location.includes('db.query'),
    );
    expect(bogusSource).toBe(false);
  });
});
