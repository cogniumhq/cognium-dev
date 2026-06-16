/**
 * Repro for cognium-dev#75 — express.Router() handler req.* sources not
 * recognized. `app.post(...)` fires; semantically-identical
 * `router.post(...)` / `require('express').Router().post(...)` MISS.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#75 — express.Router() request source recognition', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const countEvalFlows = (flows: Array<{ sink_type?: string }> | undefined) =>
    (flows ?? []).filter((f) => f.sink_type === 'code_injection').length;

  const countSqlFlows = (flows: Array<{ sink_type?: string }> | undefined) =>
    (flows ?? []).filter((f) => f.sink_type === 'sql_injection').length;

  it('R2 baseline: app.post(req.body.code) → eval — fires', async () => {
    const code = `
const express = require('express');
const app = express();
app.post('/r2', (req, res) => {
  const c = req.body.code;
  eval(c);
});
`;
    const r = await analyze(code, 'r2.js', 'javascript');
    expect(countEvalFlows(r.taint.flows)).toBeGreaterThanOrEqual(1);
  });

  it('R1: const router = express.Router(); router.post(...) — should FIRE', async () => {
    const code = `
const express = require('express');
const router = express.Router();
router.post('/r1', (req, res) => {
  const c = req.body.code;
  eval(c);
});
module.exports = router;
`;
    const r = await analyze(code, 'r1.js', 'javascript');
    expect(countEvalFlows(r.taint.flows)).toBeGreaterThanOrEqual(1);
  });

  it('R3: const r = require("express").Router(); r.post(...) — should FIRE', async () => {
    const code = `
const r = require('express').Router();
r.post('/r3', (req, res) => {
  const c = req.body.code;
  eval(c);
});
module.exports = r;
`;
    const result = await analyze(code, 'r3.js', 'javascript');
    expect(countEvalFlows(result.taint.flows)).toBeGreaterThanOrEqual(1);
  });

  it('R4: router.get + db.query(`SELECT ... ${req.query.id}`) — should FIRE sqli', async () => {
    const code = `
const express = require('express');
const router = express.Router();
router.get('/r4', (req, res) => {
  db.query('SELECT * FROM u WHERE id=' + req.query.id);
});
module.exports = router;
`;
    const result = await analyze(code, 'r4.js', 'javascript');
    expect(countSqlFlows(result.taint.flows)).toBeGreaterThanOrEqual(1);
  });
});
