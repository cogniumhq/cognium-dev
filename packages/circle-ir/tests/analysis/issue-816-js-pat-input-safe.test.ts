/**
 * cognium-dev #816 — PAT-INPUT-01 js safe mirror (cve-intake-b /
 * input_validation_safe.js shape). Range-checked numeric `amount` must
 * not emit xss; raw unvalidated input still fires.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const xssFlows = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter(f => f.sink_type === 'xss' && !f.sanitized);

const safeXferRoute = `const express = require('express');
const app = express();
app.get('/xfer', (req, res) => {
    const amount = parseInt(req.query.amount, 10);
    const MAX = 1000;
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).end();
    if (amount > MAX) return res.status(400).end();
    res.end(\`xfer \${amount}\`);
});
module.exports = app;
`;

/** sast-validation FQ-T3-S01 / #237 repro — range-checked amount + raw \`to\` in one template. */
const safeXferWithToRoute = `const express = require('express');
const app = express();
app.get('/xfer', (req, res) => {
    const to = req.query.to;
    const amount = Number(req.query.amount);
    const MAX = 1000;
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).end();
    if (amount > MAX) return res.status(400).end();
    res.end(\`xfer \${amount} to \${to}\`);
});
module.exports = app;
`;

const rawEchoRoute = `const express = require('express');
const app = express();
app.get('/echo', (req, res) => {
    const msg = req.query.msg;
    res.end(\`echo: \${msg}\`);
});
module.exports = app;
`;

describe('#816 PAT-INPUT-01 js safe mirror', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('range-checked Number-coerced qty stays clean in template response', async () => {
    const ir = await analyze(safeXferRoute, 'pat_input_safe_mirror.js', 'javascript');
    expect(xssFlows(ir)).toEqual([]);
  });

  it('FQ-T3-S01 shape: bounded amount beside raw to stays clean (input_validation_safe.js)', async () => {
    const ir = await analyze(safeXferWithToRoute, 'input_validation_safe.js', 'javascript');
    expect(xssFlows(ir)).toEqual([]);
  });

  it('recall: raw query in template still emits xss', async () => {
    const ir = await analyze(rawEchoRoute, 'pat_input_tp_mirror.js', 'javascript');
    expect(xssFlows(ir).length).toBeGreaterThan(0);
  });
});
