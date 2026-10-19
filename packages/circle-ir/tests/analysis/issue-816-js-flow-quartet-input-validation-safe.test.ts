/**
 * cognium-dev #816 — flow-quartet tier-3 `input_validation` / js safe mirror
 * (`javascript-vuln-demo/intake/b-tier/input_validation_safe.js` in the
 * sast-validation manifest). Range-checked `amount` must not emit xss; raw
 * query echo still fires.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const unsanitizedXss = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter((f) => f.sink_type === 'xss' && !f.sanitized);

/** Nightly safe shape: bounded Number-coerced amount beside raw `to` in one template. */
const safeMirror = `const express = require('express');
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

const tpMirror = `const express = require('express');
const app = express();
app.get('/echo', (req, res) => {
    const msg = req.query.msg;
    res.end(\`echo: \${msg}\`);
});
module.exports = app;
`;

describe('#816 flow-quartet js input_validation safe mirror', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('input_validation_safe.js stays clean for xss (gate category input_validation)', async () => {
    const ir = await analyze(safeMirror, 'input_validation_safe.js', 'javascript');
    expect(unsanitizedXss(ir)).toEqual([]);
  });

  it('recall: unvalidated query in template still emits xss', async () => {
    const ir = await analyze(tpMirror, 'input_validation_tp.js', 'javascript');
    expect(unsanitizedXss(ir).length).toBeGreaterThan(0);
  });
});
