/**
 * cognium-dev #816 — PAT-INPUT-01 TypeScript safe mirror (cve-intake-b).
 * Same shapes as issue-816-js-pat-input-safe.test.ts; expect 0 unsanitized xss flows.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const xssFlows = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter(f => f.sink_type === 'xss' && !f.sanitized);

const safeXferRoute = `import express from 'express';
const app = express();
app.get('/xfer', (req, res) => {
    const amount = parseInt(String(req.query.amount), 10);
    const MAX = 1000;
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).end();
    if (amount > MAX) return res.status(400).end();
    res.end(\`xfer \${amount}\`);
});
export default app;
`;

const safeXferWithToRoute = `import express from 'express';
const app = express();
app.get('/xfer', (req, res) => {
    const to = req.query.to;
    const amount = Number(req.query.amount);
    const MAX = 1000;
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).end();
    if (amount > MAX) return res.status(400).end();
    res.end(\`xfer \${amount} to \${to}\`);
});
export default app;
`;

const rawEchoRoute = `import express from 'express';
const app = express();
app.get('/echo', (req, res) => {
    const msg = req.query.msg;
    res.end(\`echo: \${msg}\`);
});
export default app;
`;

describe('#816 PAT-INPUT-01 ts safe mirror', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('range-checked Number-coerced qty stays clean in template response', async () => {
    const ir = await analyze(safeXferRoute, 'pat_input_safe_mirror.ts', 'typescript');
    expect(xssFlows(ir)).toEqual([]);
  });

  it('FQ-T3-S01 shape: bounded amount beside raw to stays clean (input_validation_safe.ts)', async () => {
    const ir = await analyze(safeXferWithToRoute, 'input_validation_safe.ts', 'typescript');
    expect(xssFlows(ir)).toEqual([]);
  });

  it('recall: raw query in template still emits xss', async () => {
    const ir = await analyze(rawEchoRoute, 'pat_input_tp_mirror.ts', 'typescript');
    expect(xssFlows(ir).length).toBeGreaterThan(0);
  });
});
