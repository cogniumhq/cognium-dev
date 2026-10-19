/**
 * cognium-dev #816 — ts-rust-parity quartet tier-3 `log_injection` / typescript safe
 * mirror (`typescript-vuln-demo` flow-sanitize custom_wrapper shape). CRLF-stripping
 * helper must suppress log_injection; partial strip and raw echo still fire.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const logInj = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter((f) => f.sink_type === 'log_injection' && !f.sanitized);

const safeMirror = `import express from 'express';

function stripLogChars(s: string): string {
  return s.replace(/\\r/g, '_').replace(/\\n/g, '_').replace(/\\t/g, '_');
}

const app = express();
app.get('/audit', (req, res) => {
  const user = String(req.query.user ?? '');
  console.log('user=' + stripLogChars(user));
  res.end('ok');
});

export default app;
`;

const partialStrip = `import express from 'express';

function stripSpaces(s: string): string {
  return s.replace(/ /g, '-');
}

const app = express();
app.get('/audit', (req, res) => {
  const user = String(req.query.user ?? '');
  console.log('user=' + stripSpaces(user));
  res.end('ok');
});

export default app;
`;

const tpMirror = `import express from 'express';

const app = express();
app.get('/audit', (req, res) => {
  const user = String(req.query.user ?? '');
  console.log('user=' + user);
  res.end('ok');
});

export default app;
`;

describe('#816 ts-rust-parity quartet log_injection safe mirror', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('custom_wrapper CRLF strip stays clean for log_injection', async () => {
    const ir = await analyze(safeMirror, 'V06CustomWrapperSafe.ts', 'typescript');
    expect(logInj(ir)).toEqual([]);
  });

  it('helper that only strips spaces still fires log_injection', async () => {
    const ir = await analyze(partialStrip, 'V06PartialWrapper.ts', 'typescript');
    expect(logInj(ir).length).toBeGreaterThan(0);
  });

  it('recall: raw query in console.log still emits log_injection', async () => {
    const ir = await analyze(tpMirror, 'V01BaselineTp.ts', 'typescript');
    expect(logInj(ir).length).toBeGreaterThan(0);
  });
});
