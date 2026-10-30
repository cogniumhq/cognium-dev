/**
 * cognium-dev#999 — security results must not be raised on lines that are only
 * a comment. Dogfood cases: a doc comment quoting `JSON.parse(req.body)`
 * (insecure_deserialization), mass-assignment and tls-verify-disabled doc
 * comments in circle-ir's own passes.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const securityOnLine = async (code: string, line: number, file = 'x.ts', lang: 'typescript' | 'python' | 'java' = 'typescript') => {
  const r = await analyze(code, file, lang);
  const findings = (r.findings ?? []).filter(f => f.category === 'security' && f.line === line).map(f => f.rule_id);
  const sinks = r.taint.sinks.filter(s => s.line === line).map(s => s.type);
  return [...findings, ...sinks];
};

describe('#999 — no security results on comment-only lines', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('a JSDoc line quoting JSON.parse(req.body) raises nothing', async () => {
    const code = `
/**
 * Example: JSON.parse(req.body) is dangerous.
 * res.redirect(req.query.next)
 */
export function f() { return 1; }
// eval(req.body.code)
`;
    expect(await securityOnLine(code, 3)).toEqual([]);
    expect(await securityOnLine(code, 4)).toEqual([]);
    expect(await securityOnLine(code, 7)).toEqual([]);
  });

  it('the same text in code still fires', async () => {
    const code = `
import express from 'express';
const app = express();
app.post('/x', (req: any, res: any) => {
  const body = JSON.parse(req.body);
  res.send(body);
});
`;
    expect((await securityOnLine(code, 5)).length).toBeGreaterThan(0);
  });

  it('a code line with a trailing comment keeps its results', async () => {
    const code = `
import express from 'express';
const app = express();
app.post('/x', (req: any, res: any) => {
  const body = JSON.parse(req.body); // parse the body
  res.send(body);
});
`;
    expect((await securityOnLine(code, 5)).length).toBeGreaterThan(0);
  });

  it('a file-level finding anchored on line 1 survives a leading doc comment', async () => {
    const code = `/**
 * Server entry.
 */
import express from 'express';
const app = express();
app.get('/x', (req: any, res: any) => { res.send('ok'); });
app.listen(3000);
`;
    const r = await analyze(code, 'server.ts', 'typescript');
    const lineOne = (r.findings ?? []).filter(f => f.line === 1 && f.category === 'security').map(f => f.rule_id);
    const r0 = await analyze(code.replace('/**\n * Server entry.\n */\n', '\n\n\n'), 'server.ts', 'typescript');
    const lineOneNoComment = (r0.findings ?? []).filter(f => f.line === 1 && f.category === 'security').map(f => f.rule_id);
    expect(lineOne).toEqual(lineOneNoComment);
  });

  it('Python # comment and Java block comment raise nothing', async () => {
    const py = `
# pickle.loads(request.data)
def f():
    return 1
`;
    expect(await securityOnLine(py, 2, 'x.py', 'python')).toEqual([]);
    const java = `
public class X {
  /* Runtime.getRuntime().exec(request.getParameter("c")); */
  void f() {}
}
`;
    expect(await securityOnLine(java, 3, 'X.java', 'java')).toEqual([]);
  });
});
