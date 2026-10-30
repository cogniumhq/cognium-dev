/**
 * JavaScript / TypeScript `try`, `catch` and `finally` in the DFG: locals
 * declared there get defs, the catch parameter (identifier or pattern) is a
 * def in its clause, and uses inside and after reach them.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { buildDFG } from '../../src/core/extractors/dfg.js';
import { analyze } from '../../src/index.js';

const CODE = `function f(x) {
  let out = '';
  try {
    const y = x.trim();
    out = y;
  } catch (e) {
    const m = e.message;
    out = m;
  } finally {
    const z = 1;
  }
  try { g(); } catch ({ message, code }) { h(message, code); }
  try { g(); } catch { h(); }
  return out;
}`;

describe('JavaScript DFG: try statements', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('records defs for body, catch-parameter, destructured catch and finally locals', async () => {
    const dfg = buildDFG(await parse(CODE, 'javascript'), undefined, 'javascript');
    const at = (v: string) => dfg.defs.find(d => d.variable === v);
    expect(at('y')).toMatchObject({ line: 4, kind: 'local' });
    expect(at('e')).toMatchObject({ line: 6 });
    expect(at('m')).toMatchObject({ line: 7 });
    expect(at('z')).toMatchObject({ line: 10 });
    expect(at('message')).toBeDefined();
    expect(at('code')).toBeDefined();
  });

  it('links uses inside the clauses and after the statement', async () => {
    const dfg = buildDFG(await parse(CODE, 'javascript'), undefined, 'javascript');
    const def = (v: string) => dfg.defs.find(d => d.variable === v)!.id;
    expect(dfg.uses.find(u => u.variable === 'y' && u.line === 5)?.def_id).toBe(def('y'));
    expect(dfg.uses.find(u => u.variable === 'e' && u.line === 7)?.def_id).toBe(def('e'));
    expect(dfg.uses.find(u => u.variable === 'message' && u.line === 12)?.def_id).toBe(def('message'));
    expect(dfg.uses.find(u => u.variable === 'out' && u.line === 14)?.def_id).not.toBeNull();
  });

  it('TypeScript too', async () => {
    const dfg = buildDFG(await parse(`function f(x: string): string {\n  try { const y: string = x; return y; } catch (e: unknown) { return String(e); }\n}`, 'typescript'), undefined, 'typescript');
    expect(dfg.defs.find(d => d.variable === 'y')).toBeDefined();
    expect(dfg.defs.find(d => d.variable === 'e')).toBeDefined();
  });

  it('a tainted value moved through a local inside a try reaches its sink', async () => {
    const ir = await analyze(`const { exec } = require('child_process');
function run(req, res) {
  try {
    const cmd = req.query.cmd;
    exec('ls ' + cmd);
  } catch (e) { res.send('no'); }
}
module.exports = { run };`, 'run.js', 'javascript');
    expect(ir.taint.flows?.some(f => f.sink_type === 'command_injection')).toBe(true);
  });
});
