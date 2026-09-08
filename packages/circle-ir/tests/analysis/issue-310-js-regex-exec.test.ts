/**
 * cognium-dev #310 (from cognium-ai#195 / cognium-ai#279 R-4 family).
 *
 * The classless `exec` CWE-78 sink exists for destructured
 * `child_process.exec`, but `RegExp.prototype.exec` shares the name. A regex
 * receiver — literal, `new RegExp(...)`, or a variable bound to one in the
 * file — is a pattern match, not a shell, and must not fire. Bare `exec(...)`
 * and module-handle receivers keep firing.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const cmdi = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'command_injection');

describe('#310 JS: regex receivers do not match the classless exec sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  for (const [label, line] of [
    ['regex literal', 'const m = /^(\\w+)/.exec(req.query.q);'],
    ['new RegExp(...) receiver', 'const m = new RegExp("^\\\\w+").exec(req.query.q);'],
    ['variable bound to a regex literal', 'const m = RE.exec(req.query.q);'],
  ] as const) {
    it(`${label} does NOT fire command_injection`, async () => {
      const code = [
        'const RE = /^(\\w+)/;',
        'app.get("/s", (req, res) => {',
        `  ${line}`,
        '  res.json(m);',
        '});',
      ].join('\n');
      const r = await analyze(code, 'server.js', 'javascript');
      expect(cmdi(r)).toEqual([]);
    });
  }

  for (const [label, prelude, line] of [
    ['destructured child_process.exec', 'const { exec } = require("child_process");', 'exec("ls " + req.query.dir);'],
    ['module handle cp.exec', 'const cp = require("child_process");', 'cp.exec("ls " + req.query.dir);'],
  ] as const) {
    it(`${label} STILL fires command_injection (recall preserved)`, async () => {
      const code = [
        prelude,
        'app.get("/s", (req, res) => {',
        `  ${line}`,
        '  res.end();',
        '});',
      ].join('\n');
      const r = await analyze(code, 'server.js', 'javascript');
      expect(cmdi(r).length).toBeGreaterThan(0);
    });
  }

  it('Java Runtime.exec is untouched by the JS-scoped gate', async () => {
    const code = [
      'public class A {',
      '  public void run(String cmd) throws Exception {',
      '    Runtime.getRuntime().exec("ls " + cmd);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'A.java', 'java');
    expect(cmdi(r).length).toBeGreaterThan(0);
  });
});
