/**
 * cognium-dev #311 (from cognium-ai#196).
 *
 * Python's classless `compile` CWE-94 sink models the builtin
 * `compile(src, filename, mode)`. Library methods that happen to be named
 * `compile` — `re.compile`, LangGraph `workflow.compile()`, template engines —
 * cannot execute their argument and must not fire. The bare builtin and the
 * explicit `builtins.compile` keep firing.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const codei = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'code_injection');

describe('#311 Python: only the builtin compile is a code_injection sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('re.compile(tainted) does NOT fire code_injection', async () => {
    const code = [
      'import re',
      'from flask import request',
      'def h():',
      '    pat = re.compile(request.args["q"])',
      '    return pat',
    ].join('\n');
    const r = await analyze(code, 'app.py', 'python');
    expect(codei(r)).toEqual([]);
  });

  it('workflow.compile(tainted) does NOT fire code_injection', async () => {
    const code = [
      'from flask import request',
      'def h(workflow):',
      '    graph = workflow.compile(request.args["mode"])',
      '    return graph',
    ].join('\n');
    const r = await analyze(code, 'app.py', 'python');
    expect(codei(r)).toEqual([]);
  });

  for (const [label, call] of [
    ['bare builtin compile', 'compile(request.form["src"], "<s>", "exec")'],
    ['explicit builtins.compile', 'builtins.compile(request.form["src"], "<s>", "exec")'],
  ] as const) {
    it(`${label} STILL fires code_injection (recall preserved)`, async () => {
      const code = [
        'import builtins',
        'from flask import request',
        'def h():',
        `    return ${call}`,
      ].join('\n');
      const r = await analyze(code, 'app.py', 'python');
      expect(codei(r).length).toBeGreaterThan(0);
    });
  }
});
