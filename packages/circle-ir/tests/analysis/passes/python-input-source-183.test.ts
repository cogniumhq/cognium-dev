/**
 * Sprint 72 — #183 residual: `input()` as a forward-taint source in Python.
 *
 * The Sprint 56 skipped test (`python-reflection-code-injection-fn.test.ts`
 * line 78) was deferred because:
 *
 *   "input() is registered as a source in `configs/sources/python.json`
 *    but not in `PYTHON_TAINTED_PATTERNS`, which is a separate broader
 *    concern."
 *
 * The Sprint 68 docstring (same file, lines 105-109) explicitly carries
 * this over. This sprint addresses the residual by adding `input()` to
 * the two `PYTHON_TAINTED_PATTERNS` registries (`language-sources-pass.ts`
 * and `taint-matcher.ts`) so that `pyTaintedVars` recognises `name =
 * input()` as a tainted definition.
 *
 * Concretely closes the `getattr(obj, input())()` reflection-invocation
 * shape from #183 and the well-known `os.system(input())` / `eval(input())`
 * stdin-injection patterns.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';

describe('#183 Sprint 72 — Python input() as forward-taint source', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const flowsOf = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
    (r.taint?.flows ?? []).filter(f => f.sink_type === type).length;

  const sinksOf = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
    (r.taint?.sinks ?? []).filter(s => s.type === type);

  it('TP — aliased getattr-invoke with input() source emits code_injection', async () => {
    const code = [
      'def handler(obj):',
      '    name = input()',
      '    fn = getattr(obj, name)',
      '    fn()',
      '',
    ].join('\n');
    const r = await analyze(code, 'gi.py', 'python');
    expect(sinksOf(r, 'code_injection').length).toBeGreaterThanOrEqual(1);
    expect(flowsOf(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('TP — direct getattr-invoke with input() source emits code_injection', async () => {
    const code = [
      'def handler(obj):',
      '    name = input()',
      '    return getattr(obj, name)()',
      '',
    ].join('\n');
    const r = await analyze(code, 'gi2.py', 'python');
    expect(sinksOf(r, 'code_injection').length).toBeGreaterThanOrEqual(1);
    expect(flowsOf(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('TP — os.system(input()) two-line variant flows command_injection', async () => {
    const code = [
      'import os',
      'def run():',
      '    cmd = input()',
      '    os.system(cmd)',
      '',
    ].join('\n');
    const r = await analyze(code, 'cmd.py', 'python');
    expect(flowsOf(r, 'command_injection')).toBeGreaterThanOrEqual(1);
  });

  it('TN — input() followed by shlex.quote sanitizer suppresses command_injection', async () => {
    const code = [
      'import os, shlex',
      'def run():',
      '    raw = input()',
      '    safe = shlex.quote(raw)',
      '    os.system("ls " + safe)',
      '',
    ].join('\n');
    const r = await analyze(code, 'safe.py', 'python');
    // shlex.quote IS registered as a command_injection sanitizer.
    expect(flowsOf(r, 'command_injection')).toBe(0);
  });
});
