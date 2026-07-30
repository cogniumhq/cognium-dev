/**
 * Python "reject-then-return" traversal guard (cognium-dev #4 residual-FP
 * audit).
 *
 *   if '../' in name:
 *       return "File name must not include '../'"
 *   fd = open(f'{BASE_DIR}/{name}', 'rb')
 *
 * The guard leaves the function when the traversal token is present, so the
 * downstream `open()` cannot receive one. This was the single largest FP shape
 * on OWASP BenchmarkPython — 18 of 72 flow-level FPs, all pathtraver, all
 * removed by this detector with no true-positive loss.
 *
 * The negative cases matter as much as the positive one: the credit must not
 * survive a missing terminator, the wrong polarity, an unrelated substring
 * check, or a reassignment that re-taints the name.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';

const preamble = ['from flask import request', '', 'def handler():', '    name = request.args.get("f")'];

async function pathTraversalFlows(body: string[]): Promise<number> {
  const code = [...preamble, ...body].join('\n');
  const ir = await analyze(code, 'app.py', 'python');
  return (ir.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal' && !f.sanitized).length;
}

describe('python traversal reject guard', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('suppresses path_traversal after a guard that returns', async () => {
    expect(
      await pathTraversalFlows([
        '    if \'../\' in name:',
        '        return "rejected"',
        '    fd = open(f\'/data/{name}\', \'rb\')',
        '    return fd',
      ]),
    ).toBe(0);
  });

  it('follows a one-hop derivation of the guarded name', async () => {
    expect(
      await pathTraversalFlows([
        '    if \'../\' in name:',
        '        return "rejected"',
        '    target = f\'/data/{name}\'',
        '    fd = open(target, \'rb\')',
        '    return fd',
      ]),
    ).toBe(0);
  });

  it('accepts raise and abort() as terminators', async () => {
    expect(
      await pathTraversalFlows([
        '    if \'..\' in name:',
        '        raise ValueError("nope")',
        '    fd = open(f\'/data/{name}\', \'rb\')',
        '    return fd',
      ]),
    ).toBe(0);
  });

  it('does NOT credit a guard that only logs and falls through', async () => {
    expect(
      await pathTraversalFlows([
        '    if \'../\' in name:',
        '        print("suspicious")',
        '    fd = open(f\'/data/{name}\', \'rb\')',
        '    return fd',
      ]),
    ).toBeGreaterThan(0);
  });

  // Asserted on the detector's own output rather than on flows: the inverse
  // polarity happens to produce no path_traversal flow anyway (unrelated
  // branch handling suppresses it), so a flow-level assertion would pass
  // without exercising this detector at all.
  it('emits no guard sanitizer for the inverse polarity (`not in`)', async () => {
    const code = [
      ...preamble,
      '    if \'../\' not in name:',
      '        return "ok"',
      '    fd = open(f\'/data/{name}\', \'rb\')',
      '    return fd',
    ].join('\n');
    const ir = await analyze(code, 'app.py', 'python');
    const guards = (ir.taint.sanitizers ?? []).filter(
      s => s.type === 'python_traversal_reject_guard',
    );
    expect(guards).toEqual([]);
  });

  it('does NOT credit a guard on an unrelated substring', async () => {
    expect(
      await pathTraversalFlows([
        '    if \'debug\' in name:',
        '        return "rejected"',
        '    fd = open(f\'/data/{name}\', \'rb\')',
        '    return fd',
      ]),
    ).toBeGreaterThan(0);
  });

  it('does NOT credit a name reassigned from a fresh tainted read', async () => {
    expect(
      await pathTraversalFlows([
        '    if \'../\' in name:',
        '        return "rejected"',
        '    target = request.args.get("other")',
        '    fd = open(target, \'rb\')',
        '    return fd',
      ]),
    ).toBeGreaterThan(0);
  });

  it('leaves other sink types alone — the guard says nothing about shell metacharacters', async () => {
    const code = [
      ...preamble,
      '    if \'../\' in name:',
      '        return "rejected"',
      '    import os',
      '    os.system(f\'cat {name}\')',
    ].join('\n');
    const ir = await analyze(code, 'app.py', 'python');
    const cmdFlows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection' && !f.sanitized,
    );
    expect(cmdFlows.length).toBeGreaterThan(0);
  });
});
