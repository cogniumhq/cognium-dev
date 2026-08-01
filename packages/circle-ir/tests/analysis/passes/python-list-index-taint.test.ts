/**
 * Python per-element list taint (cognium-dev #4 residual-FP audit, slice 4).
 *
 *   lst = []
 *   lst.append('safe')      # [safe]
 *   lst.append(param)       # [safe, TAINT]
 *   lst.append('moresafe')  # [safe, TAINT, moresafe]
 *   lst.pop(0)              # [TAINT, moresafe]  ← shift
 *   bar = lst[1]            # 'moresafe' — NOT tainted
 *
 * `buildPythonTaintedVars` previously marked the whole container tainted on
 * any tainted append, so every later index read inherited it. This was the
 * largest remaining FP shape (13 files spanning xpathi, ldapi, redirect,
 * codeinj, pathtraver). `ConstantPropagationPass` has done the equivalent
 * index shifting for Java `list.add/remove/get` for some time.
 *
 * Precision cuts both ways here, so the reads that SHOULD stay tainted are
 * asserted just as heavily as the ones that should not.
 */

import { describe, it, expect } from 'vitest';
import { buildPythonTaintedVars } from '../../../src/analysis/passes/language-sources-pass.js';

const src = (...body: string[]): string =>
  ['from flask import request', 'def handler():', '    param = request.args.get("p")', ...body].join('\n');

describe('python per-element list taint', () => {
  it('resolves the benchmark shape: pop(0) shifts the tainted element down', () => {
    const tainted = buildPythonTaintedVars(
      src(
        '    lst = []',
        "    lst.append('safe')",
        '    lst.append(param)',
        "    lst.append('moresafe')",
        '    lst.pop(0)',
        '    bar = lst[1]',
      ),
    );
    expect(tainted.has('bar')).toBe(false);
  });

  it('keeps taint when the index lands ON the tainted element', () => {
    const tainted = buildPythonTaintedVars(
      src(
        '    lst = []',
        "    lst.append('safe')",
        '    lst.append(param)',
        "    lst.append('moresafe')",
        '    lst.pop(0)',
        '    bar = lst[0]',
      ),
    );
    expect(tainted.has('bar')).toBe(true);
  });

  it('handles negative indices', () => {
    const tainted = buildPythonTaintedVars(
      src('    lst = []', "    lst.append('safe')", '    lst.append(param)', '    bar = lst[-1]'),
    );
    expect(tainted.has('bar')).toBe(true);
  });

  it('tracks insert() at a literal index', () => {
    const tainted = buildPythonTaintedVars(
      src(
        '    lst = []',
        "    lst.append('a')",
        "    lst.append('b')",
        '    lst.insert(1, param)',
        '    bar = lst[1]',
        '    safe = lst[2]',
      ),
    );
    expect(tainted.has('bar')).toBe(true);
    expect(tainted.has('safe')).toBe(false);
  });

  it('binds the removed element to the pop() result', () => {
    const tainted = buildPythonTaintedVars(
      src('    lst = []', "    lst.append('safe')", '    lst.append(param)', '    got = lst.pop(1)'),
    );
    expect(tainted.has('got')).toBe(true);
  });

  it('tracks a list literal', () => {
    const tainted = buildPythonTaintedVars(
      src("    lst = ['safe', param, 'other']", '    bar = lst[0]', '    evil = lst[1]'),
    );
    expect(tainted.has('bar')).toBe(false);
    expect(tainted.has('evil')).toBe(true);
  });

  it('falls back to whole-container taint after an unmodelled mutation', () => {
    const tainted = buildPythonTaintedVars(
      src(
        '    lst = []',
        "    lst.append('safe')",
        '    lst.append(param)',
        '    lst.extend(other)',   // not modelled — stop tracking elements
        '    bar = lst[0]',
      ),
    );
    expect(tainted.has('bar')).toBe(true);
  });

  it('stops tracking when the name is rebound', () => {
    const tainted = buildPythonTaintedVars(
      src(
        '    lst = []',
        "    lst.append('safe')",
        '    lst = build(param)',
        '    bar = lst[0]',
      ),
    );
    expect(tainted.has('bar')).toBe(true);
  });

  it('stops tracking when an index is out of the known range', () => {
    const tainted = buildPythonTaintedVars(
      src('    lst = []', '    lst.append(param)', '    bar = lst[5]'),
    );
    // Out of range → no precise answer → the coarse container taint stands.
    expect(tainted.has('bar')).toBe(true);
  });
});
