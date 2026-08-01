/**
 * Python constant-folded conditional expression (cognium-dev #4 residual-FP
 * audit, slice 2).
 *
 *   num = 106
 *   bar = "safe" if 7 * 18 + num > 200 else param   # 232 > 200 → always safe
 *
 * The tainted branch is dead, so scanning the whole right-hand side for
 * tainted names reports a flow that cannot execute. `buildPythonTaintedVars`
 * now folds the condition when it is decidable from tracked integer constants
 * and propagates taint from the live branch only.
 *
 * The dangerous direction is over-folding: an undecidable condition, or one
 * whose live branch IS the tainted one, must keep the flow. Both are asserted.
 */

import { describe, it, expect } from 'vitest';
import { buildPythonTaintedVars } from '../../../src/analysis/passes/language-sources-pass.js';

const src = (...body: string[]): string =>
  ['from flask import request', 'def handler():', '    param = request.args.get("p")', ...body].join('\n');

describe('python constant-folded conditional expressions', () => {
  it('drops taint when the condition is always true and the safe branch wins', () => {
    const tainted = buildPythonTaintedVars(
      src('    num = 106', '    bar = "safe" if 7 * 18 + num > 200 else param'),
    );
    expect(tainted.has('param')).toBe(true);
    expect(tainted.has('bar')).toBe(false);
  });

  it('keeps taint when the condition is false and the tainted branch wins', () => {
    // (7*42) - 106 = 188, which is NOT > 200 → `bar = param`.
    const tainted = buildPythonTaintedVars(
      src('    num = 106', '    bar = "never" if (7*42) - num > 200 else param'),
    );
    expect(tainted.has('bar')).toBe(true);
  });

  it('keeps taint when the condition is undecidable', () => {
    const tainted = buildPythonTaintedVars(
      src('    num = int(request.args.get("n"))', '    bar = "safe" if num > 200 else param'),
    );
    expect(tainted.has('bar')).toBe(true);
  });

  it('keeps taint when the constant is later reassigned to something opaque', () => {
    const tainted = buildPythonTaintedVars(
      src(
        '    num = 106',
        '    num = compute()',
        '    bar = "safe" if 7 * 18 + num > 200 else param',
      ),
    );
    expect(tainted.has('bar')).toBe(true);
  });

  it('folds the always-true branch even when the tainted name is the then-branch', () => {
    // Condition true → `bar = param`; taint must be kept.
    const tainted = buildPythonTaintedVars(
      src('    num = 106', '    bar = param if 7 * 18 + num > 200 else "safe"'),
    );
    expect(tainted.has('bar')).toBe(true);
  });

  it('handles parentheses, integer division and modulo', () => {
    const tainted = buildPythonTaintedVars(
      src('    n = 10', '    bar = "safe" if (n * 3) // 2 % 7 == 1 else param'),
    );
    // (10*3)//2 = 15, 15 % 7 = 1 → condition true → safe branch.
    expect(tainted.has('bar')).toBe(false);
  });

  it('does not fold a plain assignment that merely contains the word if', () => {
    const tainted = buildPythonTaintedVars(src('    bar = param  # if in a comment'));
    expect(tainted.has('bar')).toBe(true);
  });

  it('leaves division by zero undecided rather than throwing', () => {
    const tainted = buildPythonTaintedVars(
      src('    z = 0', '    bar = "safe" if 5 // z > 1 else param'),
    );
    expect(tainted.has('bar')).toBe(true);
  });
});
