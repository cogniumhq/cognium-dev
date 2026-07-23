/**
 * PythonReceiverTaintFormatPass — cognium-dev #264 (Python receiver-taint).
 *
 * Emits `format_string` (CWE-134) findings for Python `.format(...)`
 * calls whose RECEIVER is tainted. The pre-#264-Python-slice sink
 * patterns key exclusively on `arg_positions`, which cannot represent
 * a taint that lives on the call's receiver — Python's
 * `str.format(*args)` shape puts the format template AS the receiver,
 * not as an argument. Same is true of the `%`-operator shape
 * (`taintedFmt % args`), which lives entirely in a binary-operator
 * AST node, not a call.
 *
 * This pass takes the receiver-taint half of that gap by scanning
 * `graph.ir.calls` for `.format(...)` calls whose receiver appears in
 * the constant-propagation `tainted` set. On a hit, emits a direct
 * `format_string` finding at the call site (severity `medium`, level
 * `warning`).
 *
 * The `%`-operator half is genuinely bigger — needs a new AST scan
 * over `binary_operator` nodes with format-shape RHS detection — and
 * remains deferred on #264.
 *
 * Python-only. No-op on other languages.
 *
 * Pipeline slot: runs after `ConstantPropagationPass` so the
 * `tainted` set is populated. Any pass position after
 * `constant-propagation` is safe; placing near the sink-emission
 * chain keeps like-with-like grouped.
 *
 * Direct-finding emission (via `ctx.addFinding`) rather than
 * synthetic-sink emission because the format-string vulnerability
 * here doesn't need a taint-source → sink flow trace: the
 * `constant-propagation.tainted` set implicitly encodes that the
 * receiver traces back to a source. Emitting a sink would require
 * TaintPropagationPass to also understand receiver-taint, which
 * would be a much broader engine change.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { ConstantPropagatorResult } from './constant-propagation-pass.js';

export interface PythonReceiverTaintFormatResult {
  /** Number of `.format()` calls flagged this run. */
  findingsEmitted: number;
}

export class PythonReceiverTaintFormatPass
  implements AnalysisPass<PythonReceiverTaintFormatResult>
{
  readonly name = 'python-receiver-taint-format';
  readonly category = 'security' as const;

  run(ctx: PassContext): PythonReceiverTaintFormatResult {
    if (ctx.language !== 'python') {
      return { findingsEmitted: 0 };
    }

    const { calls, meta } = ctx.graph.ir;
    const constProp = ctx.getResult<ConstantPropagatorResult>(
      'constant-propagation',
    );
    const tainted = constProp.tainted;

    let count = 0;
    for (const call of calls) {
      if (call.method_name !== 'format') continue;
      const receiver = call.receiver;
      if (!receiver) continue;

      // Only bare-identifier receivers can be looked up in the tainted
      // set. Skip complex receivers (`obj.attr.format()`, `f(x).format()`)
      // — those don't correspond to a variable name the taint tracker
      // would have on file. Recall may improve later with attribute-
      // chain resolution, but the direct-identifier form is the common
      // shape for user-controlled templates.
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(receiver)) continue;

      // constant-propagation stores both scoped (`method:var`) and
      // unscoped forms in the tainted set. Check both.
      const scopedName = call.in_method
        ? `${call.in_method}:${receiver}`
        : receiver;
      if (!tainted.has(receiver) && !tainted.has(scopedName)) continue;

      ctx.addFinding({
        id: `format_string-${meta.file}-${call.location.line}-${receiver}`,
        pass: this.name,
        category: 'security',
        rule_id: 'format_string',
        cwe: 'CWE-134',
        severity: 'medium',
        level: 'warning',
        message:
          `Format-string vulnerability: the format template \`${receiver}\` ` +
          `is tainted (traces back to a taint source). Attacker can leak ` +
          `object attributes via \`{obj.__class__.__mro__[…]}\` chains or ` +
          `crash the process via unbounded specifiers. Use a literal ` +
          `format string and pass user input as an argument instead.`,
        file: meta.file,
        line: call.location.line,
      });
      count++;
    }

    return { findingsEmitted: count };
  }
}
