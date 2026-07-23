/**
 * PythonReceiverTaintFormatPass — cognium-dev #264 (Python receiver-taint).
 *
 * Emits `format_string` (CWE-134) findings for Python `.format(...)` /
 * `.format_map(...)` calls whose RECEIVER is a tainted variable. The
 * generic sink-pattern schema keys exclusively on `arg_positions`,
 * which cannot represent a taint that lives on the call's receiver —
 * Python's `str.format(*args)` shape puts the format template AS the
 * receiver, not as an argument.
 *
 * ## Coverage overlap with Sprint 86 (#189)
 *
 * `language-sources-pass.ts` already carries a Sprint 86 (#189)
 * codepath that regex-matches `.format(` and `<name> %` shapes at
 * file scope, gated on the presence of a Flask / Django / FastAPI
 * request extractor in the source. **That path handles the common
 * case.** This pass is intentionally a fallback for the shapes
 * Sprint 86 misses:
 *
 *   - Files that don't reference `request.args` / `flask.request`
 *     (Sprint 86 short-circuits and never runs).
 *   - `.format_map(...)` calls — Sprint 86's regex only accepts
 *     `.format\s*\(`, not `.format_map`. As of 3.181.0 Sprint 86's
 *     regex is extended, but this pass is kept as belt-and-suspenders.
 *   - Non-Flask taint sources (e.g. `os.environ`, `sys.stdin`) that
 *     the plugin's `getBuiltinSources()` catches but Sprint 86's
 *     framework-gate excludes.
 *
 * ## Taint signal
 *
 * The pass consumes `graph.ir.taint.sources` (populated by
 * `TaintMatcherPass` before this pass runs). Each source has an
 * optional `variable` field naming the identifier the source's
 * return-value flows into. A `.format` call whose receiver name
 * matches any source's `variable` name in the same file is
 * treated as receiver-taint.
 *
 * (Prior to 3.181.0 this pass read `ConstantPropagatorResult.tainted`
 * which is empty for many Python cases — the pass no-op'd whenever
 * constant-propagation didn't populate the set. The switch to
 * `graph.ir.taint.sources[].variable` matches the taint-tracker's
 * own view of tainted identifiers and no longer depends on
 * constant-propagation state.)
 *
 * Python-only. No-op on other languages.
 *
 * Direct-finding emission via `ctx.addFinding` rather than
 * synthetic-sink emission because the source→sink relationship is
 * already established: the taint source populated `variable` at
 * assignment time; the format-call at the sink line consumes it
 * directly. Emitting a sink would require TaintPropagationPass to
 * also understand receiver-taint, a much broader engine change.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

export interface PythonReceiverTaintFormatResult {
  /** Number of `.format()` / `.format_map()` calls flagged this run. */
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

    const { calls, meta, taint } = ctx.graph.ir;

    // Collect the set of variable names that hold tainted values,
    // as seen by the taint-matcher (from `getBuiltinSources()`
    // patterns with `return_tainted: true`). This is a smaller, more
    // targeted signal than constant-propagation's `tainted` set —
    // and, crucially, it's populated for Python files even when
    // Sprint 86's Flask/Django/FastAPI regex gate short-circuits.
    const taintedVarNames = new Set<string>();
    for (const s of taint.sources) {
      if (typeof s.variable === 'string' && s.variable.length > 0) {
        taintedVarNames.add(s.variable);
      }
    }
    if (taintedVarNames.size === 0) {
      return { findingsEmitted: 0 };
    }

    // Track (line, receiver) pairs we've already flagged this file
    // to avoid emitting a second finding when Sprint 86 also fired
    // on the same call — the two paths produce different `id` values
    // but describe the same vulnerability at the same location.
    const seen = new Set<string>();

    let count = 0;
    for (const call of calls) {
      // `format` and `format_map` share the receiver-taint risk shape.
      // Both put the format template as the receiver rather than an
      // argument. `format_map` accepts a mapping instead of *args but
      // the attribute-leak / DoS surface is identical.
      if (call.method_name !== 'format' && call.method_name !== 'format_map') continue;

      const receiver = call.receiver;
      if (!receiver) continue;

      // Only bare-identifier receivers can be looked up in the
      // tainted-source set. Skip complex receivers
      // (`obj.attr.format()`, `f(x).format()`, `"literal".format()`)
      // — those either don't correspond to a taintable variable name
      // or need attribute-chain resolution the taint tracker doesn't
      // currently do.
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(receiver)) continue;

      if (!taintedVarNames.has(receiver)) continue;

      const seenKey = `${call.location.line}:${receiver}`;
      if (seen.has(seenKey)) continue;
      seen.add(seenKey);

      ctx.addFinding({
        id: `format_string-${meta.file}-${call.location.line}-${receiver}-${call.method_name}`,
        pass: this.name,
        category: 'security',
        rule_id: 'format_string',
        cwe: 'CWE-134',
        severity: 'medium',
        level: 'warning',
        message:
          `Format-string vulnerability: the format template \`${receiver}\` ` +
          `is tainted (traces back to a taint source) and used as the ` +
          `receiver of \`${call.method_name}(...)\`. Attacker can leak ` +
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
