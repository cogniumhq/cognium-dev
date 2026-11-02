/**
 * ConstantPropagationPass
 *
 * Runs constant propagation + dead-code detection over the AST.
 *
 * Depends on: taint-matcher (to extract inter-procedural tainted parameters
 * before propagation, so method-parameter taint is seeded correctly).
 *
 * Receives the parsed Tree via constructor because it needs the raw AST for
 * node-level analysis — the CodeGraph contains only extracted IR.
 */

import type { Tree } from 'web-tree-sitter';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import { analyzeConstantPropagation, type ConstantPropagatorResult } from '../constant-propagation.js';
import type { TaintMatcherResult } from './taint-matcher-pass.js';

export type { ConstantPropagatorResult };

export class ConstantPropagationPass implements AnalysisPass<ConstantPropagatorResult> {
  readonly name = 'constant-propagation';
  readonly category = 'security' as const;

  constructor(private readonly tree: Tree) {}

  run(ctx: PassContext): ConstantPropagatorResult {
    const { code } = ctx;
    const taintMatcher = ctx.getResult<TaintMatcherResult>('taint-matcher');

    // Extract inter-procedural parameter sources from the preliminary taint results.
    // These seeds ensure that method parameters receiving tainted data are tracked.
    const taintedParameters: Array<{ methodName: string; paramName: string }> = [];
    for (const source of taintMatcher.sources) {
      if (source.type === 'interprocedural_param') {
        // Location format: "ParamType paramName in methodName"
        const match = source.location.match(/(\S+)\s+(\S+)\s+in\s+(\S+)/);
        if (match) {
          taintedParameters.push({
            methodName: match[3],
            paramName: match[2],
          });
        }
      }
    }

    const result = analyzeConstantPropagation(this.tree, code, {
      sanitizerMethods: taintMatcher.sanitizerMethods,
      taintedParameters,
    });
    if (ctx.language === 'java') pruneDeadChains(ctx, result.unreachableLines);
    return result;
  }
}

/**
 * Java: a def on a line const-prop proved unreachable (`else bar = param;`
 * under a constant-true condition) propagates nothing. Drop its DFG chains so
 * every chain walker — notably the cross-file interprocedural phase, which
 * has no const-prop of its own — sees only live paths (#976: the try defs
 * exposed OWASP dead-branch helpers whose source is in another file).
 */
function pruneDeadChains(ctx: PassContext, unreachable: ReadonlySet<number>): void {
  if (unreachable.size === 0) return;
  const dfg = ctx.graph.ir.dfg;
  if (!dfg.chains || dfg.chains.length === 0) return;
  // Unreachable lines are line-granular: a ternary's dead arm marks the line of
  // a live def (`bar = c ? "never" : param;`), so such lines are left alone.
  const lines = ctx.code.split('\n');
  const dead = new Set<number>();
  for (const d of dfg.defs) {
    if (unreachable.has(d.line) && !/\?[^?.:]*:/.test(lines[d.line - 1] ?? '')) dead.add(d.id);
  }
  if (dead.size === 0) return;
  dfg.chains = dfg.chains.filter(c => !dead.has(c.from_def) && !dead.has(c.to_def));
}
