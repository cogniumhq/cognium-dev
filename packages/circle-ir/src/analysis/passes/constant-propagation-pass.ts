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

    return analyzeConstantPropagation(this.tree, code, {
      sanitizerMethods: taintMatcher.sanitizerMethods,
      taintedParameters,
    });
  }
}
