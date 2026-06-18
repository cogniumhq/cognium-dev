/**
 * Constant Propagation Engine
 *
 * Tracks constant values through variable assignments and evaluates expressions
 * to detect dead code and reduce false positives in taint analysis.
 *
 * @module constant-propagation
 */

import type { Tree } from 'web-tree-sitter';
import type { ConstantPropagatorResult, ConstantPropagationOptions } from './types.js';
import { ConstantPropagator } from './propagator.js';

// Re-export types
export type { ConstantType, ConstantValue, ConstantPropagatorResult, ConstantPropagationOptions, TaintedParameter } from './types.js';

// Re-export utilities
export { isKnown, createUnknown, createConstant, getNodeText, getNodeLine } from './ast-utils.js';

// Re-export patterns
export { TAINT_PATTERNS, TAINT_PATTERN_REGEX, SANITIZER_METHODS, PROPAGATOR_METHODS } from './patterns.js';

// Re-export classes
export { ExpressionEvaluator } from './evaluator.js';
export { ConstantPropagator } from './propagator.js';

/**
 * Analyze source code for constant propagation.
 *
 * @param tree - Parsed AST from tree-sitter
 * @param sourceCode - Original source code
 * @param options - Analysis options
 * @returns Constant propagation result with symbols, tainted vars, and unreachable lines
 */
export function analyzeConstantPropagation(
  tree: Tree,
  sourceCode: string,
  options: ConstantPropagationOptions = {}
): ConstantPropagatorResult {
  const propagator = new ConstantPropagator();
  return propagator.analyze(
    tree,
    sourceCode,
    options.additionalTaintPatterns ?? [],
    options.sanitizerMethods ?? [],
    options.taintedParameters ?? []
  );
}

/**
 * Check if a potential vulnerability is a false positive.
 *
 * @param result - Constant propagation result
 * @param sinkLine - Line number of the sink
 * @param taintedVar - Name of the potentially tainted variable
 * @returns Object indicating if it's a false positive and the reason
 */
export function isFalsePositive(
  result: ConstantPropagatorResult,
  sinkLine: number,
  taintedVar: string
): { isFalsePositive: boolean; reason: string | null } {
  // Reason 1: Sink is in dead code
  if (result.unreachableLines.has(sinkLine)) {
    return { isFalsePositive: true, reason: 'sink_in_dead_code' };
  }

  // Reason 2: Variable has constant value (not tainted)
  const varValue = result.symbols.get(taintedVar);
  if (varValue && varValue.type !== 'unknown' && !result.tainted.has(taintedVar)) {
    return { isFalsePositive: true, reason: `variable_is_constant: ${varValue.value}` };
  }

  // Reason 3: Variable not tainted.
  //
  // Only fire when const-prop *specifically* tracked this variable (it's in
  // the symbols map) AND didn't mark it tainted. Using `symbols.size > 0` as
  // a proxy for "const-prop ran" is brittle: in JavaScript, the engine
  // doesn't process arrow-function-scoped `const c = ...` declarations, so
  // request-handler locals never appear in symbols — but a single unrelated
  // top-level assignment like `module.exports = app` adds `module.exports`
  // to symbols, flips size from 0 to 1, and then incorrectly flags every
  // flow path variable as `variable_not_tainted`. This silently zeroed JS
  // taint analysis on any realistic multi-handler Express file
  // (cognium-dev#77).
  //
  // Switching to `symbols.has(taintedVar)` is strictly tighter: we only
  // suppress when we actually tracked the var and concluded it's clean.
  //
  // cognium-dev#104 (Sprint 22) — OOP field-path variables (`self.X`,
  // `this.X`) are emitted as synthetic sources by `findOopFieldReadSources`
  // in `LanguageSourcesPass`, an entirely separate mechanism from
  // const-prop's symbol tracking. If the JS const-prop happens to record
  // `this.X = ...` while analysing the constructor body, the symbol shows
  // up but is never tagged tainted (the OOP source uses
  // `interprocedural_param`, not const-prop's intra-procedural seed). The
  // resulting FP suppression silently zeroed all JS OOP-source flows. Skip
  // the symbol check for OOP field paths — their taint provenance is
  // tracked at the source-emission layer, not in const-prop.
  if (taintedVar.startsWith('self.') || taintedVar.startsWith('this.')) {
    return { isFalsePositive: false, reason: null };
  }
  if (result.symbols.has(taintedVar) && !result.tainted.has(taintedVar)) {
    return { isFalsePositive: true, reason: 'variable_not_tainted' };
  }

  return { isFalsePositive: false, reason: null };
}

/**
 * Check if a taint flow is a false positive due to correlated predicates.
 *
 * This handles cases like:
 *   if(choice) { x = tainted; }
 *   if(!choice) { sink(x); }
 *
 * The taint of x only applies when choice=true, but the sink only executes
 * when choice=false. These are mutually exclusive paths, so no vulnerability.
 *
 * @param result - Constant propagation result with conditional taint info
 * @param flow - The taint flow to check
 * @returns true if this is a false positive due to correlated predicates
 */
export function isCorrelatedPredicateFP(
  result: ConstantPropagatorResult,
  flow: { source: { line: number }; sink: { line: number }; path: Array<{ variable: string; line: number }> }
): boolean {
  // Get the condition that guards the sink line
  const sinkCondition = result.lineConditions?.get(flow.sink.line);
  if (!sinkCondition) {
    return false; // Sink is not under a known condition
  }

  // Check each variable in the taint path
  for (const step of flow.path) {
    const varName = step.variable;

    // Check both scoped and unscoped variable names
    const checkNames = [varName, varName.split(':').pop() || varName];

    // Find which condition this variable was tainted under
    for (const [taintCond, taintedVars] of result.conditionalTaints?.entries() ?? []) {
      // Check if any of our variable names match tainted vars (considering scoping)
      let matched = false;
      for (const checkName of checkNames) {
        if (taintedVars.has(checkName)) {
          matched = true;
          break;
        }
        // Also check if any tainted var ends with :checkName (scoped match)
        for (const taintedVar of taintedVars) {
          if (taintedVar.endsWith(':' + checkName)) {
            matched = true;
            break;
          }
        }
        if (matched) break;
      }

      if (matched) {
        // Check if the taint condition and sink condition are mutually exclusive
        if (areNegatedConditions(taintCond, sinkCondition)) {
          return true; // Correlated predicate FP
        }
      }
    }
  }

  return false;
}

/**
 * Check if two condition expressions are negations of each other.
 * "x" and "!x" are negations.
 * "!x" and "x" are negations.
 */
function areNegatedConditions(cond1: string, cond2: string): boolean {
  const norm1 = normalizeCondition(cond1);
  const norm2 = normalizeCondition(cond2);

  // Check if one is the negation of the other
  if (norm1.startsWith('!') && normalizeCondition(norm1.slice(1)) === norm2) {
    return true;
  }
  if (norm2.startsWith('!') && normalizeCondition(norm2.slice(1)) === norm1) {
    return true;
  }

  return false;
}

/**
 * Normalize a condition expression for comparison.
 */
function normalizeCondition(cond: string): string {
  let normalized = cond.trim();
  // Remove outer parentheses
  while (normalized.startsWith('(') && normalized.endsWith(')')) {
    let depth = 0;
    let balanced = true;
    for (let i = 0; i < normalized.length - 1; i++) {
      if (normalized[i] === '(') depth++;
      else if (normalized[i] === ')') depth--;
      if (depth === 0 && i > 0) {
        balanced = false;
        break;
      }
    }
    if (balanced) {
      normalized = normalized.slice(1, -1).trim();
    } else {
      break;
    }
  }
  return normalized;
}
