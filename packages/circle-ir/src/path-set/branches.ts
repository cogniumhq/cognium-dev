/**
 * Branch facts: for every `if` statement in a file, the calls its condition
 * makes (and whether each is negated), the line ranges of its two branches,
 * and whether each branch leaves the enclosing block (`throw`, `return`,
 * `raise`, `break`, `continue`) on every path through its top level.
 *
 * Read from the syntax tree with circle-ir's own parser. The CFG alone cannot
 * answer "which side of this check does that line run on": it carries no
 * throw edge (a `throw` block falls through to the next block) and does not
 * keep the condition's negation. These facts fill that gap; they decide
 * nothing.
 *
 * Async (parsing is); every consumer takes the facts as plain data, so the
 * analysis that uses them stays synchronous and pure.
 */

import type { Node } from 'web-tree-sitter';
import { disposeTree, parse, type SupportedLanguage } from '../core/parser.js';

export interface BranchCall {
  /** Method or function name as written (`startsWith`, `contains`). */
  method: string;
  /** 1-based line and 0-based column of the call. */
  line: number;
  column: number;
  /** An odd number of `!` / `not` operators sit between the call and the condition root. */
  negated: boolean;
}

export interface BranchRange {
  start: number;
  end: number;
  /** Every path through the branch's top level leaves the enclosing block. */
  exits: boolean;
}

export interface BranchFact {
  /** First and last line of the condition. */
  line: number;
  endLine: number;
  /** Last line of the whole `if` statement, `else` included. */
  stmtEnd: number;
  calls: BranchCall[];
  then: BranchRange;
  else?: BranchRange;
}

/** The side of a branch a line runs on: `true`/`false` of the condition, or `both` (not decided by it). */
export type BranchSide = boolean | 'both';

const CALL_TYPES = new Set(['method_invocation', 'call_expression', 'call', 'invocation_expression']);
const EXIT_TYPES = new Set(['throw_statement', 'return_statement', 'raise_statement', 'break_statement', 'continue_statement']);
const BLOCK_TYPES = new Set(['block', 'statement_block', 'compound_statement']);

function calleeName(call: Node): string {
  const name = call.childForFieldName('name');
  if (name) return name.text;
  const fn = call.childForFieldName('function');
  if (!fn) return call.text;
  const prop = fn.childForFieldName('property') ?? fn.childForFieldName('attribute') ?? fn.childForFieldName('field');
  return (prop ?? fn).text;
}

function isNegation(n: Node): boolean {
  if (n.type === 'not_operator') return true;
  if (n.type !== 'unary_expression') return false;
  const op = n.childForFieldName('operator') ?? n.child(0);
  return op?.text === '!';
}

function conditionCalls(cond: Node): BranchCall[] {
  const out: BranchCall[] = [];
  const walk = (n: Node, negations: number): void => {
    const neg = negations + (isNegation(n) ? 1 : 0);
    if (CALL_TYPES.has(n.type)) {
      out.push({ method: calleeName(n), line: n.startPosition.row + 1, column: n.startPosition.column, negated: neg % 2 === 1 });
    }
    for (const c of n.namedChildren) if (c) walk(c, neg);
  };
  walk(cond, 0);
  return out;
}

/** Does every path through this statement leave the enclosing block? */
function exits(stmt: Node | null): boolean {
  if (!stmt) return false;
  if (EXIT_TYPES.has(stmt.type)) return true;
  if (BLOCK_TYPES.has(stmt.type) || stmt.type === 'block' || stmt.type === 'else_clause') {
    return stmt.namedChildren.some(c => c !== null && exits(c));
  }
  if (stmt.type === 'if_statement') {
    const alt = stmt.childForFieldName('alternative');
    return exits(stmt.childForFieldName('consequence')) && alt !== null && exits(alt);
  }
  return false;
}

function range(n: Node): BranchRange {
  return { start: n.startPosition.row + 1, end: n.endPosition.row + 1, exits: exits(n) };
}

/** Branch facts for every `if` statement in `code`, in source order. */
export async function deriveBranchFacts(code: string, language: SupportedLanguage): Promise<BranchFact[]> {
  const tree = await parse(code, language);
  try {
    const out: BranchFact[] = [];
    const walk = (n: Node): void => {
      if (n.type === 'if_statement') {
        const cond = n.childForFieldName('condition');
        const cons = n.childForFieldName('consequence');
        const alt = n.childForFieldName('alternative');
        if (cond && cons) {
          const fact: BranchFact = {
            line: cond.startPosition.row + 1,
            endLine: cond.endPosition.row + 1,
            stmtEnd: n.endPosition.row + 1,
            calls: conditionCalls(cond),
            then: range(cons),
          };
          if (alt) fact.else = range(alt);
          out.push(fact);
        }
      }
      for (const c of n.namedChildren) if (c) walk(c);
    };
    walk(tree.rootNode);
    return out;
  } finally {
    disposeTree(tree);
  }
}

/**
 * The side of `fact`'s condition on which `line` runs: inside a branch, that
 * branch's side; after the statement, the side of the branch that does not
 * leave the block when exactly one of them does; otherwise `both`.
 */
export function sideOf(fact: BranchFact, line: number): BranchSide {
  if (line >= fact.then.start && line <= fact.then.end) return true;
  if (fact.else && line >= fact.else.start && line <= fact.else.end) return false;
  if (line <= fact.stmtEnd) return 'both';
  const thenExits = fact.then.exits;
  const elseExits = fact.else?.exits ?? false;
  if (thenExits && !elseExits) return false;
  if (elseExits && !thenExits) return true;
  return 'both';
}
