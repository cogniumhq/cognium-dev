/**
 * ScopeGraph
 *
 * Thin wrapper over CodeGraph that enriches each DFGDef with declaration-keyword
 * awareness. Needed by the three Group-3 passes (variable-shadowing, leaked-global,
 * unused-variable) which must distinguish between a "real" variable declaration
 * (`let x = 5`) and a bare reassignment (`x = 5`).
 *
 * The DFG extractor treats both as `kind='local'` because reassignments also
 * create new reaching definitions. ScopeGraph recovers the distinction by
 * scanning the source line for language-specific declaration keywords.
 *
 * Design:
 *   - Built once per pass via `new ScopeGraph(graph, code, language)`
 *   - O(n) construction where n = number of DFG defs
 *   - No mutations — all state is computed in the constructor
 *   - Browser + Node.js safe (no platform APIs)
 */

import type { DFGDef } from '../types/index.js';
import type { CodeGraph } from './code-graph.js';

// ---------------------------------------------------------------------------
// Per-language declaration keyword patterns
// ---------------------------------------------------------------------------

/**
 * Returns true when the source line text contains a variable-declaration keyword
 * for the given language.
 *
 * Java/Rust/JS/TS: explicit keywords precede the variable name.
 * Python: no declaration keyword exists → always returns false.
 */
function hasDeclKeyword(lineText: string, language: string): boolean {
  switch (language) {
    case 'java':
      // Primitive types, `var`, `final`, generic types (upper-case first letter)
      return /\b(?:int|long|float|double|boolean|byte|char|short|var|final)\b/.test(lineText)
          || /\b[A-Z]\w*(?:<[^>]*>)?\s+\w/.test(lineText);

    case 'javascript':
    case 'typescript':
      return /\b(?:let|const|var)\s+[\w{[]/.test(lineText);

    case 'rust':
      return /\blet\s+(?:mut\s+)?\w/.test(lineText);

    default:
      // Python and other languages: no reliable declaration keyword
      return false;
  }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Enriched view of a single DFGDef with scope metadata. */
export interface ScopeEntry {
  /** The underlying DFG definition. */
  readonly def: DFGDef;
  /**
   * True when the source line that created this def contains a declaration
   * keyword appropriate for the language (e.g. `let`/`const`/`var` for JS,
   * type keyword for Java, `let` for Rust). False for bare reassignments.
   */
  readonly hasDeclKeyword: boolean;
  /**
   * `start_line` of the enclosing method, or -1 if the def is at the
   * top/module level (no enclosing method found).
   */
  readonly methodStart: number;
  /**
   * `end_line` of the enclosing method, or -1 if top-level.
   */
  readonly methodEnd: number;
}

// ---------------------------------------------------------------------------
// ScopeGraph
// ---------------------------------------------------------------------------

export class ScopeGraph {
  /** One entry per DFGDef in the IR, in original order. */
  readonly entries: ScopeEntry[];

  constructor(graph: CodeGraph, code: string, language: string) {
    const codeLines = code.split('\n');
    this.entries = graph.ir.dfg.defs.map((def): ScopeEntry => {
      const m = graph.methodAtLine(def.line);
      const lineText = codeLines[def.line - 1] ?? '';
      return {
        def,
        hasDeclKeyword: hasDeclKeyword(lineText, language),
        methodStart: m?.method.start_line ?? -1,
        methodEnd:   m?.method.end_line   ?? -1,
      };
    });
  }

  /**
   * Returns all entries whose def falls within the inclusive range
   * [start, end] (both are 1-based source line numbers).
   */
  defsInMethod(start: number, end: number): ScopeEntry[] {
    return this.entries.filter(e => e.def.line >= start && e.def.line <= end);
  }

  /**
   * Returns true if the given variable has at least one def with
   * `hasDeclKeyword === true` inside the method whose start line is
   * `methodStart` OR at module level (methodStart === -1).
   *
   * Module-level declarations are included because JavaScript/TypeScript
   * module-level `let`/`const`/`var` variables are legitimately reassigned
   * inside functions — that is not a global leak.
   *
   * Used by `leaked-global` to determine whether a bare assignment is truly
   * undeclared within its enclosing function.
   */
  hasDeclaredDef(variable: string, methodStart: number): boolean {
    return this.entries.some(
      e => e.def.variable === variable
        && e.hasDeclKeyword
        && (e.methodStart === methodStart || e.methodStart === -1),
    );
  }
}
