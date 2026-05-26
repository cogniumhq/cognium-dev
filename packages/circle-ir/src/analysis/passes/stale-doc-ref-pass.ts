/**
 * Pass #33: stale-doc-ref
 *
 * Flags doc comment references (using link/see JSDoc tags) that point to
 * symbols not found in the file's type declarations or imports.
 * Stale doc refs cause confusion and erode documentation trustworthiness.
 *
 * Category: maintainability | Severity: low | Level: note | CWE: none
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { SastFinding } from '../../types/index.js';

export interface StaleDocRefResult {
  staleRefs: Array<{ line: number; ref: string }>;
}

// Matches /** ... */ blocks (non-greedy, multiline)
const DOC_BLOCK_RE = /\/\*\*([\s\S]*?)\*\//g;
// Matches {@link Foo.Bar#method} or {@link Foo}
const LINK_RE = /\{@link\s+([\w.#]+)/g;
// Matches @see Foo.Bar or @see Foo
const SEE_RE  = /@see\s+([\w.#]+)/g;

/**
 * Normalize a symbol reference: strip method fragment (#method) and
 * take the last dot-separated segment (so "java.util.List" → "List").
 */
function normalizeRef(raw: string): string {
  const withoutMethod = raw.split('#')[0];
  const parts = withoutMethod.split('.');
  return parts[parts.length - 1] ?? raw;
}

/**
 * Return the 1-based line number of the start of a match within `code`.
 */
function lineOfIndex(code: string, index: number): number {
  let line = 1;
  const limit = Math.min(index, code.length);
  for (let i = 0; i < limit; i++) {
    if (code[i] === '\n') line++;
  }
  return line;
}

export class StaleDocRefPass implements AnalysisPass<StaleDocRefResult> {
  readonly name = 'stale-doc-ref';
  readonly category = 'maintainability' as const;

  run(ctx: PassContext): StaleDocRefResult {
    const staleRefs: Array<{ line: number; ref: string }> = [];

    // Build known-symbol set from types + imports
    const knownSymbols = new Set<string>();
    for (const t of ctx.graph.ir.types) {
      knownSymbols.add(t.name);
    }
    for (const imp of ctx.graph.ir.imports) {
      if (imp.imported_name && imp.imported_name !== '*' && imp.imported_name !== 'default') {
        knownSymbols.add(imp.imported_name);
      }
      if (imp.alias) {
        knownSymbols.add(imp.alias);
      }
    }

    const code = ctx.code;
    DOC_BLOCK_RE.lastIndex = 0;

    let blockMatch: RegExpExecArray | null;
    while ((blockMatch = DOC_BLOCK_RE.exec(code)) !== null) {
      const blockStart = blockMatch.index;
      const blockText  = blockMatch[0];

      // Extract all refs from the block
      const refs: Array<{ raw: string; offsetInBlock: number }> = [];

      LINK_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = LINK_RE.exec(blockText)) !== null) {
        refs.push({ raw: m[1], offsetInBlock: m.index });
      }

      SEE_RE.lastIndex = 0;
      while ((m = SEE_RE.exec(blockText)) !== null) {
        refs.push({ raw: m[1], offsetInBlock: m.index });
      }

      for (const { raw, offsetInBlock } of refs) {
        const normalized = normalizeRef(raw);
        if (!knownSymbols.has(normalized)) {
          const absIdx = blockStart + offsetInBlock;
          const line   = lineOfIndex(code, absIdx);
          staleRefs.push({ line, ref: normalized });

          const finding: SastFinding = {
            id:       `stale-doc-ref-${ctx.graph.ir.meta.file.replace(/[^a-z0-9]/gi, '-')}-${line}`,
            pass:     'stale-doc-ref',
            category: 'maintainability',
            rule_id:  'stale-doc-ref',
            severity: 'low',
            level:    'note',
            message:  `Doc comment references unknown symbol '${normalized}'. Update or remove the stale reference.`,
            file:     ctx.graph.ir.meta.file,
            line,
            evidence: { ref: normalized, raw },
          };
          ctx.addFinding(finding);
        }
      }
    }

    return { staleRefs };
  }
}
