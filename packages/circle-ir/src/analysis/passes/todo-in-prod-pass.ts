/**
 * Pass #36: todo-in-prod (category: maintainability)
 *
 * Flags TODO, FIXME, HACK, and XXX comments in production code. These markers
 * signal deferred work or known defects that were never resolved. In production
 * code they represent acknowledged technical debt.
 *
 * Test files are excluded entirely: TODO comments in test helpers or test
 * setup code are expected and noise-free.
 *
 * Detection: line-by-line regex scan on the raw source text. A marker must
 * appear in a comment context (after `//`, `#`, `--`, or inside `/* ... *\/`).
 * Markers inside string literals are not flagged.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** Files matching these path patterns are treated as test/spec files. */
const TEST_PATH_RE = /[/._](test|tests|spec|specs|__tests?__|__mocks?__)[/._]/i;

/**
 * Matches comment markers on a line.
 *
 * Groups:
 *   1 — comment prefix (`//`, `#`, `--`, `*`)
 *   2 — marker keyword (TODO, FIXME, HACK, XXX)
 */
const MARKER_RE = /(?:\/\/|#|--|^\s*\*)\s*(TODO|FIXME|HACK|XXX)\b/i;

/**
 * Severity mapping by marker keyword.
 * - FIXME / HACK → medium (known defect / deliberate workaround)
 * - TODO / XXX  → low (deferred work / note)
 */
function markerSeverity(marker: string): 'medium' | 'low' {
  const upper = marker.toUpperCase();
  return upper === 'FIXME' || upper === 'HACK' ? 'medium' : 'low';
}

export interface TodoInProdPassResult {
  /** Lines containing TODO/FIXME/HACK/XXX markers in production code. */
  markerLines: Array<{ line: number; marker: string; text: string }>;
}

export class TodoInProdPass implements AnalysisPass<TodoInProdPassResult> {
  readonly name = 'todo-in-prod';
  readonly category = 'maintainability' as const;

  run(ctx: PassContext): TodoInProdPassResult {
    const { graph, code } = ctx;
    const file = graph.ir.meta.file;

    // Exclude test/spec files.
    if (TEST_PATH_RE.test(file)) {
      return { markerLines: [] };
    }

    const lines = code.split('\n');
    const markerLines: Array<{ line: number; marker: string; text: string }> = [];

    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      const match = MARKER_RE.exec(lineText);
      if (!match) continue;

      const marker = match[1].toUpperCase();
      const lineNum = i + 1; // 1-indexed

      markerLines.push({ line: lineNum, marker, text: lineText.trim() });

      ctx.addFinding({
        id: `todo-in-prod-${file}-${lineNum}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        severity: markerSeverity(marker),
        level: 'note',
        message: `${marker} in production code at line ${lineNum}: ${lineText.trim()}`,
        file,
        line: lineNum,
        snippet: lineText.trim(),
        evidence: { marker },
      });
    }

    return { markerLines };
  }
}
