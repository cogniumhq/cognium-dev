/**
 * Pass #29: broad-catch (CWE-396, category: reliability)
 *
 * Detects catch clauses that catch a base exception type (Exception,
 * Throwable, BaseException) rather than the specific subtypes the code
 * can handle.  Broad catches suppress unexpected errors, make bugs harder
 * to find, and can inadvertently catch serious errors (OutOfMemoryError,
 * StackOverflowError) that should not be swallowed.
 *
 * Detection strategy:
 *   1. Build an ExceptionFlowGraph to locate catch handler entry lines.
 *   2. Check the source text of each catch line for broad-catch patterns.
 *
 * Languages: Java, Python only.
 *   - JS/TS: no typed catch clauses; not applicable.
 *   - Rust/Bash: no traditional exceptions; skip.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import { ExceptionFlowGraph } from '../../graph/exception-flow-graph.js';

/** Java: catch(Exception|Throwable|RuntimeException|Error ...) */
const JAVA_BROAD_RE = /catch\s*\(\s*(Exception|Throwable|RuntimeException|Error)\s/;

/**
 * Python: bare `except:` or `except Exception[/BaseException][:]`
 * Also matches `except (Exception, ...):` patterns.
 */
const PYTHON_BROAD_RE = /^\s*except\s*:|except\s+(Exception|BaseException)\b/;

export interface BroadCatchResult {
  broadCatches: Array<{ line: number; type: string }>;
}

export class BroadCatchPass implements AnalysisPass<BroadCatchResult> {
  readonly name = 'broad-catch';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): BroadCatchResult {
    const { graph, code, language } = ctx;

    if (language !== 'java' && language !== 'python') {
      return { broadCatches: [] };
    }

    const { cfg } = graph.ir;
    if (cfg.blocks.length === 0) return { broadCatches: [] };

    const exGraph = new ExceptionFlowGraph(cfg, graph.blockById);
    if (!exGraph.hasTryCatch) return { broadCatches: [] };

    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');
    const broadCatches: BroadCatchResult['broadCatches'] = [];
    const reported = new Set<number>();

    const pattern = language === 'java' ? JAVA_BROAD_RE : PYTHON_BROAD_RE;

    for (const pair of exGraph.pairs) {
      const catchLine = pair.catchBlock.start_line;
      if (reported.has(catchLine)) continue;

      const lineText = codeLines[catchLine - 1] ?? '';
      const match = pattern.exec(lineText);
      if (!match) continue;

      const caughtType = match[1] ?? 'Exception';
      reported.add(catchLine);
      broadCatches.push({ line: catchLine, type: caughtType });

      const snippet = lineText.trim();
      ctx.addFinding({
        id: `broad-catch-${file}-${catchLine}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-396',
        severity: 'low',
        level: 'warning',
        message:
          `Broad catch: catching \`${caughtType}\` at line ${catchLine} suppresses ` +
          `unexpected errors and hides bugs`,
        file,
        line: catchLine,
        snippet,
        fix:
          language === 'java'
            ? `Catch the specific exception types your code can handle (e.g., \`IOException\`, \`SQLException\`)`
            : `Catch the specific exception types your code can handle (e.g., \`ValueError\`, \`KeyError\`)`,
        evidence: { caughtType },
      });
    }

    return { broadCatches };
  }
}
