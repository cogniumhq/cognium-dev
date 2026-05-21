/**
 * Pass #28: swallowed-exception (CWE-390, category: reliability)
 *
 * Detects catch blocks that silently discard exceptions — no re-throw,
 * no logging call, no error return.  Swallowed exceptions hide failures,
 * make debugging extremely difficult, and can mask security issues.
 *
 * Detection strategy:
 *   1. Build an ExceptionFlowGraph from the CFG exception edges.
 *   2. For each catch handler entry block, determine the catch body bounds
 *      using a brace-depth walk of the source text.
 *   3. Scan the catch body for any "meaningful action": throw/raise,
 *      logging API call, or a non-empty return statement.
 *   4. If nothing is found → emit a finding at the catch line.
 *
 * Languages: Java, JavaScript, TypeScript, Python (skip Rust/Bash).
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import { ExceptionFlowGraph } from '../../graph/exception-flow-graph.js';

const MEANINGFUL_ACTION_RE =
  /\b(throw|raise|log|logger|console\.(error|warn|log|debug|info)|System\.(out|err)\.|print(?:ln|f)?|warn|error|debug|info|fatal|LOGGER|LOG|logging\.(warning|error|debug|info|critical))\b|\breturn\s+\S/;

export interface SwallowedExceptionResult {
  swallowed: Array<{ line: number }>;
}

export class SwallowedExceptionPass implements AnalysisPass<SwallowedExceptionResult> {
  readonly name = 'swallowed-exception';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): SwallowedExceptionResult {
    const { graph, code, language } = ctx;

    if (language === 'rust' || language === 'bash') {
      return { swallowed: [] };
    }

    const { cfg } = graph.ir;
    if (cfg.blocks.length === 0) return { swallowed: [] };

    const exGraph = new ExceptionFlowGraph(cfg, graph.blockById);
    if (!exGraph.hasTryCatch) return { swallowed: [] };

    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');
    const swallowed: SwallowedExceptionResult['swallowed'] = [];
    const reported = new Set<number>();

    for (const pair of exGraph.pairs) {
      const catchLine = pair.catchBlock.start_line;
      if (reported.has(catchLine)) continue;

      // Determine catch body end via brace-depth walk
      const methodInfo = graph.methodAtLine(catchLine);
      const scanEnd = methodInfo ? methodInfo.method.end_line : codeLines.length;
      const catchBodyEnd = this.findCatchBodyEnd(codeLines, catchLine, scanEnd);

      // Scan for any meaningful action
      let hasAction = false;
      for (let ln = catchLine; ln <= catchBodyEnd && ln <= codeLines.length; ln++) {
        if (MEANINGFUL_ACTION_RE.test(codeLines[ln - 1] ?? '')) {
          hasAction = true;
          break;
        }
      }

      // Check if the caught exception variable is forwarded via a function call
      // (e.g., `catch (err) { cb(err); }` or `catch (e) { next(e); }`)
      if (!hasAction) {
        // The catch variable may be on catchLine or catchLine-1, depending on
        // whether the CFG start_line points to the `catch (...)` declaration
        // or to the first statement inside the catch body.
        let catchDeclLine = catchLine;
        let catchVarMatch = (codeLines[catchLine - 1] ?? '').match(/catch\s*\(\s*(\w+)/);
        if (!catchVarMatch && catchLine > 1) {
          catchVarMatch = (codeLines[catchLine - 2] ?? '').match(/catch\s*\(\s*(\w+)/);
          catchDeclLine = catchLine - 1;
        }
        if (catchVarMatch) {
          const catchVar = catchVarMatch[1];
          const forwardRe = new RegExp(`\\w+\\s*\\([^)]*\\b${catchVar}\\b`);
          // Scan the catch body, skipping the catch declaration line itself
          // (which contains `catch (err)` and would false-match the regex)
          for (let ln = catchLine; ln <= catchBodyEnd && ln <= codeLines.length; ln++) {
            if (ln === catchDeclLine) continue;
            if (forwardRe.test(codeLines[ln - 1] ?? '')) {
              hasAction = true;
              break;
            }
          }
        }
      }

      if (!hasAction) {
        reported.add(catchLine);
        swallowed.push({ line: catchLine });

        const snippet = (codeLines[catchLine - 1] ?? '').trim();
        ctx.addFinding({
          id: `swallowed-exception-${file}-${catchLine}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-390',
          severity: 'medium',
          level: 'warning',
          message:
            `Swallowed exception: catch block at line ${catchLine} has no throw, log, or ` +
            `return — the exception is silently discarded`,
          file,
          line: catchLine,
          snippet,
          fix: 'At minimum log the exception, or re-throw it; never silently discard exceptions',
        });
      }
    }

    return { swallowed };
  }

  /**
   * Walks source lines starting at `startLine` counting brace depth.
   * Returns the line where the brace depth first returns to zero after
   * the opening brace (i.e., the closing brace of the catch block).
   * Capped at `maxLine`.
   */
  private findCatchBodyEnd(lines: string[], startLine: number, maxLine: number): number {
    let depth = 0;
    let started = false;
    for (let ln = startLine; ln <= maxLine && ln <= lines.length; ln++) {
      const text = lines[ln - 1] ?? '';
      for (const ch of text) {
        if (ch === '{') {
          depth++;
          started = true;
        } else if (ch === '}' && started) {
          depth--;
        }
      }
      if (started && depth <= 0) return ln;
    }
    return maxLine;
  }
}
