/**
 * Pass #24: missing-await (CWE-252, category: reliability)
 *
 * Detects calls to well-known async APIs in JavaScript/TypeScript where the
 * returned Promise is silently discarded — the call result is neither awaited
 * nor captured in a variable. This is the "fire-and-forget" pattern that hides
 * errors and makes execution non-deterministic.
 *
 * Detection criteria (ALL must hold):
 *   1. Language is javascript or typescript.
 *   2. The method name is in the curated ASYNC_METHODS set.
 *   3. The source line does NOT contain the `await` keyword.
 *   4. There is no DFG definition at the call's line (result not assigned).
 *
 * Deliberately narrow to keep false-positive rate near zero. Only methods that
 * are essentially always async in practice are included. The `return async()`
 * pattern is excluded (legitimate "pass-through Promise" idiom).
 */

import type { CallInfo } from '../../types/index.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/**
 * Methods that are async in virtually every JS/TS codebase.
 * Grouped by domain for maintainability.
 */
const ASYNC_METHODS: ReadonlySet<string> = new Set([
  // Node.js fs.promises / util.promisify (the async variants)
  'readFile', 'writeFile', 'appendFile', 'unlink', 'rmdir', 'mkdir',
  'readdir', 'stat', 'lstat', 'access', 'rename', 'copyFile',
  // Network / HTTP
  'fetch',
  // Database — raw clients
  'query', 'execute',
  // Mongoose ODM
  'findOne', 'findById', 'findByIdAndUpdate', 'findByIdAndDelete',
  'findOneAndUpdate', 'findOneAndDelete', 'countDocuments', 'aggregate',
  // Sequelize / TypeORM overlap
  'findAll', 'findAndCountAll', 'bulkCreate',
  // Prisma
  'findFirst', 'findUnique', 'findMany',
  // Generic lifecycle
  'connect', 'disconnect',
]);

export interface MissingAwaitPassResult {
  /** Calls where a Promise return value is silently discarded. */
  missingAwaitCalls: CallInfo[];
}

export class MissingAwaitPass implements AnalysisPass<MissingAwaitPassResult> {
  readonly name = 'missing-await';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): MissingAwaitPassResult {
    const { graph, code, language } = ctx;

    // Only JS/TS: other languages either don't have async/await or surface
    // missing-await through their type systems (Rust, Java).
    if (language !== 'javascript' && language !== 'typescript') {
      return { missingAwaitCalls: [] };
    }

    const lines = code.split('\n');
    const file = graph.ir.meta.file;

    // Lines that have a DFG definition — result is captured in a variable.
    const linesWithDefs = new Set(graph.ir.dfg.defs.map(d => d.line));

    const missingAwaitCalls: CallInfo[] = [];

    for (const call of graph.ir.calls) {
      if (!ASYNC_METHODS.has(call.method_name)) continue;

      const lineNum = call.location.line;
      const lineText = lines[lineNum - 1] ?? '';

      // Skip if `await` is present on this line (already awaited).
      if (/\bawait\b/.test(lineText)) continue;

      // Skip if result is captured (DFG def at this line).
      if (linesWithDefs.has(lineNum)) continue;

      // Skip `return asyncOp()` — intentional Promise pass-through.
      if (/^\s*return\b/.test(lineText)) continue;

      missingAwaitCalls.push(call);

      ctx.addFinding({
        id: `missing-await-${file}-${lineNum}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-252',
        severity: 'medium',
        level: 'warning',
        message:
          `Missing await: \`${call.method_name}()\` returns a Promise that is neither ` +
          `awaited nor captured — errors will be silently swallowed`,
        file,
        line: lineNum,
        snippet: lineText.trim(),
        fix: `Add \`await\` before \`${call.method_name}()\`, or assign the Promise and handle rejection`,
      });
    }

    return { missingAwaitCalls };
  }
}
