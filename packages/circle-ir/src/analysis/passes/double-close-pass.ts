/**
 * Pass #31: double-close (CWE-675, category: reliability)
 *
 * Detects I/O resources that are closed more than once within the same
 * method.  Calling close() on an already-closed stream (e.g., Java's
 * FileInputStream, Node.js streams) typically throws an exception and
 * indicates a resource-management bug.
 *
 * Detection strategy:
 *   1. Find resource-opening calls (same patterns as resource-leak-pass).
 *   2. Collect the bound variable from DFG defs at the open line.
 *   3. Find ALL close() calls on that variable within the enclosing method.
 *   4. If two or more close calls exist:
 *      a. Skip if both are inside a finally block (benign idiomatic pattern).
 *      b. Otherwise emit a finding.
 *
 * Languages: Java, JavaScript, TypeScript, Python, Rust (skip Bash).
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** Constructors that produce closeable resources. */
const RESOURCE_CTORS: ReadonlySet<string> = new Set([
  'FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter',
  'BufferedReader', 'BufferedWriter', 'PrintWriter', 'InputStreamReader',
  'OutputStreamWriter', 'RandomAccessFile', 'DataInputStream', 'DataOutputStream',
  'ObjectInputStream', 'ObjectOutputStream', 'ZipInputStream', 'ZipOutputStream',
  'JarInputStream', 'JarOutputStream', 'GZIPInputStream', 'GZIPOutputStream',
  'FileChannel', 'Socket', 'ServerSocket', 'DatagramSocket',
]);

/** Factory / open methods that return closeable resources. */
const RESOURCE_FACTORY_METHODS: ReadonlySet<string> = new Set([
  'openConnection', 'openStream', 'newInputStream', 'newOutputStream',
  'newBufferedReader', 'newBufferedWriter', 'newByteChannel',
  'open', 'createReadStream', 'createWriteStream', 'createConnection',
]);

/** Methods that release a resource. */
const CLOSE_METHODS: ReadonlySet<string> = new Set([
  'close', 'dispose', 'shutdown', 'disconnect', 'release', 'destroy', 'free',
  'shutdownNow', 'terminate',
]);

export interface DoubleCloseResult {
  doubleCloses: Array<{ openLine: number; closeLines: number[]; variable: string }>;
}

export class DoubleClosePass implements AnalysisPass<DoubleCloseResult> {
  readonly name = 'double-close';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): DoubleCloseResult {
    const { graph, code } = ctx;

    if (ctx.language === 'bash') return { doubleCloses: [] };

    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');
    const doubleCloses: DoubleCloseResult['doubleCloses'] = [];

    for (const call of graph.ir.calls) {
      const name = call.method_name;
      const isConstructor = call.is_constructor === true && RESOURCE_CTORS.has(name);
      const isFactory = !call.is_constructor && RESOURCE_FACTORY_METHODS.has(name);
      if (!isConstructor && !isFactory) continue;

      const openLine = call.location.line;
      const defs = graph.defsAtLine(openLine);
      if (defs.length === 0) continue;
      const resourceVar = defs[0].variable;

      const methodInfo = graph.methodAtLine(openLine);
      if (!methodInfo) continue;
      const { start_line: methodStart, end_line: methodEnd } = methodInfo.method;

      // Collect all close calls on resourceVar within the method
      const closeCalls = graph.ir.calls.filter(
        c =>
          CLOSE_METHODS.has(c.method_name) &&
          c.receiver === resourceVar &&
          c.location.line > openLine &&
          c.location.line <= methodEnd,
      );

      if (closeCalls.length < 2) continue;

      const closeLines = closeCalls.map(c => c.location.line);

      // Benign check: skip if all closes are guarded by finally
      // (common idiom: try { ... } finally { res.close(); } + catch { res.close(); })
      const allInFinally = closeLines.every(cl =>
        this.isInFinallyBlock(codeLines, cl, methodStart, methodEnd),
      );
      if (allInFinally) continue;

      doubleCloses.push({ openLine, closeLines, variable: resourceVar });

      const snippet = (codeLines[openLine - 1] ?? '').trim();
      const linesStr = closeLines.join(' and ');
      ctx.addFinding({
        id: `double-close-${file}-${openLine}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-675',
        severity: 'medium',
        level: 'warning',
        message:
          `Double close: \`${resourceVar}\` is closed at lines ${linesStr} — ` +
          `closing an already-closed resource may throw`,
        file,
        line: openLine,
        snippet,
        fix:
          `Close the resource exactly once in a finally block; ` +
          `add a null/isClosed guard before the second close if closing on multiple paths`,
        evidence: { variable: resourceVar, close_lines: closeLines },
      });
    }

    return { doubleCloses };
  }

  /** True if the given line is inside a `finally` block in the method. */
  private isInFinallyBlock(
    lines: string[],
    targetLine: number,
    methodStart: number,
    methodEnd: number,
  ): boolean {
    for (let ln = methodStart; ln <= targetLine && ln <= methodEnd && ln <= lines.length; ln++) {
      if (/\bfinally\b/.test(lines[ln - 1] ?? '')) return true;
    }
    return false;
  }
}
