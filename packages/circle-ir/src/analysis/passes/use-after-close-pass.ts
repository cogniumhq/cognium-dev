/**
 * Pass #32: use-after-close (CWE-672, category: reliability)
 *
 * Detects method calls on a resource variable that occur after the resource
 * has been closed (close/dispose/shutdown).  Using a closed stream or
 * connection throws an IOException or similar, causing unexpected runtime
 * failures.
 *
 * Detection strategy:
 *   1. Find resource-opening calls (same patterns as resource-leak-pass).
 *   2. Find the FIRST close() call on the resource variable within the method.
 *   3. If a close is found, scan subsequent calls on the same receiver variable
 *      that are NOT themselves close calls → use-after-close.
 *
 * Languages: Java, JavaScript, TypeScript, Python, Rust (skip Bash).
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

const RESOURCE_CTORS: ReadonlySet<string> = new Set([
  'FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter',
  'BufferedReader', 'BufferedWriter', 'PrintWriter', 'InputStreamReader',
  'OutputStreamWriter', 'RandomAccessFile', 'DataInputStream', 'DataOutputStream',
  'ObjectInputStream', 'ObjectOutputStream', 'ZipInputStream', 'ZipOutputStream',
  'JarInputStream', 'JarOutputStream', 'GZIPInputStream', 'GZIPOutputStream',
  'FileChannel', 'Socket', 'ServerSocket', 'DatagramSocket',
]);

const RESOURCE_FACTORY_METHODS: ReadonlySet<string> = new Set([
  'openConnection', 'openStream', 'newInputStream', 'newOutputStream',
  'newBufferedReader', 'newBufferedWriter', 'newByteChannel',
  'open', 'createReadStream', 'createWriteStream', 'createConnection',
]);

const CLOSE_METHODS: ReadonlySet<string> = new Set([
  'close', 'dispose', 'shutdown', 'disconnect', 'release', 'destroy', 'free',
  'shutdownNow', 'terminate',
]);

export interface UseAfterCloseResult {
  useAfterCloses: Array<{ openLine: number; closeLine: number; useLine: number; variable: string }>;
}

export class UseAfterClosePass implements AnalysisPass<UseAfterCloseResult> {
  readonly name = 'use-after-close';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): UseAfterCloseResult {
    const { graph, code } = ctx;

    if (ctx.language === 'bash') return { useAfterCloses: [] };

    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');
    const useAfterCloses: UseAfterCloseResult['useAfterCloses'] = [];

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
      const methodEnd = methodInfo.method.end_line;

      // Find the FIRST close call on resourceVar
      const firstClose = graph.ir.calls
        .filter(
          c =>
            CLOSE_METHODS.has(c.method_name) &&
            c.receiver === resourceVar &&
            c.location.line > openLine &&
            c.location.line <= methodEnd,
        )
        .sort((a, b) => a.location.line - b.location.line)[0];

      if (!firstClose) continue; // No close → handled by resource-leak pass

      const closeLine = firstClose.location.line;

      // Find any non-close call on resourceVar after closeLine
      const usesAfterClose = graph.ir.calls.filter(
        c =>
          c.receiver === resourceVar &&
          c.location.line > closeLine &&
          c.location.line <= methodEnd &&
          !CLOSE_METHODS.has(c.method_name),
      );

      for (const use of usesAfterClose) {
        const useLine = use.location.line;
        useAfterCloses.push({ openLine, closeLine, useLine, variable: resourceVar });

        const snippet = (codeLines[useLine - 1] ?? '').trim();
        ctx.addFinding({
          id: `use-after-close-${file}-${useLine}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-672',
          severity: 'high',
          level: 'error',
          message:
            `Use after close: \`${resourceVar}.${use.method_name}()\` at line ${useLine} ` +
            `is called after \`${resourceVar}.close()\` at line ${closeLine}`,
          file,
          line: useLine,
          snippet,
          fix:
            `Do not use a resource after closing it; keep \`${resourceVar}\` open ` +
            `until all uses are complete`,
          evidence: { variable: resourceVar, close_line: closeLine, open_line: openLine },
        });
      }
    }

    return { useAfterCloses };
  }
}
