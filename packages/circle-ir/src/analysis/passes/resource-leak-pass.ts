/**
 * Pass #21: resource-leak (CWE-772, category: reliability)
 *
 * Detects I/O resources (streams, connections, sockets) that are opened but
 * not closed on all exit paths. Unclosed resources exhaust file descriptors
 * or connection pools and cause subtle failures under load.
 *
 * Detection strategy:
 *   1. Find resource-opening calls: known constructors (FileInputStream, etc.)
 *      or factory methods (open, createReadStream, etc.).
 *   2. Get the variable bound to the resource from DFG defs at the open line.
 *   3. Within the enclosing method, look for a close()/dispose() call whose
 *      receiver matches the resource variable.
 *   4a. No close call found → definite leak (high, error).
 *   4b. Close found but no `finally` keyword in the method after the open
 *       → potential leak (medium, warning): an exception skips the close.
 *
 * Note: Java try-with-resources generates no explicit close() in the source;
 * the pass treats the absence of both an explicit close AND a finally as a
 * definite leak.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** Constructors that produce closeable resources. */
const RESOURCE_CTORS: ReadonlySet<string> = new Set([
  // Java IO
  'FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter',
  'BufferedReader', 'BufferedWriter', 'PrintWriter', 'InputStreamReader',
  'OutputStreamWriter', 'RandomAccessFile', 'DataInputStream', 'DataOutputStream',
  'ObjectInputStream', 'ObjectOutputStream', 'ZipInputStream', 'ZipOutputStream',
  'JarInputStream', 'JarOutputStream', 'GZIPInputStream', 'GZIPOutputStream',
  // Java NIO
  'FileChannel',
  // Java Net
  'Socket', 'ServerSocket', 'DatagramSocket',
]);

/** Factory / open methods that return closeable resources. */
const RESOURCE_FACTORY_METHODS: ReadonlySet<string> = new Set([
  // Java NIO/IO
  'openConnection', 'openStream', 'newInputStream', 'newOutputStream',
  'newBufferedReader', 'newBufferedWriter', 'newByteChannel',
  // Python built-in
  'open',
  // Node.js streams
  'createReadStream', 'createWriteStream', 'createConnection',
]);

/** Methods that properly release a resource. */
const CLOSE_METHODS: ReadonlySet<string> = new Set([
  'close', 'dispose', 'shutdown', 'disconnect', 'release', 'destroy', 'free',
  'shutdownNow', 'terminate',
]);

export interface ResourceLeakResult {
  /** Resources that may not be properly closed. */
  leaks: Array<{
    line: number;
    resource: string;
    variable: string;
    kind: 'definite' | 'potential';
  }>;
}

export class ResourceLeakPass implements AnalysisPass<ResourceLeakResult> {
  readonly name = 'resource-leak';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): ResourceLeakResult {
    const { graph, code } = ctx;
    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');

    const leaks: ResourceLeakResult['leaks'] = [];

    for (const call of graph.ir.calls) {
      const name = call.method_name;

      const isConstructor = call.is_constructor === true && RESOURCE_CTORS.has(name);
      const isFactory = !call.is_constructor && RESOURCE_FACTORY_METHODS.has(name);
      if (!isConstructor && !isFactory) continue;

      const openLine = call.location.line;

      // Resource must be captured in a variable to be trackable
      const defs = graph.defsAtLine(openLine);
      if (defs.length === 0) continue;
      const resourceVar = defs[0].variable;

      // Limit search to the enclosing method
      const methodInfo = graph.methodAtLine(openLine);
      if (!methodInfo) continue;
      const methodEnd = methodInfo.method.end_line;

      // Look for a close() call on this resource within the method
      const closeCall = graph.ir.calls.find(
        c =>
          CLOSE_METHODS.has(c.method_name) &&
          c.receiver === resourceVar &&
          c.location.line > openLine &&
          c.location.line <= methodEnd,
      );

      const snippet = (codeLines[openLine - 1] ?? '').trim();

      if (!closeCall) {
        // Also accept try-with-resources or with-statement as implicit close
        if (this.hasTryWithResources(codeLines, openLine, methodEnd)) continue;

        // Definite leak: resource is never explicitly released
        leaks.push({ line: openLine, resource: name, variable: resourceVar, kind: 'definite' });
        ctx.addFinding({
          id: `resource-leak-${file}-${openLine}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-772',
          severity: 'high',
          level: 'error',
          message:
            `Resource leak: \`${name}\` assigned to '${resourceVar}' at line ${openLine} ` +
            `is never closed — file descriptors or connections may be exhausted`,
          file,
          line: openLine,
          snippet,
          fix:
            `Use try-with-resources (Java 7+): \`try (${name} ${resourceVar} = ...) { ... }\`, ` +
            `or call \`${resourceVar}.close()\` in a finally block`,
          evidence: { resource: name, variable: resourceVar },
        });
        continue;
      }

      // Close found — check if it is protected by a finally block
      if (this.hasFinallyBlock(codeLines, openLine, methodEnd)) continue;

      // Potential leak: close() exists but may be skipped on exception
      leaks.push({ line: openLine, resource: name, variable: resourceVar, kind: 'potential' });
      ctx.addFinding({
        id: `resource-leak-${file}-${openLine}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-772',
        severity: 'medium',
        level: 'warning',
        message:
          `Potential resource leak: \`${name}\` ('${resourceVar}') is closed at ` +
          `line ${closeCall.location.line} but not inside a finally block — ` +
          `an exception could skip the close`,
        file,
        line: openLine,
        snippet,
        fix: `Move \`${resourceVar}.close()\` into a finally block, or use try-with-resources`,
        evidence: {
          resource: name,
          variable: resourceVar,
          close_line: closeCall.location.line,
        },
      });
    }

    return { leaks };
  }

  /** True if a `finally` keyword appears in the method body after the open line. */
  private hasFinallyBlock(lines: string[], fromLine: number, toLine: number): boolean {
    for (let l = fromLine; l <= toLine && l <= lines.length; l++) {
      if (/\bfinally\b/.test(lines[l - 1] ?? '')) return true;
    }
    return false;
  }

  /**
   * True if a try-with-resources or Python `with` statement wraps the resource,
   * indicating implicit close. Detects `try (` or `with open(` patterns.
   */
  private hasTryWithResources(lines: string[], fromLine: number, toLine: number): boolean {
    for (let l = fromLine; l <= toLine && l <= lines.length; l++) {
      const text = lines[l - 1] ?? '';
      if (/\btry\s*\(/.test(text) || /\bwith\b.*\bopen\b/.test(text)) return true;
    }
    return false;
  }
}
