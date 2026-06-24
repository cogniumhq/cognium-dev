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
import type { CodeGraph } from '../../graph/code-graph.js';
import type { MethodInfo, TypeInfo } from '../../types/index.js';

/** Escape a string so it can be safely embedded in a `new RegExp(...)` literal. */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Factory-shape method-name prefixes that conventionally transfer
 * resource ownership to the caller (e.g. `openInputStream`,
 * `createReader`, `newSession`, `getInputStream`, `makeConnection`,
 * `buildClient`). Combined with a non-void return type. (#158) */
const FACTORY_METHOD_NAME_RE =
  /^(?:open|create|new|get|make|build)[A-Z]/;

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
      const methodStart = methodInfo.method.start_line;
      const methodEnd = methodInfo.method.end_line;

      // #158 — suppression 1: resource is returned to the caller.
      // Caller owns the resource (typically via try-with-resources).
      // Text-scan method lines for `return ...<resourceVar>...` —
      // cheap, conservative, false-positive-bias preserved.
      if (this.isReturnedToCaller(codeLines, resourceVar, methodStart, methodEnd)) {
        continue;
      }

      // #158 — suppression 2: resource is stored to an instance field
      // AND the enclosing class declares a method that closes the
      // field (`<field>.close()` / `release()` / etc.). Both conditions
      // required (conservative-bias).
      const fieldName = this.fieldStoredName(codeLines, resourceVar, openLine, methodEnd);
      if (fieldName && this.classHasCloseMethodFor(graph, fieldName, methodInfo.type)) {
        continue;
      }

      // #158 — suppression 3: enclosing method has a factory-shape
      // name + non-void return type. Empirical: openFoo/createBar/
      // getBaz returning a resource transfers ownership to caller.
      if (this.isFactoryMethod(methodInfo.method)) {
        continue;
      }

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

  /**
   * #158 — true if `variable` appears in a `return ...` expression within
   * the enclosing method's line range. Returning the handle transfers
   * ownership to the caller (caller is responsible for close).
   */
  private isReturnedToCaller(
    lines: string[],
    variable: string,
    fromLine: number,
    toLine: number,
  ): boolean {
    const varRe = new RegExp(`\\breturn\\b[^;]*\\b${escapeRegex(variable)}\\b`);
    for (let l = fromLine; l <= toLine && l <= lines.length; l++) {
      if (varRe.test(lines[l - 1] ?? '')) return true;
    }
    return false;
  }

  /**
   * #158 — if `variable` is assigned to `this.<field>` within the
   * enclosing method (scanning from the open line to method end),
   * returns the field name; otherwise null.
   */
  private fieldStoredName(
    lines: string[],
    variable: string,
    openLine: number,
    toLine: number,
  ): string | null {
    const thisAssignRe = new RegExp(
      `\\bthis\\s*\\.\\s*(\\w+)\\s*=\\s*${escapeRegex(variable)}\\b`,
    );
    for (let l = openLine; l <= toLine && l <= lines.length; l++) {
      const m = thisAssignRe.exec(lines[l - 1] ?? '');
      if (m) return m[1];
    }
    return null;
  }

  /**
   * #158 — true if the enclosing class declares any call of the form
   * `<fieldName>.<closeMethod>(...)` where closeMethod is in
   * CLOSE_METHODS. Indicates a paired close method (e.g. `closeDriver`)
   * exists on the same class, so the field-stored resource is
   * eventually released.
   */
  private classHasCloseMethodFor(
    graph: CodeGraph,
    fieldName: string,
    type: TypeInfo,
  ): boolean {
    for (const c of graph.ir.calls) {
      if (c.location.line < type.start_line || c.location.line > type.end_line) continue;
      if (c.receiver !== fieldName) continue;
      if (CLOSE_METHODS.has(c.method_name)) return true;
    }
    return false;
  }

  /**
   * #158 — true if the enclosing method's name matches a factory-shape
   * prefix (`open` / `create` / `new` / `get` / `make` / `build` followed
   * by a capital letter) AND its return type is non-void / non-null.
   * Both conditions required: methods named `process()` or
   * `void openFoo()` continue to fire.
   */
  private isFactoryMethod(method: MethodInfo): boolean {
    if (!method.return_type || method.return_type === 'void') return false;
    return FACTORY_METHOD_NAME_RE.test(method.name);
  }
}
