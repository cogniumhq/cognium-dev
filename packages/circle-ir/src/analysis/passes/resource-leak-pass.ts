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
import type { CallInfo, MethodInfo, TypeInfo } from '../../types/index.js';

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

/**
 * #226 — Closeable wrapper constructors that document ownership transfer
 * of their underlying stream/reader. When the underlying resource is passed
 * as a constructor argument to one of these wrappers, closing the wrapper
 * cascades to the inner stream (per JDK javadoc), so no leak exists.
 * Reference: java.io + java.util.zip standard wrappers.
 */
const WRAPPER_CTORS: ReadonlySet<string> = new Set([
  // java.io wrappers
  'BufferedInputStream', 'BufferedOutputStream', 'BufferedReader', 'BufferedWriter',
  'InputStreamReader', 'OutputStreamWriter', 'DataInputStream', 'DataOutputStream',
  'PrintStream', 'PrintWriter', 'LineNumberReader', 'PushbackInputStream',
  'PushbackReader', 'SequenceInputStream',
  // java.util.zip wrappers
  'GZIPInputStream', 'GZIPOutputStream', 'ZipInputStream', 'ZipOutputStream',
  'InflaterInputStream', 'DeflaterOutputStream', 'CheckedInputStream',
  'CheckedOutputStream',
]);

/**
 * #227 — Anonymous-class / functional-interface literal method names that
 * commonly hold long-lived resources handed off from an outer scope. When a
 * resource-field is closed inside one of these literals, ownership has been
 * transferred to the worker and the outer method should not be flagged.
 */
const WORKER_METHODS: ReadonlySet<string> = new Set([
  'run',    // Runnable, Thread
  'call',   // Callable
  'accept', // Consumer
  'get',    // Supplier
  'apply',  // Function
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

      // #226 — suppression 4: resource is immediately passed as a
      // constructor argument to a known Closeable wrapper (e.g.
      // `new GZIPInputStream(fis)`, `new BufferedReader(new
      // InputStreamReader(is))`). Per JDK javadoc, closing the
      // wrapper cascades to the underlying stream, so ownership
      // transfers to the wrapper and the inner reference is released
      // through the outer chain.
      if (this.isWrappedByCloseableCtor(
        graph.ir.calls, resourceVar, openLine, methodEnd,
      )) {
        continue;
      }

      // #227 — suppression 5: resource is stored to a class field
      // AND that field is referenced with a close() call inside a
      // worker literal (Runnable#run / Callable#call / etc.) declared
      // in the same method. Idiomatic Java concurrency: outer method
      // opens the resource, executor thread closes it in cleanup.
      if (this.isClosedInNestedWorker(
        graph, codeLines, resourceVar, methodInfo, openLine, methodEnd,
      )) {
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

  /**
   * #226 — true if `variable` is passed as a constructor argument to a
   * known Closeable wrapper call within the enclosing method's line
   * range. Ownership of the inner stream transfers to the wrapper.
   *
   * The check is deliberately per-method: cross-method wrapping does
   * not apply because the inner reference has already escaped the
   * scope by then.
   */
  private isWrappedByCloseableCtor(
    calls: readonly CallInfo[],
    variable: string,
    fromLine: number,
    toLine: number,
  ): boolean {
    // WRAPPER_CTORS names are PascalCase JDK class names — safe to
    // match regardless of `is_constructor` (Java tree-sitter often
    // omits the flag).
    for (const call of calls) {
      if (!WRAPPER_CTORS.has(call.method_name)) continue;
      if (call.location.line < fromLine || call.location.line > toLine) continue;
      for (const arg of call.arguments) {
        if (arg.variable === variable) return true;
      }
    }
    return false;
  }

  /**
   * #227 — true if `variable` refers to a field of the enclosing class
   * that is closed inside a worker-literal method (Runnable#run,
   * Callable#call, Consumer#accept, ...) declared in the same enclosing
   * method. Ownership transfers to the executor thread.
   *
   * The heuristic is intentionally conservative: it requires both
   *  (a) the resource variable to match a declared field name on the
   *      enclosing class (so a stray local named `selector` cannot
   *      accidentally opt in to the suppression), AND
   *  (b) a `<field>.close()` (or CLOSE_METHODS) call to appear on a
   *      line inside a method whose name is one of WORKER_METHODS and
   *      whose start_line is strictly within the enclosing method's
   *      body (nested literal indicator).
   */
  private isClosedInNestedWorker(
    graph: CodeGraph,
    lines: string[],
    variable: string,
    methodInfo: { method: MethodInfo; type: TypeInfo },
    fromLine: number,
    toLine: number,
  ): boolean {
    // (a) resource variable must match a declared field of the class,
    // or be text-assigned to a field within the outer method.
    const fieldNames = new Set(methodInfo.type.fields.map(f => f.name));
    let candidateField: string | null = null;
    if (fieldNames.has(variable)) {
      candidateField = variable;
    } else {
      // Fallback: `this.<field> = variable` or `<field> = variable`
      // where <field> is a declared field.
      const thisAssignRe = new RegExp(
        `(?:\\bthis\\s*\\.\\s*)?(\\w+)\\s*=\\s*${escapeRegex(variable)}\\b`,
      );
      for (let l = fromLine; l <= toLine && l <= lines.length; l++) {
        const m = thisAssignRe.exec(lines[l - 1] ?? '');
        if (m && fieldNames.has(m[1])) {
          candidateField = m[1];
          break;
        }
      }
    }
    if (!candidateField) return false;

    // (b) find a close-style call on the candidate field whose line
    // falls inside a WORKER_METHODS method nested in the enclosing
    // method's body.
    for (const call of graph.ir.calls) {
      if (call.receiver !== candidateField) continue;
      if (!CLOSE_METHODS.has(call.method_name)) continue;
      const closeLine = call.location.line;
      if (closeLine < fromLine || closeLine > toLine) continue;
      const enclosing = graph.methodAtLine(closeLine);
      if (!enclosing) continue;
      // Same outer method — not nested.
      if (enclosing.method === methodInfo.method) continue;
      if (!WORKER_METHODS.has(enclosing.method.name)) continue;
      // Nested worker start must lie inside the outer method body.
      if (
        enclosing.method.start_line > fromLine &&
        enclosing.method.start_line <= toLine
      ) {
        return true;
      }
    }
    return false;
  }
}
