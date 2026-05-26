/**
 * Pass: cleanup-verify (#54, CWE-772)
 *
 * Detects resources that have a close() call but that close() does not
 * post-dominate the acquisition point — meaning some control-flow paths
 * skip the cleanup entirely.
 *
 * Detection strategy:
 *   1. Find resource-opening calls (same set as ResourceLeakPass).
 *   2. Locate the corresponding close() call within the enclosing method.
 *   3. Build a post-dominator graph by reversing all CFG edges and computing
 *      a DominatorGraph from the exit block.
 *   4. If close() block does NOT post-dominate the open block → emit finding.
 *
 * Languages: Java, Python, JavaScript/TypeScript.
 * Skips: Rust (RAII guarantees cleanup), Bash.
 *
 * Note: complements ResourceLeakPass, which handles the no-close() case.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import { DominatorGraph } from '../../graph/dominator-graph.js';
import type { CFG } from '../../types/index.js';

/** Resource-opening constructors (same set as ResourceLeakPass). */
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

/**
 * Build a post-dominator graph by reversing all CFG edges and running
 * the dominator algorithm from the exit block.
 * `postDom.dominates(A, B)` means "A post-dominates B in the original CFG".
 */
function buildPostDomGraph(cfg: CFG): DominatorGraph {
  const exitBlock =
    cfg.blocks.find(b => b.type === 'exit') ??
    cfg.blocks.find(b => !cfg.edges.some(e => e.from === b.id));

  if (!exitBlock || cfg.blocks.length === 0) {
    return new DominatorGraph({ blocks: [], edges: [] });
  }

  const reversed: CFG = {
    blocks: cfg.blocks,
    edges: cfg.edges.map(e => ({ from: e.to, to: e.from, type: e.type })),
  };

  return new DominatorGraph(reversed, exitBlock.id);
}

export interface CleanupVerifyResult {
  findings: number;
}

export class CleanupVerifyPass implements AnalysisPass<CleanupVerifyResult> {
  readonly name = 'cleanup-verify';
  readonly category = 'reliability' as const;

  run(ctx: PassContext): CleanupVerifyResult {
    const { graph, language } = ctx;

    // Rust RAII guarantees cleanup; Bash has no structured resource model
    if (language === 'rust' || language === 'bash') return { findings: 0 };

    const { cfg, calls } = graph.ir;
    const file = graph.ir.meta.file;

    if (cfg.blocks.length === 0) return { findings: 0 };

    const postDom = buildPostDomGraph(cfg);

    const blockContainingLine = (line: number) =>
      cfg.blocks.find(b => b.start_line <= line && line <= b.end_line) ?? null;

    let count = 0;

    for (const call of calls) {
      const name = call.method_name;
      const isConstructor = call.is_constructor === true && RESOURCE_CTORS.has(name);
      const isFactory = !call.is_constructor && RESOURCE_FACTORY_METHODS.has(name);
      if (!isConstructor && !isFactory) continue;

      const openLine = call.location.line;

      // Resource must be captured in a variable to be trackable
      const defs = graph.defsAtLine(openLine);
      if (defs.length === 0) continue;
      const resourceVar = defs[0].variable;

      const methodInfo = graph.methodAtLine(openLine);
      if (!methodInfo) continue;
      const methodEnd = methodInfo.method.end_line;

      // Find the first close() call for this resource within the enclosing method
      const closeCall = calls.find(
        c =>
          CLOSE_METHODS.has(c.method_name) &&
          c.receiver === resourceVar &&
          c.location.line > openLine &&
          c.location.line <= methodEnd,
      );

      // ResourceLeakPass handles the no-close() case; we only care about
      // close() calls that may be skipped on some paths
      if (!closeCall) continue;

      const openBlock  = blockContainingLine(openLine);
      const closeBlock = blockContainingLine(closeCall.location.line);
      if (!openBlock || !closeBlock) continue;

      // If close post-dominates open, cleanup is guaranteed on every exit path
      if (postDom.dominates(closeBlock.id, openBlock.id)) continue;

      count++;
      ctx.addFinding({
        id: `cleanup-verify-${file}-${openLine}`,
        pass: this.name,
        category: this.category,
        rule_id: 'cleanup-verify',
        cwe: 'CWE-772',
        severity: 'medium',
        level: 'warning',
        message:
          `Resource \`${resourceVar}\` opened at line ${openLine} may not close on all ` +
          `paths — close() at line ${closeCall.location.line} does not post-dominate ` +
          `the acquisition`,
        file,
        line: openLine,
        fix: 'Use try-with-resources (Java) or a finally block to guarantee cleanup on all paths',
        evidence: {
          resource: name,
          variable: resourceVar,
          close_line: closeCall.location.line,
        },
      });
    }

    return { findings: count };
  }
}
