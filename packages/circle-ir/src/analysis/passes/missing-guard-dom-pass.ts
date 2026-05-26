/**
 * Pass: missing-guard-dom (#53, CWE-285)
 *
 * @deprecated NOT REGISTERED IN THE DEFAULT PIPELINE
 *
 * This pass was removed from the default AnalysisPipeline in v3.14.0 because
 * its hardcoded auth-method list (12 names) produces high-severity false
 * positives in any codebase that uses framework-level authorization (Spring
 * Security annotations, filter chains, middleware) — those guards never appear
 * as intra-method call nodes in the CFG, so every sensitive operation looks
 * unguarded.
 *
 * The raw signals this pass relies on are already present in CircleIR:
 *   • ir.calls  — all call sites with method_name; filter AUTH_METHODS /
 *                 SENSITIVE_METHODS to identify candidates.
 *   • ir.cfg    — full CFG (blocks + edges); build DominatorGraph from it.
 *
 * This file is retained so that circle-ir-ai can reconstruct the dominator
 * analysis on top of LLM-identified auth guards (which correctly handle
 * annotations, middleware, and framework-specific patterns).
 *
 * Detects sensitive operations that are not dominated by an authentication
 * or authorization check on all control-flow paths within the same method.
 *
 * Detection strategy:
 *   1. Identify calls to known authentication methods and sensitive operations.
 *   2. Build a DominatorGraph from the file-level CFG.
 *   3. For each sensitive operation, find the CFG block containing it and check
 *      whether any auth-check block in the same method dominates that block.
 *   4. If no auth-check block dominates the sensitive-op block → emit finding.
 *
 * Language: Java only (other languages handled differently or not yet).
 * Dedup: at most one finding per method.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import { DominatorGraph } from '../../graph/dominator-graph.js';

const AUTH_METHODS: ReadonlySet<string> = new Set([
  'authenticate', 'isAuthenticated', 'isAuthorized', 'isAdmin',
  'checkAuth', 'hasPermission', 'requiresAuth', 'verifyToken',
  'validateToken', 'checkRole', 'authorize', 'isLoggedIn',
]);

const SENSITIVE_METHODS: ReadonlySet<string> = new Set([
  'delete', 'deleteById', 'drop', 'truncate', 'executeUpdate',
  'createUser', 'createAdmin', 'modifyPermission', 'grantRole',
  'setAdmin', 'elevatePrivilege',
]);

export interface MissingGuardDomResult {
  findings: number;
}

export class MissingGuardDomPass implements AnalysisPass<MissingGuardDomResult> {
  readonly name = 'missing-guard-dom';
  readonly category = 'security' as const;

  run(ctx: PassContext): MissingGuardDomResult {
    const { graph, language } = ctx;

    if (language !== 'java') return { findings: 0 };

    const { cfg, calls } = graph.ir;
    if (cfg.blocks.length === 0 || cfg.edges.length === 0) return { findings: 0 };

    const dom = new DominatorGraph(cfg);
    const file = graph.ir.meta.file;

    // Collect auth-check and sensitive-op call lines from the IR
    const authCallLines: number[] = [];
    const sensitiveOps: Array<{ line: number; method: string }> = [];

    for (const call of calls) {
      if (AUTH_METHODS.has(call.method_name)) {
        authCallLines.push(call.location.line);
      }
      if (SENSITIVE_METHODS.has(call.method_name)) {
        sensitiveOps.push({ line: call.location.line, method: call.method_name });
      }
    }

    if (sensitiveOps.length === 0) return { findings: 0 };

    // Helper: find the CFG block whose [start_line, end_line] contains a given line
    const blockContainingLine = (line: number) =>
      cfg.blocks.find(b => b.start_line <= line && line <= b.end_line) ?? null;

    // Emit at most one finding per method to avoid noise
    const reportedMethods = new Set<string>();
    let count = 0;

    for (const op of sensitiveOps) {
      const opBlock = blockContainingLine(op.line);
      if (!opBlock) continue;

      const methodInfo = graph.methodAtLine(op.line);
      if (!methodInfo) continue;

      const methodKey = `${methodInfo.type.name}::${methodInfo.method.name}`;
      if (reportedMethods.has(methodKey)) continue;

      const { start_line, end_line } = methodInfo.method;

      // Restrict auth checks to those inside the same method
      const authInMethod = authCallLines.filter(l => l >= start_line && l <= end_line);

      // Check whether any auth-check block dominates the sensitive-op block
      const dominated = authInMethod.some(authLine => {
        const authBlock = blockContainingLine(authLine);
        return authBlock !== null && dom.dominates(authBlock.id, opBlock.id);
      });

      if (!dominated) {
        reportedMethods.add(methodKey);
        count++;
        ctx.addFinding({
          id: `missing-guard-dom-${file}-${op.line}`,
          pass: this.name,
          category: this.category,
          rule_id: 'missing-guard-dom',
          cwe: 'CWE-285',
          severity: 'high',
          level: 'error',
          message:
            `Sensitive operation \`${op.method}()\` at line ${op.line} is not dominated ` +
            `by an authentication check`,
          file,
          line: op.line,
          fix: `Add authentication/authorization check on all paths leading to line ${op.line}`,
          evidence: { method: op.method },
        });
      }
    }

    return { findings: count };
  }
}
