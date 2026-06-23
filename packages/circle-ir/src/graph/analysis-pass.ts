/**
 * Analysis Pass Interface
 *
 * Defines the contract for modular analysis passes that operate on a CodeGraph.
 * Passes are run sequentially by AnalysisPipeline; each pass reads prior results
 * via context.getResult() and returns a typed result stored under its name.
 */

import type { TaintConfig } from '../types/config.js';
import type { PassCategory, SastFinding } from '../types/index.js';
import type { CodeGraph } from './code-graph.js';

/**
 * Context passed to every pass during pipeline execution.
 * Provides shared inputs and access to results from previously-run passes.
 */
export interface PassContext {
  /** The shared graph built once before the pipeline runs. */
  readonly graph: CodeGraph;
  /** Raw source code text. */
  readonly code: string;
  /** Language identifier (java, python, javascript, etc.). */
  readonly language: string;
  /** Merged taint configuration (sources + sinks patterns). */
  readonly config: TaintConfig;

  /**
   * Retrieve the result of a previously-run pass.
   * Throws if the pass has not run yet — check pass ordering.
   */
  getResult<T>(passName: string): T;

  /** Returns true if the named pass has already produced a result. */
  hasResult(passName: string): boolean;

  /**
   * Emit a SAST finding from this pass.
   * Findings are collected by the pipeline and returned alongside results.
   */
  addFinding(finding: SastFinding): void;

  /**
   * Read findings emitted by previously-run passes in this pipeline run.
   * Used by dedup-aware passes (e.g. ScanSecretsPass) to avoid double-reporting
   * the same `(file, line, rule_id)` already covered by an earlier pass.
   *
   * Optional: only the real pipeline implementation provides this. Test
   * harnesses that construct a `PassContext` literal may omit it; passes that
   * read it must treat `undefined` as "no prior findings".
   */
  getFindings?(): readonly SastFinding[];
}

/**
 * An analysis pass over a CodeGraph.
 * Each pass has a unique name and category used to key its result in the
 * pipeline and group findings by ISO 25010 quality characteristic.
 */
export interface AnalysisPass<TResult = unknown> {
  readonly name: string;
  /** ISO 25010 / SonarQube category for findings emitted by this pass. */
  readonly category: PassCategory;
  run(context: PassContext): TResult;
}

/** Return value of AnalysisPipeline.run(). */
export interface PipelineRunResult {
  /** Keyed pass results (same semantics as the previous Map return). */
  results: Map<string, unknown>;
  /** All SastFindings emitted via context.addFinding() across all passes. */
  findings: SastFinding[];
}

/**
 * Runs a sequence of AnalysisPasses, threading context between them.
 *
 * Usage:
 *   const { results, findings } = new AnalysisPipeline()
 *     .add(new TaintMatcherPass(config))
 *     .add(new ConstantPropagationPass(tree))
 *     .run(graph, code, language, config);
 */
export class AnalysisPipeline {
  private readonly passes: AnalysisPass[] = [];

  add<T>(pass: AnalysisPass<T>): this {
    this.passes.push(pass);
    return this;
  }

  run(
    graph: CodeGraph,
    code: string,
    language: string,
    config: TaintConfig,
  ): PipelineRunResult {
    const results = new Map<string, unknown>();
    const findings: SastFinding[] = [];

    const context: PassContext = {
      graph,
      code,
      language,
      config,
      getResult<T>(passName: string): T {
        if (!results.has(passName)) {
          throw new Error(
            `Pass '${passName}' result not available. Check pass ordering.`,
          );
        }
        return results.get(passName) as T;
      },
      hasResult(passName: string): boolean {
        return results.has(passName);
      },
      addFinding(finding: SastFinding): void {
        findings.push(finding);
      },
      getFindings(): readonly SastFinding[] {
        return findings;
      },
    };

    // Diagnostic: per-pass timing. Enabled when
    // (globalThis as any).__circleIrPassTiming === true. Emits to console.error
    // — browser-safe (no `process` access). Used by #141 investigation.
    const timingEnabled =
      (globalThis as { __circleIrPassTiming?: boolean }).__circleIrPassTiming === true;

    for (const pass of this.passes) {
      if (timingEnabled) {
        // eslint-disable-next-line no-console
        console.error(`[pass-start] ${pass.name} file=${graph.ir.meta.file}`);
      }
      const t0 = timingEnabled ? Date.now() : 0;
      const result = pass.run(context);
      if (timingEnabled) {
        const dt = Date.now() - t0;
        // eslint-disable-next-line no-console
        console.error(`[pass-timing] ${pass.name} ${dt}ms file=${graph.ir.meta.file}`);
      }
      results.set(pass.name, result);
    }

    return { results, findings };
  }
}
