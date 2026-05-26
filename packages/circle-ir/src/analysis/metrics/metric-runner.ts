import type { CircleIR, MetricValue } from '../../types/index.js';
import type { MetricPass } from './metric-pass.js';
import { SizeMetricsPass } from './passes/size-metrics-pass.js';
import { ComplexityMetricsPass } from './passes/complexity-metrics-pass.js';
import { HalsteadMetricsPass } from './passes/halstead-metrics-pass.js';
import { DataFlowMetricsPass } from './passes/data-flow-metrics-pass.js';
import { CouplingMetricsPass } from './passes/coupling-metrics-pass.js';
import { InheritanceMetricsPass } from './passes/inheritance-metrics-pass.js';
import { CohesionMetricsPass } from './passes/cohesion-metrics-pass.js';
import { DocumentationMetricsPass } from './passes/documentation-metrics-pass.js';
import { CompositeMetricsPass } from './passes/composite-metrics-pass.js';

/**
 * MetricRunner
 *
 * Orchestrates all MetricPass instances for a single file.  Each pass receives
 * the accumulated results from prior passes so that CompositeMetricsPass (always
 * last) can reference earlier computed values.
 *
 * Usage:
 *   const metrics = new MetricRunner().run(ir, code, language);
 *   ir.metrics = { file: filePath, metrics };
 */
export class MetricRunner {
  private readonly passes: MetricPass[] = [
    new SizeMetricsPass(),
    new ComplexityMetricsPass(),
    new HalsteadMetricsPass(),
    new DataFlowMetricsPass(),
    new CouplingMetricsPass(),
    new InheritanceMetricsPass(),
    new CohesionMetricsPass(),
    new DocumentationMetricsPass(),
    new CompositeMetricsPass(), // MUST be last — reads accumulated
  ];

  /**
   * Run all metric passes on the given IR and source code.
   *
   * @returns Flat array of all MetricValues produced by all passes.
   */
  run(ir: CircleIR, code: string, language: string): MetricValue[] {
    const accumulated: MetricValue[] = [];
    for (const pass of this.passes) {
      const results = pass.run({ ir, code, language, accumulated });
      accumulated.push(...results);
    }
    return accumulated;
  }
}
