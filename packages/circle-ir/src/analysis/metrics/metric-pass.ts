import type { CircleIR, MetricValue } from '../../types/index.js';

/**
 * Context passed to each MetricPass during a MetricRunner execution.
 *
 * `accumulated` contains MetricValues emitted by all passes run before this
 * one in the pipeline — CompositeMetricsPass (always last) uses this to read
 * earlier metrics without re-computing them.
 */
export interface MetricContext {
  ir: CircleIR;
  /** Full source text of the file being analyzed. */
  code: string;
  language: string;
  /** Results from all prior passes, in emission order. */
  accumulated: MetricValue[];
}

/**
 * A single metric computation unit.
 *
 * Each pass returns zero or more MetricValues.  Passes must not mutate
 * `ctx.accumulated`; the MetricRunner appends returned values to it between
 * passes.
 */
export interface MetricPass {
  readonly name: string;
  run(ctx: MetricContext): MetricValue[];
}
