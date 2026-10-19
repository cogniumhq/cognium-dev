/**
 * cognium-dev#684 — mirror resolved cross-file taint paths onto the sink
 * file's per-file `taint.flows` so project scans expose the same types in the
 * per-file vulnerability list that `cross_file_taint_paths` already carries.
 */
import type { TaintFlowInfo, TaintFlowStep, TaintPath } from '../types/index.js';

type FileTaint = { file: string; analysis: { taint: { flows?: TaintFlowInfo[] } } };

export function promoteCrossFilePathsToSinkFlows(
  fileAnalyses: FileTaint[],
  taintPaths: TaintPath[],
): void {
  for (const tp of taintPaths) {
    if (!tp.path_exists || tp.source.file === tp.sink.file) continue;

    const fa = fileAnalyses.find(f => f.file === tp.sink.file);
    if (!fa) continue;

    const flows = fa.analysis.taint.flows ?? [];
    const exists = flows.some(
      f =>
        f.sink_line === tp.sink.line
        && f.sink_type === tp.sink.type
        && f.source_line === tp.source.line
        && f.source_type === tp.source.type,
    );
    if (exists) continue;

    const path: TaintFlowStep[] = tp.hops.map((h, i) => ({
      variable: h.variable,
      line: h.line,
      type: i === 0 ? 'source' : i === tp.hops.length - 1 ? 'sink' : 'use',
    }));

    flows.push({
      source_line: tp.source.line,
      sink_line: tp.sink.line,
      source_type: tp.source.type,
      sink_type: tp.sink.type,
      path,
      confidence: tp.confidence,
      sanitized: false,
    });
    fa.analysis.taint.flows = flows;
  }
}
