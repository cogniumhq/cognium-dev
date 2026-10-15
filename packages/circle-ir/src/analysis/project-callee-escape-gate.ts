/**
 * Project-callee escape gate (cognium-dev#637, C#).
 *
 * A file analysed on its own cannot see a method defined in another file, so
 * a tainted argument passed to it is reported as an `external_taint_escape`
 * (data handed to an unknown method). Inside `analyzeProject` the callee is
 * known: the call is project code, not data leaving the program, and whether
 * the value reaches a sink is decided by the cross-file phase and its callee
 * reach check. With both classes in one file the same call reports nothing,
 * so this step makes the project result agree with it.
 *
 * Runs after the per-file analyses and before the cross-file phase, so no
 * cross-file path is built from the dropped sink. A sink is dropped only when
 * every call at its line to that method name resolves exactly to a method
 * declared in a different project file; an unresolved, inferred or
 * polymorphic call keeps the escape.
 */

import type { CircleIR } from '../types/index.js';
import type { ProjectGraph } from '../graph/project-graph.js';

const ESCAPE = 'external_taint_escape';

export function dropEscapesToProjectCallees(
  fileAnalyses: ReadonlyArray<{ file: string; analysis: CircleIR }>,
  projectGraph: ProjectGraph,
): void {
  const resolver = projectGraph.resolver;
  for (const fa of fileAnalyses) {
    const ir = fa.analysis;
    if (ir.meta.language !== 'csharp') continue;
    const sinks = ir.taint?.sinks ?? [];
    if (!sinks.some(s => s.type === ESCAPE)) continue;

    const dropped = new Set<number>();
    for (const sink of sinks) {
      if (sink.type !== ESCAPE || !sink.method) continue;
      const calls = ir.calls.filter(c => c.location.line === sink.line && c.method_name === sink.method);
      if (calls.length === 0) continue;
      const projectCall = calls.every(call => {
        const r = resolver.resolveCall(call, fa.file);
        return !!r && r.resolution === 'exact' && r.targetFile !== fa.file;
      });
      if (projectCall) dropped.add(sink.line);
    }
    if (dropped.size === 0) continue;

    const isDropped = (type: string, line: number): boolean => type === ESCAPE && dropped.has(line);
    // In place: the project graph holds the same arrays.
    for (let i = sinks.length - 1; i >= 0; i--) {
      if (isDropped(sinks[i].type, sinks[i].line)) sinks.splice(i, 1);
    }
    const flows = ir.taint.flows ?? [];
    for (let i = flows.length - 1; i >= 0; i--) {
      if (isDropped(flows[i].sink_type, flows[i].sink_line)) flows.splice(i, 1);
    }
  }
}
