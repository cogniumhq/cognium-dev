/**
 * Escapes explained by a resolved taint path.
 *
 * A file analysed on its own cannot see a function defined in another file,
 * so passing a tainted value to one is reported as an `external_taint_escape`
 * at the call: the value leaves the code the analysis can see. In a project
 * scan the cross-file phase may follow the same value through that call to a
 * real sink in the other file:
 *
 *   main.go      6  target := r.URL.Query().Get("next")
 *                7  redirectTo(w, r, target)          ← escape (per file)
 *   redirect.go  6  http.Redirect(w, r, target, 302)  ← open redirect (path)
 *
 * The escape at line 7 then tells the same defect a second time, less
 * precisely. After the cross-file phase, an escape is dropped (its per-file
 * flow, its sink when no flow into it is left, and any cross-file path that
 * ends in it) when a resolved path to a sink of another type starts at the
 * same source (file and line) and hands the value to another file at the
 * escape's line. An escape with no such path keeps its meaning — the value
 * left the analysed code here — and is kept, and so is an escape on the
 * source's own line when the path leaves the file later.
 */

import type { CircleIR, TaintPath } from '../types/index.js';

const ESCAPE = 'external_taint_escape';

const key = (sourceFile: string, sourceLine: number, file: string, line: number): string =>
  `${sourceFile}:${sourceLine}|${file}:${line}`;

/**
 * Drop the escapes that a resolved path explains. Per-file flows and sinks are
 * changed in place; the kept taint paths are returned.
 */
export function dropEscapesExplainedByTaintPaths(
  fileAnalyses: ReadonlyArray<{ file: string; analysis: CircleIR }>,
  taintPaths: TaintPath[],
): TaintPath[] {
  // Every (source, line) where a resolved non-escape path hands the value to
  // another file: a hop whose next hop (or, for the last hop, the sink) is in
  // a different file.
  const explained = new Set<string>();
  for (const p of taintPaths) {
    if (!p.path_exists || p.sink.type === ESCAPE) continue;
    const hops = p.hops;
    for (let i = 0; i < hops.length; i++) {
      const h = hops[i];
      const nextFile = i + 1 < hops.length ? hops[i + 1].file : p.sink.file;
      if (nextFile !== h.file) explained.add(key(p.source.file, p.source.line, h.file, h.line));
    }
  }
  if (explained.size === 0) return taintPaths;

  for (const fa of fileAnalyses) {
    const taint = fa.analysis.taint;
    const flows = taint.flows ?? [];
    if (!flows.some(f => f.sink_type === ESCAPE)) continue;
    const dropped = new Set<number>();
    for (let i = flows.length - 1; i >= 0; i--) {
      const f = flows[i];
      if (f.sink_type !== ESCAPE) continue;
      if (!explained.has(key(f.source_file ?? fa.file, f.source_line, fa.file, f.sink_line))) continue;
      flows.splice(i, 1);
      dropped.add(f.sink_line);
    }
    if (dropped.size === 0) continue;
    // A sink is kept while a flow from another source still reaches it.
    const reached = new Set(flows.filter(f => f.sink_type === ESCAPE).map(f => f.sink_line));
    const sinks = taint.sinks;
    for (let i = sinks.length - 1; i >= 0; i--) {
      const s = sinks[i];
      if (s.type === ESCAPE && dropped.has(s.line) && !reached.has(s.line)) sinks.splice(i, 1);
    }
  }

  return taintPaths.filter(p =>
    p.sink.type !== ESCAPE
    || !explained.has(key(p.source.file, p.source.line, p.sink.file, p.sink.line)));
}
