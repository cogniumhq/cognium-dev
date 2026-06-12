/**
 * CrossFilePass
 *
 * Project-level pass that uses the CrossFileResolver to surface taint flows
 * that cross file boundaries and to map resolved inter-file calls.
 *
 * Unlike the single-file AnalysisPass instances, CrossFilePass operates across
 * the full set of files in a ProjectGraph and is invoked once after all
 * per-file analyses are complete.
 *
 * Depends on: ProjectGraph (with all files registered)
 */

import type {
  CrossFileCall,
  TaintPath,
  TypeHierarchy,
  SourceType,
  SinkType,
} from '../../types/index.js';
import type { ProjectGraph } from '../../graph/project-graph.js';

export interface CrossFilePassResult {
  /** Inter-file method calls (source file → target file). */
  crossFileCalls: CrossFileCall[];
  /** Taint paths that cross file boundaries. */
  taintPaths: TaintPath[];
  /** Type hierarchy across all files. */
  typeHierarchy: TypeHierarchy;
}

export class CrossFilePass {
  run(
    projectGraph: ProjectGraph,
    /** Raw source lines per file (used to populate `code` fields in paths). */
    sourceLines: Map<string, string[]>,
  ): CrossFilePassResult {
    const resolver = projectGraph.resolver;

    // --- 1. Cross-file taint flows → TaintPath[] ----------------------------
    const flows = resolver.findCrossFileTaintFlows();
    const taintPaths: TaintPath[] = flows.flatMap((flow, idx) => {
      const srcLines = sourceLines.get(flow.sourceFile) ?? [];
      const tgtLines = sourceLines.get(flow.targetFile) ?? [];

      // Look up matched sink from the target file's IR to get type + cwe.
      // Skip flows where no known sink exists at the target line — we never
      // default to 'sql_injection' because that produces massive false positives
      // for any TypeScript project that uses string manipulation helpers.
      const targetIR  = projectGraph.getIR(flow.targetFile);
      if (!targetIR || targetIR.taint.sinks.length === 0) return [];

      const matchedSink = targetIR.taint.sinks.find(s => s.line === flow.targetLine);
      if (!matchedSink) return [];

      return [{
        id: `cf-${idx}`,
        source: {
          file: flow.sourceFile,
          line: flow.sourceLine,
          type: flow.sourceType as SourceType,
          code: srcLines[flow.sourceLine - 1] ?? '',
        },
        sink: {
          file: flow.targetFile,
          line: flow.targetLine,
          type: matchedSink.type as SinkType,
          cwe:  matchedSink.cwe,
          code: tgtLines[flow.targetLine - 1] ?? '',
        },
        hops: [
          {
            file:     flow.sourceFile,
            method:   '',
            line:     flow.sourceLine,
            code:     srcLines[flow.sourceLine - 1] ?? '',
            variable: '',
          },
          {
            file:     flow.targetFile,
            method:   flow.targetMethod,
            line:     flow.targetLine,
            code:     tgtLines[flow.targetLine - 1] ?? '',
            variable: '',
          },
        ],
        sanitizers_in_path: [],
        path_exists: true,
        confidence: 0.7,
      }];
    });

    // --- 1b. Inter-procedural multi-hop taint chains -----------------------
    // Source in callee A → caller-side wrapper-return → caller-side sink-call
    // → sink in callee B.  These are flows that `findCrossFileTaintFlows()`
    // can't see because no single file has both source and sink.
    const ipPaths = resolver.findInterproceduralTaintPaths();
    for (let i = 0; i < ipPaths.length; i++) {
      const p = ipPaths[i];
      const sinkIR = projectGraph.getIR(p.sink.file);
      if (!sinkIR) continue;
      const matchedSink = sinkIR.taint.sinks.find(s => s.line === p.sink.line);
      if (!matchedSink) continue;

      const srcLines = sourceLines.get(p.source.file) ?? [];
      const tgtLines = sourceLines.get(p.sink.file)   ?? [];

      // Dedup against any direct cross-file taint already emitted at the same
      // source/sink coordinates.
      const dupId = `${p.source.file}:${p.source.line}→${p.sink.file}:${p.sink.line}`;
      if (taintPaths.some(tp =>
        tp.source.file === p.source.file && tp.source.line === p.source.line &&
        tp.sink.file   === p.sink.file   && tp.sink.line   === p.sink.line)) {
        continue;
      }

      taintPaths.push({
        id: `cf-ip-${i}-${dupId}`,
        source: {
          file: p.source.file,
          line: p.source.line,
          type: p.source.type as SourceType,
          code: srcLines[p.source.line - 1] ?? '',
        },
        sink: {
          file: p.sink.file,
          line: p.sink.line,
          type: matchedSink.type as SinkType,
          cwe:  matchedSink.cwe,
          code: tgtLines[p.sink.line - 1] ?? '',
        },
        hops: p.hops.map(h => ({
          file:     h.file,
          method:   h.method,
          line:     h.line,
          code:     (sourceLines.get(h.file) ?? [])[h.line - 1] ?? '',
          variable: '',
        })),
        sanitizers_in_path: [],
        path_exists: true,
        confidence: p.confidence,
      });
    }

    // --- 2. Resolved inter-file calls → CrossFileCall[] --------------------
    // `args_mapping[].taint_propagates` is populated from the callee's
    // `taintedParams` summary so callers can see at a glance which args of
    // a cross-file call lead to a downstream sink.
    const crossFileCalls: CrossFileCall[] = [];
    for (const filePath of projectGraph.filePaths) {
      const resolved = resolver.getResolvedCallsFromFile(filePath);
      for (const rc of resolved) {
        if (rc.sourceFile === rc.targetFile) continue; // same-file, skip

        const calleeInfo = resolver.getMethodTaintInfo(rc.targetMethod);
        const taintedParamSet = new Set(calleeInfo?.taintedParams ?? []);

        crossFileCalls.push({
          id: `${rc.sourceFile}:${rc.call.location.line}:${rc.targetMethod}`,
          from: {
            file:   rc.sourceFile,
            method: rc.call.in_method ?? '',
            line:   rc.call.location.line,
          },
          to: {
            file:   rc.targetFile,
            method: rc.targetMethod,
            line:   0,  // target line resolved via symbol table if needed
          },
          args_mapping: (rc.call.arguments ?? []).map((_, i) => ({
            caller_arg:       i,
            callee_param:     i,
            taint_propagates: taintedParamSet.has(i),
          })),
          resolved: rc.resolution === 'exact',
        });
      }
    }

    // --- 3. Type hierarchy --------------------------------------------------
    const typeHierarchy: TypeHierarchy = projectGraph.typeHierarchy.toTypeHierarchyData();

    return { crossFileCalls, taintPaths, typeHierarchy };
  }
}
