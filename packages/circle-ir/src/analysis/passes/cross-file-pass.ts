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
  TypeInfo,
  CircleIR,
} from '../../types/index.js';
import type { ProjectGraph } from '../../graph/project-graph.js';
import type { InterproceduralTaintPath } from '../../resolution/cross-file.js';
import { logger } from '../../utils/logger.js';

export interface CrossFilePassResult {
  /** Inter-file method calls (source file → target file). */
  crossFileCalls: CrossFileCall[];
  /** Taint paths that cross file boundaries. */
  taintPaths: TaintPath[];
  /** Type hierarchy across all files. */
  typeHierarchy: TypeHierarchy;
  /**
   * Set when the cross-file budget (`options.budgetMs`) was exceeded
   * mid-phase. When `true`, `taintPaths` may be incomplete — remaining
   * sub-phases were skipped. Added in 3.89.0 (#141).
   */
  budgetExceeded?: boolean;
}

export interface CrossFilePassOptions {
  /**
   * Wall-time budget (ms) for the entire cross-file phase. `0` or `undefined`
   * disables the breaker (unlimited). On exceed, partial `taintPaths` are
   * kept, the remaining sub-phases are skipped, and `budgetExceeded` is set.
   *
   * Threaded from `AnalyzerOptions.crossFileBudgetMs` (default 300_000ms /
   * 5 min) in 3.89.0 to mitigate #141 (langchain4j hang).
   */
  budgetMs?: number;
}

export class CrossFilePass {
  run(
    projectGraph: ProjectGraph,
    /** Raw source lines per file (used to populate `code` fields in paths). */
    sourceLines: Map<string, string[]>,
    options: CrossFilePassOptions = {},
  ): CrossFilePassResult {
    const resolver = projectGraph.resolver;
    const budgetMs = options.budgetMs ?? 0;
    const startMs = Date.now();
    const budgetExceeded = (): boolean =>
      budgetMs > 0 && Date.now() - startMs > budgetMs;
    const fileCount = projectGraph.filePaths.length;
    logger.info('cross-file: starting', { files: fileCount, budgetMs });

    // --- 1. Cross-file taint flows → TaintPath[] ----------------------------
    const phase1Start = Date.now();
    logger.debug('cross-file: phase 1/4 starting (findCrossFileTaintFlows)');
    const flows = resolver.findCrossFileTaintFlows();
    logger.info('cross-file: phase 1/4 done', {
      flows: flows.length,
      elapsedMs: Date.now() - phase1Start,
    });
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
    //
    // Also includes cross-instance field-binding flows
    // (`findFieldBindingTaintPaths()`): canonical Jenkins shape where one
    // class writes `this.field = param` in a `@DataBoundConstructor` and
    // another class reads that field on an aliased instance and forwards to
    // a sink.
    //
    // Phases 2-4 are individually budget-gated so a pathological 3rd phase
    // (e.g. quadratic aliasing on a large Java monorepo) cannot block
    // delivery of phase-1/2 taint paths. See #141 / 3.89.0 CHANGELOG.
    let exceeded = false;
    const ipPaths: InterproceduralTaintPath[] = [];

    if (budgetExceeded()) {
      exceeded = true;
      logger.warn('cross-file: budget exceeded after phase 1/4, skipping phases 2-4', {
        budgetMs, elapsedMs: Date.now() - startMs, partialPaths: taintPaths.length,
      });
    } else {
      const phase2Start = Date.now();
      logger.debug('cross-file: phase 2/4 starting (findInterproceduralTaintPaths)');
      const phase2 = resolver.findInterproceduralTaintPaths();
      ipPaths.push(...phase2);
      logger.info('cross-file: phase 2/4 done', {
        paths: phase2.length, elapsedMs: Date.now() - phase2Start,
      });
    }

    if (!exceeded && budgetExceeded()) {
      exceeded = true;
      logger.warn('cross-file: budget exceeded after phase 2/4, skipping phases 3-4', {
        budgetMs, elapsedMs: Date.now() - startMs, partialPaths: taintPaths.length + ipPaths.length,
      });
    } else if (!exceeded) {
      const phase3Start = Date.now();
      logger.debug('cross-file: phase 3/4 starting (findFieldBindingTaintPaths)');
      const phase3 = resolver.findFieldBindingTaintPaths();
      ipPaths.push(...phase3);
      logger.info('cross-file: phase 3/4 done', {
        paths: phase3.length, elapsedMs: Date.now() - phase3Start,
      });
    }

    if (!exceeded && budgetExceeded()) {
      exceeded = true;
      logger.warn('cross-file: budget exceeded after phase 3/4, skipping phase 4', {
        budgetMs, elapsedMs: Date.now() - startMs, partialPaths: taintPaths.length + ipPaths.length,
      });
    } else if (!exceeded) {
      const phase4Start = Date.now();
      logger.debug('cross-file: phase 4/4 starting (findCrossInstanceAliasingPaths)');
      const phase4 = findCrossInstanceAliasingPaths(projectGraph, sourceLines);
      ipPaths.push(...phase4);
      logger.info('cross-file: phase 4/4 done', {
        paths: phase4.length, elapsedMs: Date.now() - phase4Start,
      });
    }

    for (let i = 0; i < ipPaths.length; i++) {
      const p = ipPaths[i];
      const sinkIR = projectGraph.getIR(p.sink.file);
      if (!sinkIR) continue;
      const matchedSink = sinkIR.taint.sinks.find(s => s.line === p.sink.line);
      if (!matchedSink) continue;

      const srcLines = sourceLines.get(p.source.file) ?? [];
      const tgtLines = sourceLines.get(p.sink.file)   ?? [];

      // Dedup against any direct cross-file taint already emitted at the same
      // source/sink coordinates AND sink type. A field-binding / interprocedural
      // flow can legitimately land at the same coordinates as a direct flow
      // with a different vuln class (e.g. command_injection vs code_injection
      // at the same `execute()` call site). Without the type axis those get
      // silently dropped.
      const dupId = `${p.source.file}:${p.source.line}→${p.sink.file}:${p.sink.line}`;
      if (taintPaths.some(tp =>
        tp.source.file === p.source.file && tp.source.line === p.source.line &&
        tp.sink.file   === p.sink.file   && tp.sink.line   === p.sink.line &&
        tp.sink.type   === matchedSink.type)) {
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

    // --- 2b. Sanitizer post-filter (cognium-dev #239 C4 residual — 3.159.0)
    // ---------------------------------------------------------------------
    // The per-file `TaintPropagationPass` already consults sanitizers, but
    // the cross-file phases (1 direct, 2 interprocedural, 3 field-binding,
    // 4 aliasing) build flows from raw source/sink coordinates without
    // consulting either file's sanitizers. When the same source and sink
    // live in the same file (a legitimate output shape when the cross-file
    // resolver picks up a chain that never actually escapes the file), a
    // sanitizer between them was previously ignored — producing an
    // "intra-file" FP surface via the cross-file result.
    //
    // Filter is two-tier:
    //   - Same-file paths: drop when any sanitizer between source.line and
    //     sink.line covers sink.type.
    //   - Cross-file paths: drop when a sanitizer AT sink.line covers
    //     sink.type in the sink-file's IR (mirrors InterproceduralPass).
    const filteredTaintPaths = taintPaths.filter(tp => {
      const sinkIR = projectGraph.getIR(tp.sink.file);
      if (!sinkIR) return true;
      const sinkTypeStr = tp.sink.type as string;
      if (tp.source.file === tp.sink.file) {
        const lo = Math.min(tp.source.line, tp.sink.line);
        const hi = Math.max(tp.source.line, tp.sink.line);
        for (const san of sinkIR.taint.sanitizers ?? []) {
          if (san.line < lo || san.line > hi) continue;
          if ((san.sanitizes as readonly string[]).includes(sinkTypeStr)) {
            return false;
          }
        }
        return true;
      }
      for (const san of sinkIR.taint.sanitizers ?? []) {
        if (san.line !== tp.sink.line) continue;
        if ((san.sanitizes as readonly string[]).includes(sinkTypeStr)) {
          return false;
        }
      }
      return true;
    });

    // --- 3. Type hierarchy --------------------------------------------------
    const typeHierarchy: TypeHierarchy = projectGraph.typeHierarchy.toTypeHierarchyData();

    logger.info('cross-file: complete', {
      totalMs: Date.now() - startMs,
      paths: filteredTaintPaths.length,
      crossFileCalls: crossFileCalls.length,
      budgetExceeded: exceeded,
    });

    const result: CrossFilePassResult = { crossFileCalls, taintPaths: filteredTaintPaths, typeHierarchy };
    if (exceeded) result.budgetExceeded = true;
    return result;
  }
}

/**
 * Issue #78 round 2 — Cross-instance aliasing via constructor-stored receiver.
 *
 * Pattern:
 *   // Service.java
 *   class Service {
 *     private Repo repo;
 *     public Service(Repo r) { this.repo = r; }      // stores alias
 *     public void handle(HttpServletRequest req) {
 *       this.repo.sql = req.getParameter("c");        // tainted write
 *     }
 *   }
 *   // Repo.java
 *   class Repo {
 *     public String sql;
 *     public Statement stmt;
 *     public void run() throws Exception {
 *       stmt.executeQuery(sql);                       // sink reads field
 *     }
 *   }
 *
 * Algorithm:
 *   For each loaded Java class S, walk its method bodies for assignments
 *   of shape `this.<aliasField>.<innerField> = <rhs>`. Gate strictly:
 *     - aliasField is a declared field of S whose type T is a Java class
 *       defined elsewhere in the project, AND
 *     - innerField is a declared field of T, AND
 *     - RHS matches a known HTTP source.
 *   When the trigger fires, scan T's methods for sinks whose call
 *   arguments contain `\b<innerField>\b`. Emit one
 *   `InterproceduralTaintPath` per (write, sink) pair.
 *
 * Confidence 0.65 — strictly gated but the cross-instance reasoning is
 * still pattern-based.
 */
function findCrossInstanceAliasingPaths(
  projectGraph: ProjectGraph,
  _sourceLines: Map<string, string[]>,
): InterproceduralTaintPath[] {
  const paths: InterproceduralTaintPath[] = [];

  const javaHttpPattern = /\b(?:req|request|httpRequest|servletRequest|httpServletRequest)\.(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getCookies|getQueryString|getPathInfo|getRequestURI|getRequestURL|getInputStream|getReader)\b/;
  const aliasWriteRe = /^\s*this\.([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*=\s*(.+?)(?:;\s*)?$/;

  // Build a project-wide simple-name → (file, type, IR) index for Java classes.
  const typeIndex = new Map<string, { file: string; type: TypeInfo; ir: CircleIR }>();
  for (const filePath of projectGraph.filePaths) {
    const ir = projectGraph.getIR(filePath);
    if (!ir) continue;
    if (ir.meta.language !== 'java') continue;
    for (const t of ir.types) {
      if (t.kind === 'class') typeIndex.set(t.name, { file: filePath, type: t, ir });
    }
  }
  if (typeIndex.size === 0) return paths;

  for (const filePath of projectGraph.filePaths) {
    const ir = projectGraph.getIR(filePath);
    if (!ir) continue;
    if (ir.meta.language !== 'java') continue;
    const lines = _sourceLines.get(filePath);
    if (!lines || lines.length === 0) continue;

    for (const type of ir.types) {
      if (type.kind !== 'class') continue;

      // Map<aliasFieldName, aliasFieldDeclaredType>
      const aliasFields = new Map<string, string>();
      for (const f of type.fields) {
        if (!f.type) continue;
        // Strip generics; keep simple class name.
        const simple = f.type.replace(/<.*>/g, '').replace(/\[\]$/, '').trim();
        if (typeIndex.has(simple)) aliasFields.set(f.name, simple);
      }
      if (aliasFields.size === 0) continue;

      for (const m of type.methods) {
        if (m.name === type.name) continue; // skip constructor
        const mStart = m.start_line;
        const mEnd = m.end_line;

        for (let i = mStart - 1; i < Math.min(mEnd, lines.length); i++) {
          const trimmed = (lines[i] ?? '').trim();
          if (!trimmed || trimmed.startsWith('//')) continue;
          const wm = trimmed.match(aliasWriteRe);
          if (!wm) continue;
          const aliasField = wm[1];
          const innerField = wm[2];
          const rhs = wm[3].trim().replace(/;\s*$/, '');

          const aliasType = aliasFields.get(aliasField);
          if (!aliasType) continue;
          const target = typeIndex.get(aliasType);
          if (!target) continue;
          if (!target.type.fields.some(f => f.name === innerField)) continue;
          if (!javaHttpPattern.test(rhs)) continue;

          // Find sinks in any method of the aliased type whose call args
          // reference the inner field by name.
          const innerRe = new RegExp(`\\b${innerField}\\b`);
          for (const tm of target.type.methods) {
            const sinksInTarget = target.ir.taint.sinks.filter(
              s => s.line >= tm.start_line && s.line <= tm.end_line,
            );
            for (const sink of sinksInTarget) {
              const callsAtSink = target.ir.calls.filter(c => c.location.line === sink.line);
              let matched = false;
              for (const c of callsAtSink) {
                for (const a of c.arguments ?? []) {
                  if (innerRe.test(a.expression ?? '') || a.variable === innerField) {
                    matched = true;
                    break;
                  }
                }
                if (matched) break;
              }
              if (!matched) continue;

              paths.push({
                source: { file: filePath, line: i + 1, type: 'http_param' },
                sink: { file: target.file, line: sink.line, type: sink.type, cwe: sink.cwe },
                hops: [
                  { file: filePath, line: i + 1, method: m.name, kind: 'source' },
                  { file: filePath, line: i + 1, method: m.name, kind: 'field_write' },
                  { file: target.file, line: tm.start_line, method: tm.name, kind: 'field_read' },
                  { file: target.file, line: sink.line, method: tm.name, kind: 'sink' },
                ],
                confidence: 0.65,
              });
            }
          }
        }
      }
    }
  }

  return paths;
}
