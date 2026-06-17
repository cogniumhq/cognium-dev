/**
 * TaintPropagationPass
 *
 * Propagates taint through the DFG to find verified source-to-sink flows,
 * then supplements with three additional flow-detection strategies that the
 * DFG-based analysis may miss:
 *   - Array element flows (tainted array[idx] → sink)
 *   - Collection/iterator flows (list.get(), queue.poll(), etc.)
 *   - Direct parameter-to-sink flows (interprocedural parameter used at sink)
 *
 * Depends on: sink-filter, constant-propagation
 */

import type { TaintFlowInfo } from '../../types/index.js';
import type { CircleIR } from '../../types/index.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { ConstantPropagatorResult } from './constant-propagation-pass.js';
import type { SinkFilterResult } from './sink-filter-pass.js';
import { propagateTaint } from '../taint-propagation.js';
import { isFalsePositive, isCorrelatedPredicateFP } from '../constant-propagation.js';
import { buildPythonTaintedVars, buildRustTaintedVars } from './language-sources-pass.js';
import { canSourceReachSink } from '../findings.js';

export interface TaintPropagationPassResult {
  flows: TaintFlowInfo[];
}

export class TaintPropagationPass implements AnalysisPass<TaintPropagationPassResult> {
  readonly name = 'taint-propagation';
  readonly category = 'security' as const;

  run(ctx: PassContext): TaintPropagationPassResult {
    const { graph } = ctx;
    const { calls, types } = graph.ir;

    const constProp   = ctx.getResult<ConstantPropagatorResult>('constant-propagation');
    const sinkFilter  = ctx.getResult<SinkFilterResult>('sink-filter');
    const { sources, sinks, sanitizers } = sinkFilter;

    if (sinks.length === 0) {
      return { flows: [] };
    }
    // No real sources, but Python may still synthesize sources from derived
    // tainted vars (e.g. for-loop iterables — cognium-dev #76/#83). Defer the
    // empty-source early-return for Python so detectExpressionScanFlows runs.
    const canSynthesize = ctx.language === 'python' && typeof ctx.code === 'string';
    if (sources.length === 0 && !canSynthesize) {
      return { flows: [] };
    }

    // DFG-based taint propagation
    const propagationResult = propagateTaint(graph, sources, sinks, sanitizers);

    // Filter flows: eliminate dead-code paths and constant-propagation FPs
    const verifiedFlows = propagationResult.flows.filter(flow => {
      if (constProp.unreachableLines.has(flow.sink.line)) return false;

      for (const step of flow.path) {
        const fpCheck = isFalsePositive(constProp, step.line, step.variable);
        if (fpCheck.isFalsePositive) return false;
      }

      if (isCorrelatedPredicateFP(constProp, flow)) return false;

      // Note: Sprint 9 #58.1 sanitizer-guard suppression (regex-allowlist
      // and similar positive sanitizer evidence) is applied as a uniform
      // final-pass filter below — see `sanitizedNames` block before return.

      return true;
    });

    // Convert to TaintFlowInfo format
    const flows: TaintFlowInfo[] = verifiedFlows.map(flow => ({
      source_line: flow.source.line,
      sink_line: flow.sink.line,
      source_type: flow.source.type,
      sink_type: flow.sink.type,
      path: flow.path.map(step => ({
        variable: step.variable,
        line: step.line,
        type: step.type,
      })),
      confidence: flow.confidence,
      sanitized: flow.sanitized,
    }));

    // Supplement: array element flows
    const arrayFlows = detectArrayElementFlows(calls, sources, sinks, constProp.taintedArrayElements, constProp.unreachableLines) ?? [];
    for (const f of arrayFlows) {
      if (!flows.some(x => x.source_line === f.source_line && x.sink_line === f.sink_line)) {
        flows.push(f);
      }
    }

    // Supplement: collection/iterator flows — with FP filtering
    const collectionFlows = detectCollectionFlows(calls, sources, sinks, constProp.tainted, constProp.unreachableLines, ctx.code) ?? [];
    for (const f of collectionFlows) {
      if (flows.some(x => x.source_line === f.source_line && x.sink_line === f.sink_line)) continue;

      const flowForCheck = {
        source: { line: f.source_line },
        sink:   { line: f.sink_line   },
        path:   f.path.map(p => ({ variable: p.variable, line: p.line })),
      };
      if (isCorrelatedPredicateFP(constProp, flowForCheck)) continue;

      let isFP = false;
      for (const step of f.path) {
        if (isFalsePositive(constProp, step.line, step.variable).isFalsePositive) { isFP = true; break; }
      }
      if (isFP) continue;

      flows.push(f);
    }

    // Supplement: direct parameter-to-sink flows
    const paramFlows = detectParameterSinkFlows(types, calls, sources, sinks, constProp.unreachableLines, constProp.tainted, ctx.code) ?? [];
    for (const f of paramFlows) {
      if (!flows.some(x => x.source_line === f.source_line && x.sink_line === f.sink_line)) {
        flows.push(f);
      }
    }

    // Supplement: expression-scan flows for assignment-style sources (#18).
    //
    // The DFG-based propagator above misses two important cases:
    //   1. Languages without a per-language DFG builder (Python falls through
    //      to buildJavaDFG which finds no `method_declaration` nodes and emits
    //      an empty DFG — defs=[], uses=[], chains=[]).
    //   2. Sink calls whose argument is a compound expression (e.g.
    //      `cur.execute("SELECT ... " + uid)`) where `arg.variable` is null
    //      because the arg node isn't a bare `identifier`.
    //
    // Both cases break the `arg.variable === use.variable` matching in
    // propagateTaint(). For sources that already carry an explicit `variable`
    // field (assignment-style sources from LanguageSourcesPass, e.g.
    // `findPythonAssignmentSources`), we can sidestep the DFG entirely:
    // scan each sink's call-argument expressions for that variable name as
    // an identifier-boundary match. This is language-agnostic but in practice
    // benefits Python the most because Java sources rarely set `variable`.
    const exprScanFlows = detectExpressionScanFlows(calls, sources, sinks, sanitizers, constProp.unreachableLines, constProp.tainted, ctx.code, ctx.language) ?? [];
    for (const f of exprScanFlows) {
      if (flows.some(x =>
        x.source_line === f.source_line &&
        x.sink_line === f.sink_line &&
        x.sink_type === f.sink_type
      )) continue;

      const flowForCheck = {
        source: { line: f.source_line },
        sink:   { line: f.sink_line   },
        path:   f.path.map(p => ({ variable: p.variable, line: p.line })),
      };
      if (isCorrelatedPredicateFP(constProp, flowForCheck)) continue;

      let isFP = false;
      for (const step of f.path) {
        if (isFalsePositive(constProp, step.line, step.variable).isFalsePositive) { isFP = true; break; }
      }
      if (isFP) continue;

      flows.push(f);
    }

    // Sprint 9 #58.1 — final pass: drop any flow whose source variable was
    // explicitly marked sanitized by a guard (e.g. regex-allowlist).
    // Applied to ALL flow generators (DFG-built and the four supplements)
    // so the suppression is uniform regardless of which path emitted the flow.
    const sanitizedNames = constProp.sanitizedVars;
    const finalFlows = sanitizedNames.size === 0 ? flows : flows.filter(f => {
      if (f.path.length === 0) return true;
      const sourceVar = f.path[0].variable;
      if (!sourceVar) return true;
      if (sanitizedNames.has(sourceVar)) return false;
      for (const s of sanitizedNames) {
        if (s.endsWith(`:${sourceVar}`)) return false;
      }
      return true;
    });

    return { flows: finalFlows };
  }
}

// ---------------------------------------------------------------------------
// Helpers (moved verbatim from analyzer.ts)
// ---------------------------------------------------------------------------

function detectCollectionFlows(
  calls: CircleIR['calls'],
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks'],
  taintedVars: Set<string>,
  unreachableLines: Set<number>,
  code?: string,
): CircleIR['taint']['flows'] {
  const flows: CircleIR['taint']['flows'] = [];
  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  for (const sink of sinks) {
    if (unreachableLines.has(sink.line)) continue;
    const callsAtSink = callsByLine.get(sink.line) ?? [];

    for (const call of callsAtSink) {
      for (const arg of call.arguments) {
        // Skip arguments that are not in the sink's dangerous positions
        if (sink.argPositions && sink.argPositions.length > 0 &&
            !sink.argPositions.includes(arg.position)) {
          continue;
        }
        if (arg.variable) {
          const varName = arg.variable;
          const scopedName = call.in_method ? `${call.in_method}:${varName}` : varName;
          if (taintedVars.has(varName) || taintedVars.has(scopedName)) {
            const source = sources[0];
            if (source) {
              // Sprint 9 #56 / #58.3 — same reassign-to-literal guard as
              // detectExpressionScanFlows. Suppress when the variable is
              // demonstrably rewritten to a literal between source and sink.
              if (
                typeof code === 'string' &&
                isReassignedToLiteralBetween(code, varName, source.line, sink.line)
              ) {
                continue;
              }
              flows.push({
                source_line: source.line, sink_line: sink.line,
                source_type: source.type, sink_type: sink.type,
                path: [
                  { variable: varName, line: source.line, type: 'source' as const },
                  { variable: varName, line: sink.line,   type: 'sink'   as const },
                ],
                confidence: 0.8, sanitized: false,
              });
            }
          }
        }

        if (arg.expression) {
          const expr = arg.expression;
          // Pre-compiled patterns for collection taint propagation
          const collectionPatterns = [
            { method: 'getLast',  re: /(\w+)\.getLast\(/ },
            { method: 'getFirst', re: /(\w+)\.getFirst\(/ },
            { method: 'get',      re: /(\w+)\.get\(/ },
            { method: 'next',     re: /(\w+)\.next\(/ },
            { method: 'poll',     re: /(\w+)\.poll\(/ },
            { method: 'peek',     re: /(\w+)\.peek\(/ },
            { method: 'toArray',  re: /(\w+)\.toArray\(/ },
          ];
          for (const { re } of collectionPatterns) {
            const match = expr.match(re);
            if (match) {
              const collectionVar = match[1];
              const scopedCollection = call.in_method ? `${call.in_method}:${collectionVar}` : collectionVar;
              if (taintedVars.has(collectionVar) || taintedVars.has(scopedCollection)) {
                const source = sources[0];
                if (source) {
                  if (
                    typeof code === 'string' &&
                    isReassignedToLiteralBetween(code, collectionVar, source.line, sink.line)
                  ) {
                    continue;
                  }
                  flows.push({
                    source_line: source.line, sink_line: sink.line,
                    source_type: source.type, sink_type: sink.type,
                    path: [
                      { variable: collectionVar, line: source.line, type: 'source' as const },
                      { variable: collectionVar, line: sink.line,   type: 'sink'   as const },
                    ],
                    confidence: 0.75, sanitized: false,
                  });
                }
              }
            }
          }
        }
      }
    }
  }

  return flows;
}

function detectArrayElementFlows(
  calls: CircleIR['calls'],
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks'],
  taintedArrayElements: Map<string, Set<string>>,
  unreachableLines: Set<number>,
): CircleIR['taint']['flows'] {
  const flows: CircleIR['taint']['flows'] = [];
  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  for (const sink of sinks) {
    if (unreachableLines.has(sink.line)) continue;
    const callsAtSink = callsByLine.get(sink.line) ?? [];

    for (const call of callsAtSink) {
      for (const arg of call.arguments) {
        // Skip arguments that are not in the sink's dangerous positions
        if (sink.argPositions && sink.argPositions.length > 0 &&
            !sink.argPositions.includes(arg.position)) {
          continue;
        }
        const arrayAccessMatch = arg.expression?.match(/^(\w+)\[(\d+|[^[\]]+)\]$/);
        if (arrayAccessMatch) {
          const arrayName = arrayAccessMatch[1];
          const indexStr  = arrayAccessMatch[2];
          const taintedIndices = taintedArrayElements.get(arrayName);
          if (taintedIndices) {
            const isTainted = taintedIndices.has(indexStr) || taintedIndices.has('*');
            if (isTainted) {
              const source = sources[0];
              if (source) {
                flows.push({
                  source_line: source.line, sink_line: sink.line,
                  source_type: source.type, sink_type: sink.type,
                  path: [
                    { variable: arrayName,                    line: source.line, type: 'source' as const },
                    { variable: `${arrayName}[${indexStr}]`, line: sink.line,   type: 'sink'   as const },
                  ],
                  confidence: 0.85, sanitized: false,
                });
              }
            }
          }
        }
      }
    }
  }

  return flows;
}

function detectParameterSinkFlows(
  types: CircleIR['types'],
  calls: CircleIR['calls'],
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks'],
  unreachableLines: Set<number>,
  tainted: Set<string>,
  code?: string,
): CircleIR['taint']['flows'] {
  const flows: CircleIR['taint']['flows'] = [];

  const paramSourcesByMethod = new Map<string, Map<string, CircleIR['taint']['sources'][0]>>();
  for (const source of sources) {
    if (source.type === 'interprocedural_param') {
      const match = source.location.match(/(\S+)\s+(\S+)\s+in\s+(\S+)/);
      if (match) {
        const paramName  = match[2];
        const methodName = match[3];
        let methodParams = paramSourcesByMethod.get(methodName);
        if (!methodParams) { methodParams = new Map(); paramSourcesByMethod.set(methodName, methodParams); }
        methodParams.set(paramName, source);
      }
    }
  }

  if (paramSourcesByMethod.size === 0) return flows;

  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  for (const sink of sinks) {
    if (unreachableLines.has(sink.line)) continue;
    const callsAtSink = callsByLine.get(sink.line) ?? [];

    for (const call of callsAtSink) {
      const methodName = call.in_method;
      if (!methodName) continue;
      const methodParamSources = paramSourcesByMethod.get(methodName);
      if (!methodParamSources) continue;

      for (const arg of call.arguments) {
        if (arg.variable) {
          // Skip arguments that are not in the sink's dangerous positions.
          // E.g., execSync(cmd, { cwd: path }) — only arg 0 is a command injection sink.
          if (sink.argPositions && sink.argPositions.length > 0 &&
              !sink.argPositions.includes(arg.position)) {
            continue;
          }
          const paramSource = methodParamSources.get(arg.variable);
          if (paramSource) {
            const exists = flows.some(f => f.source_line === paramSource.line && f.sink_line === sink.line);
            if (!exists) {
              if (
                typeof code === 'string' &&
                isReassignedToLiteralBetween(code, arg.variable, paramSource.line, sink.line)
              ) {
                continue;
              }
              // Note: DFG-flow filter handles sanitizer-guard suppression
              // via `sanitizedVars` (positive-evidence check).
              flows.push({
                source_line: paramSource.line, sink_line: sink.line,
                source_type: paramSource.type, sink_type: sink.type,
                path: [
                  { variable: arg.variable, line: paramSource.line, type: 'source' as const },
                  { variable: arg.variable, line: sink.line,        type: 'sink'   as const },
                ],
                confidence: 0.75, sanitized: false,
              });
            }
          }
        }
      }
    }
  }

  // types parameter is accepted for API compatibility; not used in current implementation
  void types;
  return flows;
}

/**
 * Detect taint flows by scanning sink call argument expressions for any
 * source-variable name (#18).
 *
 * Algorithm — for each source with an explicit `variable` field (set by
 * assignment-style source detectors such as `findPythonAssignmentSources`,
 * which records the LHS variable name when an HTTP/file/env call appears on
 * the RHS):
 *
 *   1. For every sink at a later line, look at its call-site arguments.
 *   2. Respect `sink.argPositions` — skip positions that aren't dangerous
 *      (e.g. `execSync(cmd, opts)` only flags arg 0).
 *   3. If the source `variable` appears as a `\b<var>\b` identifier-boundary
 *      match inside any dangerous argument's expression text, emit a flow.
 *
 * The word-boundary regex prevents accidental substring matches
 * (e.g. tainted `uid` does NOT match `uid_table`). Confidence is moderated
 * by both source and sink confidence and a 0.7 multiplier to keep these
 * expression-scan flows distinguishable from full DFG-tracked flows.
 *
 * This detector unblocks all non-XSS Python categories (sqli, pathtraver,
 * cmdi, xpathi, xxe, deserialization, codeinj, ldapi, redirect, trustbound)
 * which previously emitted `flows: []` because:
 *   - Python has no language-specific DFG builder (falls through to Java DFG
 *     which finds zero `method_declaration` nodes in Python ASTs), AND
 *   - Python call-arg extraction sets `arg.variable = null` for compound
 *     expressions like `"SELECT ... " + uid`.
 *
 * Java is unaffected because Java sources rarely set the `variable` field
 * (they come from getter pattern detection, `@RequestParam` annotations,
 * or YAML sink/source matches that operate at the receiver-type level).
 */

/**
 * Sprint 9 #56 / #58.3 — detect "reassign-to-literal" between a tainted
 * source line and a downstream sink line. When a tainted variable is
 * reassigned to a pure string literal on any intermediate line, the
 * original taint can no longer reach the sink and the flow is suppressed.
 *
 * Recognized patterns (one per line, considering only `srcLine+1 .. sinkLine-1`):
 *
 *   1. Naked literal reassignment (any language):
 *        var = "literal"
 *        var = 'literal'
 *        var := "literal"     (Go short var decl)
 *      Trailing `;` allowed.
 *
 *   2. Allowlist guard with literal fallback (Java/JS/TS):
 *        if (!ALLOWLIST.contains(var))      var = "literal";
 *        if (!ALLOWLIST.includes(var))      var = "literal";
 *        if (ALLOWLIST.indexOf(var) === -1) var = "literal";
 *
 *   3. Allowlist guard with literal fallback (Python):
 *        if var not in ALLOWLIST: var = "literal"
 *
 * Both the single-line and split-across-two-lines forms of (2)/(3) are
 * caught because (1) matches the literal-assignment line regardless of
 * what precedes it on the previous line.
 *
 * Conservatively requires the LHS to be exactly `var` (no attribute access,
 * no array indexing) so we never drop a flow whose downstream use is a
 * different member of the same object.
 */
function isReassignedToLiteralBetween(
  code: string,
  variable: string,
  srcLine: number,
  sinkLine: number,
): boolean {
  if (!variable || sinkLine - srcLine < 2) return false;
  // Bare identifiers only — attribute paths like `obj.attr` are not
  // simple variables and we shouldn't claim they were reassigned.
  if (!/^[A-Za-z_][\w]*$/.test(variable)) return false;
  const lines = code.split('\n');
  const lo = Math.max(0, srcLine); // line numbers are 1-based; lines[] 0-based.
  const hi = Math.min(lines.length, sinkLine - 1);
  // String-literal sub-pattern: double-quoted, single-quoted, or backtick.
  const strLit =
    `(?:"[^"\\\\]*(?:\\\\.[^"\\\\]*)*"|'[^'\\\\]*(?:\\\\.[^'\\\\]*)*'|\`[^\`\\\\]*(?:\\\\.[^\`\\\\]*)*\`)`;
  // (1) Naked literal reassignment, anchored at start of line.
  //     Accepts `=` and `:=` (Go).
  const reNaked = new RegExp(
    `^\\s*${variable}\\s*(?::?=)\\s*${strLit}\\s*;?\\s*$`,
  );
  // (2) Single-line allowlist guard with literal fallback. We accept any
  //     line that begins with an `if` and ends with `var = "literal"` on
  //     the same line. This matches Java's
  //     `if (!COLUMNS.contains(col)) col = "name";` and equivalents,
  //     including Python's `if col not in COLUMNS: col = "name"`. Greedy
  //     `.*` (not `.*?`) tolerates nested parentheses in the guard
  //     condition without needing a full expression parser.
  const reGuarded = new RegExp(
    `^\\s*if\\b.*\\b${variable}\\s*=\\s*${strLit}\\s*;?\\s*$`,
  );
  for (let i = lo; i < hi; i++) {
    const line = lines[i];
    if (!line) continue;
    if (reNaked.test(line) || reGuarded.test(line)) return true;
  }
  return false;
}

function detectExpressionScanFlows(
  calls: CircleIR['calls'],
  sources: CircleIR['taint']['sources'],
  sinks: CircleIR['taint']['sinks'],
  sanitizers: CircleIR['taint']['sanitizers'],
  unreachableLines: Set<number>,
  tainted: Set<string>,
  code?: string,
  language?: string,
): CircleIR['taint']['flows'] {
  const flows: CircleIR['taint']['flows'] = [];

  // Variable-name scan path: only consider sources that carry an explicit
  // variable name. The colocation path below (cognium-dev #83) runs even
  // when this set is empty, so we no longer early-return.
  const sourcesWithVar = sources.filter((s): s is typeof s & { variable: string } =>
    typeof s.variable === 'string' && s.variable.length > 0
  );

  // Per-alias sanitizer coverage (cognium-dev #65 pt2).
  //
  // When Python alias expansion (below) adds a derived variable like
  // `cmd` from `cmd = "ping " + shlex.quote(host)`, the assignment
  // line itself usually carries the sanitizer call. We record which
  // sink types each derived alias is sanitized against so flows of
  // those types can be marked sanitized at emission time. Without
  // this, `subprocess.run(cmd, shell=True)` on the next line is
  // reported as a command-injection FP even though `shlex.quote`
  // wraps the only tainted operand of the concat.
  //
  // Scope: only the alias map populated below uses this; bare-source
  // flows where the user passes the raw tainted var to a separate
  // `shlex.quote(host)` call (not part of an assignment) are
  // unaffected, because the sanitizer call alone does not actually
  // sanitize the original `host` variable.
  const aliasSanitizedFor = new Map<string, Set<string>>();

  // Python alias expansion (#20): seed the scan with not only direct source
  // variables (e.g. `uid` from `uid = request.form.get(...)`) but also any
  // derived/aliased variables produced by simple assignment chains, compound
  // expressions, container set/get round-trips (configparser), list append +
  // subscript reads, dict access, aug-assigns and for-loops. These are already
  // computed deterministically by `buildPythonTaintedVars` for sanitizer and
  // session-boundary checks; here we reuse the same map to fix the long tail
  // of "container round-trip / helper / alias" flows=0 false-negatives that
  // are the dominant driver of OWASP BenchmarkPython misses.
  //
  // We synthesize a virtual source for each derived var, anchored to the
  // earliest real source's line/type so reported flows still point at the
  // original `request.form.get(...)`-style source, not the alias.
  if (language === 'python' && typeof code === 'string') {
    const derived = buildPythonTaintedVars(code);
    if (derived.size > 0) {
      const existingVars = new Set(sourcesWithVar.map(s => s.variable));
      // Earliest real source — used as the anchor for synthetic source lines.
      // When no real source has a `variable` field, we fall back to a per-var
      // synthetic anchor at the derivation line (typical for the for-loop /
      // bare-inline cases targeted by cognium-dev #76 / #83).
      const hasRealSource = sourcesWithVar.length > 0;
      let anchor: typeof sourcesWithVar[0] | undefined = sourcesWithVar[0];
      if (anchor) {
        for (const s of sourcesWithVar) {
          if (s.line < anchor.line) anchor = s;
        }
      }
      for (const [varName, originLine] of derived) {
        if (!varName || existingVars.has(varName)) continue;
        // Don't shadow real sources; build a minimal synthetic record that
        // satisfies the scan loop below. When no real source exists, anchor
        // the synthetic source at the derivation line itself with a generic
        // `http_param` type — the for-loop / bare-inline patterns we want
        // to recover here are all web-request-derived in practice.
        if (hasRealSource && anchor) {
          sourcesWithVar.push({
            ...anchor,
            variable: varName,
          });
        } else {
          sourcesWithVar.push({
            type: 'http_param',
            location: `<derived> ${varName}`,
            severity: 'high',
            line: originLine,
            confidence: 0.9,
            variable: varName,
          });
        }
        existingVars.add(varName);
      }

      // cognium-dev #65 pt2: record per-alias sanitizer coverage.
      // For each derived alias `lhs = ... sanitizer(taintedVar) ...`,
      // pick up the sink types the sanitizer covers so flows of those
      // types can be marked sanitized when emitted below.
      if (sanitizers && sanitizers.length > 0) {
        const sanitizersByLine = new Map<number, typeof sanitizers>();
        for (const s of sanitizers) {
          const arr = sanitizersByLine.get(s.line) ?? [];
          arr.push(s);
          sanitizersByLine.set(s.line, arr);
        }
        const codeLines = code.split('\n');
        for (const [varName, originLine] of derived) {
          const lineSans = sanitizersByLine.get(originLine);
          if (!lineSans || lineSans.length === 0) continue;
          const lineText = codeLines[originLine - 1] ?? '';
          const rhsMatch = lineText.match(/^\s*\w+\s*=\s*(.+)$/);
          if (!rhsMatch) continue;
          const rhs = rhsMatch[1];
          for (const san of lineSans) {
            // Extract the final method-name token before the trailing `()`.
            // Handles:
            //   `realpath()`                → realpath
            //   `os.path.realpath()`        → realpath
            //   `Path(raw).resolve()`       → resolve (chained constructor)
            // Then verify by substring-matching `<name>(` in the RHS text,
            // which is sufficient evidence that the sanitizer call is on
            // this assignment's RHS.
            const sanMatch = san.method.match(/(\w+)\(\)$/);
            if (!sanMatch) continue;
            const sanName = sanMatch[1];
            if (!rhs.includes(`${sanName}(`)) continue;
            let set = aliasSanitizedFor.get(varName);
            if (!set) { set = new Set<string>(); aliasSanitizedFor.set(varName, set); }
            for (const t of san.sanitizes) set.add(t);
          }
        }
      }
    }
  }

  // Rust alias expansion (#71): mirror the Python branch above so that
  // multi-level extractor chains like
  //   let form = f.into_inner();
  //   let path = form.path;
  //   fs::write(path, ...);
  // produce a flow back to the original `web::Form<T>` parameter source.
  // `buildRustTaintedVars` does a fixpoint over let-bindings + assignments
  // seeded with the real source variables.
  if (language === 'rust' && typeof code === 'string' && sourcesWithVar.length > 0) {
    const seedVars = new Set(sourcesWithVar.map(s => s.variable));
    const derived = buildRustTaintedVars(code, seedVars);
    if (derived.size > 0) {
      let anchor: typeof sourcesWithVar[0] = sourcesWithVar[0];
      for (const s of sourcesWithVar) {
        if (s.line < anchor.line) anchor = s;
      }
      const existingVars = new Set(sourcesWithVar.map(s => s.variable));
      for (const [varName] of derived) {
        if (!varName || existingVars.has(varName)) continue;
        sourcesWithVar.push({
          ...anchor,
          variable: varName,
        });
        existingVars.add(varName);
      }
    }
  }

  // Pre-compile word-boundary regexes per unique source variable.
  // Escape regex-special characters defensively (variable names should be
  // plain identifiers but Python attribute paths like `obj.attr` could leak in).
  const reCache = new Map<string, RegExp>();
  for (const s of sourcesWithVar) {
    if (reCache.has(s.variable)) continue;
    const escaped = s.variable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // Unicode-aware word boundary so non-ASCII identifiers (e.g. `café`) match.
    reCache.set(s.variable, new RegExp(`(?<![\\p{L}\\p{N}_])${escaped}(?![\\p{L}\\p{N}_])`, 'u'));
  }

  // Group calls by line for O(1) sink-line lookup.
  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  for (const sink of sinks) {
    if (unreachableLines.has(sink.line)) continue;
    const callsAtSink = callsByLine.get(sink.line) ?? [];

    for (const call of callsAtSink) {
      for (const arg of call.arguments) {
        // Respect dangerous-position filtering (e.g. execSync arg 0 only).
        if (sink.argPositions && sink.argPositions.length > 0 &&
            !sink.argPositions.includes(arg.position)) {
          continue;
        }
        const expr = arg.expression;
        if (!expr) continue;

        for (const source of sourcesWithVar) {
          // Source must appear before the sink (no backward flows).
          if (source.line >= sink.line) continue;

          const re = reCache.get(source.variable);
          if (!re || !re.test(expr)) continue;

          // Dedupe by (source_line, sink_line, sink.type) — a single source
          // can reach multiple distinct sinks at the same line (e.g. an
          // execute() call modeled as both `xss` and `sql_injection`).
          if (flows.some(f =>
            f.source_line === source.line &&
            f.sink_line === sink.line &&
            f.sink_type === sink.type
          )) continue;

          // cognium-dev #65 pt2: suppress flows where the derived alias
          // was created by an assignment that wraps the tainted operand
          // in a sanitizer covering this sink type (e.g.
          // `cmd = "ping " + shlex.quote(host)` → command_injection).
          if (aliasSanitizedFor.get(source.variable)?.has(sink.type)) {
            break;
          }

          // Sprint 9 #58.3 / #56: between source.line and sink.line, if
          // the tainted variable is reassigned to a pure string literal
          // (either naked `var = "lit"` or guarded by an allowlist check
          // such as `if (!ALLOWLIST.contains(var)) var = "lit"` /
          // `if var not in ALLOWLIST: var = "lit"`), the original taint
          // no longer reaches the sink — suppress the flow.
          if (
            typeof code === 'string' &&
            isReassignedToLiteralBetween(code, source.variable, source.line, sink.line)
          ) {
            break;
          }

          // Note: DFG-flow filter handles sanitizer-guard suppression
          // via `sanitizedVars` (positive-evidence check).

          flows.push({
            source_line: source.line,
            sink_line:   sink.line,
            source_type: source.type,
            sink_type:   sink.type,
            path: [
              { variable: source.variable, line: source.line, type: 'source' as const },
              { variable: source.variable, line: sink.line,   type: 'sink'   as const },
            ],
            confidence: source.confidence * sink.confidence * 0.7,
            sanitized: false,
          });
          break; // one source per arg is enough
        }
      }
    }
  }

  // cognium-dev #83: inline-source colocation.
  //
  // When a source expression is used INLINE as a sink argument — e.g.
  // `Runtime.getRuntime().exec(req.getParameter("u"))` (Java),
  // `eval(req.query.x)` (JS), `os.system(request.args.get("u"))` (Python) —
  // the source pattern matcher emits a source at `sink.line`, and no
  // `variable` is bound (the arg node isn't a simple identifier).
  // The DFG-based `propagateTaint` skips it (no `arg.variable`) and the
  // variable-name scan above ignores it (no `source.variable`).
  //
  // Emit a direct flow when (a) the source line is the sink line, and
  // (b) the source type can reach the sink type. Sanitizer checks are
  // intentionally not applied here because an inline source has no
  // intermediate assignment line for a sanitizer to wrap, and the
  // sink-call expression itself either contains the raw source or
  // doesn't; if a sanitizer wraps the source inside the arg expression
  // (e.g. `exec(escape(req.query.x))`), the sanitizer pass will already
  // mark the sink as sanitized via `sinkSanitizationMap`.
  //
  // Subsumes cognium-dev#76's "Python for-loop iterable inline source"
  // for the simple cases where the source pattern matches the iterable
  // and the loop variable is used on the same line.
  //
  // Restricted to sources with no `variable` field: an inline-pattern
  // source has no enclosing assignment, so it can't be confused with an
  // assignment-style source whose use happens to land on the same line
  // (the latter must still respect "source precedes sink" — see the
  // taint-propagation-pass "does NOT emit when source line is at or
  // after sink line" regression guard).
  const sourcesByLine = new Map<number, typeof sources>();
  for (const s of sources) {
    if (s.variable && s.variable.length > 0) continue;
    const arr = sourcesByLine.get(s.line) ?? [];
    arr.push(s);
    sourcesByLine.set(s.line, arr);
  }
  for (const sink of sinks) {
    if (unreachableLines.has(sink.line)) continue;
    const colocSources = sourcesByLine.get(sink.line);
    if (!colocSources || colocSources.length === 0) continue;
    for (const source of colocSources) {
      if (!canSourceReachSink(source.type, sink.type)) continue;
      // Skip the degenerate `file_input` → `path_traversal` colocation
      // where the source and sink describe the SAME call (one being the
      // chained accessor of the other). Example: Python
      //   open(safe).read()
      // matches both the `file_input` source pattern (`read` on a file
      // object) and the `path_traversal` sink pattern (`open(...)`),
      // but here `open()` is the sink target, not a downstream consumer
      // of itself. We detect this by checking whether `sink.method(`
      // appears INSIDE the source's location string — if it does, the
      // source's call is a chained derivative of the sink's call (i.e.
      // `<sink>(...).<srcMethod>()`), not a distinct consumer at the
      // same line. Real cross-call cases like Java Zip-Slip —
      //   new File(dir, entry.getName())
      // — are unaffected because the sink location is `File() in m`
      // while the source location is `entry.getName() in m`; neither
      // string contains the other's method-name marker, so the flow is
      // still emitted. Sprint 9 #48.2 / #51.1.
      if (
        source.type === 'file_input' &&
        sink.type === 'path_traversal' &&
        sink.method &&
        source.location.includes(`${sink.method}(`)
      ) {
        continue;
      }
      if (flows.some(f =>
        f.source_line === source.line &&
        f.sink_line === sink.line &&
        f.sink_type === sink.type
      )) continue;
      flows.push({
        source_line: source.line,
        sink_line:   sink.line,
        source_type: source.type,
        sink_type:   sink.type,
        path: [
          { variable: '<inline>', line: source.line, type: 'source' as const },
          { variable: '<inline>', line: sink.line,   type: 'sink'   as const },
        ],
        confidence: source.confidence * sink.confidence * 0.85,
        sanitized: false,
      });
    }
  }

  return flows;
}
