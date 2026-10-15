/**
 * Taint Propagation Engine
 *
 * Tracks taint through variable assignments, method returns, and field accesses
 * using the DFG (Data Flow Graph) to find precise source-to-sink paths.
 */

import type {
  DFG,
  DFGDef,
  DFGUse,
  DFGChain,
  CallInfo,
  TaintSource,
  TaintSink,
  TaintSanitizer,
  SinkType,
} from '../types/index.js';
import { CodeGraph } from '../graph/index.js';
import { walkBackwardDefs } from './dfg-walk.js';
import { sanitizerCoversSink } from './sanitizer-index.js';

/**
 * Optional context used by checkSanitized to widen its search from a single
 * line to the transitive reaching-def chain of the tainted use.
 *
 * cognium-dev #238 — sanitizer-credit failure.
 */
export interface SanitizerCheckCtx {
  /** DFG def id of the tainted use at the sink. */
  startDefId: number;
  /** graph.chainsByToDef — backward chain index. */
  chainsByToDef: ReadonlyMap<number, DFGChain[]>;
  /** graph.defById — def id → DFGDef lookup. */
  defById: ReadonlyMap<number, DFGDef>;
  /** Max hops for the backward walk. Default 32. */
  maxHops?: number;
}

/**
 * Represents a tainted variable at a specific point in the code.
 */
export interface TaintedVariable {
  variable: string;
  defId: number;
  line: number;
  sourceType: string;
  sourceLine: number;
  confidence: number;
}

/**
 * Represents a taint flow from source to sink.
 */
export interface TaintFlow {
  source: TaintSource;
  sink: TaintSink;
  path: TaintFlowStep[];
  sanitized: boolean;
  sanitizer?: TaintSanitizer;
  confidence: number;
}

/**
 * A step in the taint flow path.
 */
export interface TaintFlowStep {
  variable: string;
  line: number;
  type: 'source' | 'assignment' | 'use' | 'return' | 'field' | 'sink';
  description: string;
}

/**
 * Result of taint propagation analysis.
 */
export interface TaintPropagationResult {
  taintedVars: TaintedVariable[];
  flows: TaintFlow[];
  reachableSinks: Map<TaintSink, TaintSource[]>;
}

/**
 * Build a line → sanitizers index from a list of sanitizers.
 *
 * Used when `CodeGraph` was constructed before TaintMatcherPass ran (the
 * common case in `analyze()`), so `graph.sanitizersByLine` is an empty Map.
 */
function buildSanitizersByLine(sanitizers: TaintSanitizer[]): Map<number, TaintSanitizer[]> {
  const out = new Map<number, TaintSanitizer[]>();
  for (const san of sanitizers) {
    const existing = out.get(san.line);
    if (existing) existing.push(san);
    else out.set(san.line, [san]);
  }
  return out;
}

/**
 * Propagate taint through the dataflow graph.
 *
 * Accepts either a CodeGraph (preferred) or the legacy (dfg, calls, ...) signature
 * for backward compatibility with existing call sites and tests.
 */
/** Number of `${…}` interpolations in a JS/TS template-literal argument. */
function templateInterpolationCount(expression: string): number {
  if (!expression.trimStart().startsWith('`')) return 0;
  return (expression.match(/\$\{/g) ?? []).length;
}

/** True when `+` appears outside string literals. */
function concatOutsideStrings(expression: string): boolean {
  return expression.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, ' ').includes('+');
}

export function propagateTaint(
  graphOrDfg: CodeGraph | DFG,
  callsOrSources: CallInfo[] | TaintSource[],
  sourcesOrSinks: TaintSource[] | TaintSink[],
  sinksOrSanitizers: TaintSink[] | TaintSanitizer[],
  sanitizersArg?: TaintSanitizer[]
): TaintPropagationResult {
  let graph: CodeGraph;
  let sources: TaintSource[];
  let sinks: TaintSink[];
  let sanitizers: TaintSanitizer[];

  if (graphOrDfg instanceof CodeGraph) {
    // New signature: (graph, sources, sinks, sanitizers)
    graph = graphOrDfg;
    sources = callsOrSources as TaintSource[];
    sinks = sourcesOrSinks as TaintSink[];
    sanitizers = sinksOrSanitizers as TaintSanitizer[];
  } else {
    // Legacy signature: (dfg, calls, sources, sinks, sanitizers)
    const dfg = graphOrDfg as DFG;
    const calls = callsOrSources as CallInfo[];
    sources = sourcesOrSinks as TaintSource[];
    sinks = sinksOrSanitizers as TaintSink[];
    sanitizers = sanitizersArg ?? [];
    graph = new CodeGraph({
      meta: { circle_ir: '3.0', file: '', language: 'java', loc: 0, hash: '' },
      types: [], calls, cfg: { blocks: [], edges: [] }, dfg,
      taint: { sources: [], sinks: [], sanitizers },
      imports: [], exports: [], unresolved: [], enriched: {},
    });
  }

  const taintedVars: TaintedVariable[] = [];
  const flows: TaintFlow[] = [];
  const javaConcat = graph.ir.meta.language === 'java';
  const jsLike = graph.ir.meta.language === 'javascript' || graph.ir.meta.language === 'typescript';
  const reachableSinks = new Map<TaintSink, TaintSource[]>();

  // Use pre-computed indexes from CodeGraph — no local map building needed
  const defsByLine = graph.defsByLine;
  const usesByLine = graph.usesByLine;
  const callsByLine = graph.callsByLine;
  // The CodeGraph is constructed in analyzer.ts BEFORE TaintMatcherPass runs,
  // so `graph.ir.taint.sanitizers` is empty and `graph.sanitizersByLine` is an
  // empty Map. Build the sanitizer index from the `sanitizers` parameter
  // (populated by TaintMatcherPass / SinkFilterPass) instead. Fall back to
  // graph.sanitizersByLine if the parameter is empty (legacy callers).
  const sanitizersByLine: Map<number, TaintSanitizer[]> = sanitizers.length > 0
    ? buildSanitizersByLine(sanitizers)
    : graph.sanitizersByLine;
  const defById = graph.defById;

  // Step 1: Identify initial tainted definitions (from sources)
  const rawInitialTaint = findInitialTaint(sources, callsByLine, defsByLine, graph.chainsByFromDef);

  // Filter variables added via the "next-line" heuristic that are actually the
  // result of a sanitizer call.  The source variable itself (tv.line ===
  // tv.sourceLine) is always tainted; next-line additions need an extra check.
  const filteredInitialTaint = rawInitialTaint.filter(tv => {
    if (tv.line === tv.sourceLine) return true;
    if (graph.taintBarrierDefIds.has(tv.defId)) return false;
    const sanCheck = checkSanitized(tv.sourceLine, tv.line, tv.sourceType, sanitizersByLine);
    return !sanCheck.sanitized;
  });
  // Propagation is a BFS that credits each definition to the first seed that
  // reaches it. A bare function parameter (`interprocedural_param`) is only
  // speculative evidence, and its line usually precedes the handler that
  // reads real input, so seeding it first let it claim definitions that a
  // real source also reaches: `const ident = async (x) => x; … v = await
  // ident(req.query.u)` credited `v` to `x`, and the flow was then dropped
  // as parameter-only. Seed real sources first so they win any shared
  // definition; parameter-only reach is unchanged.
  const initialTaint = [
    ...filteredInitialTaint.filter(tv => tv.sourceType !== 'interprocedural_param'),
    ...filteredInitialTaint.filter(tv => tv.sourceType === 'interprocedural_param'),
  ];
  taintedVars.push(...initialTaint);

  // Step 2: Propagate taint through def-use chains
  const propagatedTaint = propagateThroughChains(
    initialTaint,
    graph.chainsByFromDef,
    defById,
    sanitizersByLine,
    graph.taintBarrierDefIds
  );
  taintedVars.push(...propagatedTaint);

  // Combine all tainted definitions
  const allTaintedDefIds = new Set<number>();
  const taintByDefId = new Map<number, TaintedVariable>();
  for (const tv of taintedVars) {
    allTaintedDefIds.add(tv.defId);
    if (!yieldsToRealSource(taintByDefId.get(tv.defId), tv)) taintByDefId.set(tv.defId, tv);
  }

  // Step 3: Check which sinks are reachable from tainted variables
  for (const sink of sinks) {
    const usesAtSink = usesByLine.get(sink.line) ?? [];
    const callsAtSink = callsByLine.get(sink.line) ?? [];

    // Check if any argument to the sink call is tainted
    for (const call of callsAtSink) {
      for (const arg of call.arguments) {
        // Skip safe argument positions when the sink specifies dangerous ones.
        // execSync(cmd, opts) has arg_positions: [0] — only arg 0 (the
        // command string) is a sink; arg 1 (options with cwd) is safe.
        if (sink.argPositions && sink.argPositions.length > 0) {
          if (!sink.argPositions.includes(arg.position)) {
            continue;
          }
        }
        // Match set:
        //   - bare identifier args → arg.variable
        //   - compound expressions (e.g. `"..." + v`, `fmt.Sprintf(t, v)`) →
        //     any use at the sink line whose reaching def is tainted, since
        //     the compound expression cannot be reduced to a single variable
        //     name but its constituent identifiers appear in usesAtSink.
        //     (cognium-dev #243 — Go loop-carried range / helper-var shapes.)
        //   - `cmd + bar` still has arg.variable set to the first identifier.
        //     A constant prefix must not hide a later tainted operand
        //     (cognium-dev#627).
        const expr = typeof arg.expression === 'string' ? arg.expression : '';
        // cognium-dev#563: a JS/TS template literal names its first
        // interpolated identifier as `arg.variable`; a sanitized first value
        // (`${n}` from `parseInt`) must not hide a raw `${to}` after it.
        const compoundConcat = !!arg.variable && expr !== arg.variable && (
          (javaConcat && concatOutsideStrings(expr)) ||
          (jsLike && templateInterpolationCount(expr) > 1));
        const candidateUses = arg.variable && !compoundConcat
          ? usesAtSink.filter(u => u.variable === arg.variable)
          : usesAtSink;
        {
          // Find if this variable use is tainted
          for (const use of candidateUses) {
            if (use.def_id !== null) {
              if (allTaintedDefIds.has(use.def_id)) {
                // For compound expressions, require the identifier to appear
                // in this arg's expression text (word-boundary) so we don't
                // credit uses that belong to sibling args or unrelated call
                // parts on the same line.
                if (!arg.variable || compoundConcat) {
                  if (typeof arg.expression !== 'string' || arg.expression.length === 0) continue;
                  const re = new RegExp(`(?:^|[^A-Za-z0-9_$])${use.variable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:[^A-Za-z0-9_$]|$)`);
                  if (!re.test(arg.expression)) continue;
                }
                const taintInfo = taintByDefId.get(use.def_id);
                if (taintInfo) {
                  // Check if sanitized.
                  //
                  // cognium-dev #238 — pass a SanitizerCheckCtx so
                  // checkSanitized can walk the DFG backward from the sink
                  // use's reaching def, crediting sanitizers along the
                  // sanitize-then-sink chain (`safe = escape(x); sink(safe)`).
                  // Cycle-safe + bounded (hop cap 32).
                  // A sanitizer on the sink line covers its own operand, not
                  // every operand (#641). `escape(a) + b` still reaches the
                  // sink through `b`. An earlier `b = escape(b)` still credits.
                  let sanMap = sanitizersByLine;
                  if (
                    identifierOutsideSanitizerCalls(
                      use.variable,
                      callsAtSink,
                      sanitizersByLine.get(sink.line) ?? [],
                      sink.type,
                    )
                  ) {
                    const stripped = new Map(sanitizersByLine);
                    const kept = (sanitizersByLine.get(sink.line) ?? []).filter(
                      s => !sanitizerCoversSink(s, sink.type),
                    );
                    if (kept.length === 0) stripped.delete(sink.line);
                    else stripped.set(sink.line, kept);
                    sanMap = stripped;
                  }
                  const isSanitized = checkSanitized(
                    taintInfo.line,
                    sink.line,
                    sink.type,
                    sanMap,
                    {
                      startDefId: use.def_id,
                      chainsByToDef: graph.chainsByToDef,
                      defById,
                    }
                  );
                  if (!isSanitized.sanitized) {
                    // Find the source
                    const source = sources.find(s => s.line === taintInfo.sourceLine);
                    if (source) {
                      // Record the flow
                      const flow = buildTaintFlow(
                        source,
                        sink,
                        taintInfo
                      );
                      flows.push(flow);

                      // Record reachable sink
                      const existingSources = reachableSinks.get(sink) ?? [];
                      if (!existingSources.some(s => s.line === source.line)) {
                        existingSources.push(source);
                      }
                      reachableSinks.set(sink, existingSources);
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  // Dedup: multiple uses of the same tainted variable at the same sink line
  // (e.g. `x = f(x)` or repeated identifier occurrences in a concat
  // expression) can emit duplicate flows with the same (source_line,
  // sink_line, path). Collapse on the source/sink/path key so downstream
  // dedup on (source_line, sink_line, sink_type) still sees a single record
  // and reachableSinks reflects unique source→sink pairs.
  const seen = new Set<string>();
  const deduped: TaintFlow[] = [];
  for (const f of flows) {
    const key = `${f.source.line}|${f.sink.line}|${f.sink.type}|${f.path.map(p => p.variable).join('>')}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(f);
  }

  return { taintedVars, flows: deduped, reachableSinks };
}

/**
 * Find initial tainted definitions from sources.
 */
/** Locations of sources that name exactly one parameter binding (#586, #587). */
const PARAM_SCOPED_SOURCE_RE = /^(?:GraphQL \w+\.\w+ resolver args|Express handler destructured request) /;

/**
 * True when `code` (one trimmed source line) is an `if` / `else if` / `while`
 * header whose parenthesised condition closes on that same line.
 */
function isCompleteConditionHeader(code: string | undefined): boolean {
  if (!code) return false;
  const m = /^(?:\}\s*)?(?:else\s+)?(?:if|while)\s*\(/.exec(code);
  if (!m) return false;
  // Blank out string / char literals so their parens do not count.
  const text = code.slice(m[0].length - 1).replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, '""');
  let depth = 0;
  for (const ch of text) {
    if (ch === '(') depth++;
    else if (ch === ')' && --depth === 0) return true;
  }
  return false;
}

/**
 * True when `code` (one trimmed source line) holds a second statement after a
 * `;` (`a := f(); b := "x"`). A `for (…;…;…)` header and a trailing comment
 * or closing brace do not count.
 */
function hasSecondStatement(code: string | undefined): boolean {
  if (!code || /^for\b/.test(code)) return false;
  const text = code.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, '""');
  return /;\s*(?!\/\/|\/\*|#|\}|\)|$)\S/.test(text);
}

function findInitialTaint(
  sources: TaintSource[],
  callsByLine: Map<number, CallInfo[]>,
  defsByLine: Map<number, DFGDef[]>,
  chainsByFromDef: Map<number, DFGChain[]>,
): TaintedVariable[] {
  const tainted: TaintedVariable[] = [];

  for (const source of sources) {
    // Find definitions on the same line as the source
    const defsOnLine = defsByLine.get(source.line) ?? [];
    // cognium-dev#490: `q := r.FormValue("q"); x := "fixed"` puts two
    // statements on the source line. Only the source's own binding, and a
    // same-line definition the data-flow graph derives from it
    // (`w := r.FormValue("w"); cmd := "x " + w`), is tainted; an unrelated
    // neighbour statement's definition is not.
    let seedable: Set<number> | null = null;
    if (source.variable && hasSecondStatement(source.code)) {
      const own = defsOnLine.filter(d => d.variable === source.variable);
      if (own.length > 0) {
        seedable = new Set(own.map(d => d.id));
        for (const d of own) {
          for (const c of chainsByFromDef.get(d.id) ?? []) {
            if (defsOnLine.some(o => o.id === c.to_def)) seedable.add(c.to_def);
          }
        }
      }
    }

    for (const def of defsOnLine) {
      if (seedable && !seedable.has(def.id)) continue;
      // cognium-dev #308 (from cognium-ai#326 / #289): an
      // `interprocedural_param` source names exactly one parameter
      // (`source.variable`, set for Java/C#). Every parameter shares the
      // signature line, so seeding *all* param defs on that line co-tainted
      // non-taintable neighbours — `SqlConnection conn` beside
      // `string input` — and `new SqlCommand(constSql, conn)` then carried
      // the bogus taint into `cmd.ExecuteReader()`. Taintable neighbours
      // (`string tableName`) get their own source, so restricting the seed
      // to the named parameter loses nothing.
      // cognium-dev#586 / #587: framework parameter sources (GraphQL resolver
      // `args`, Express destructured request keys) also name exactly one
      // binding; `parent` / `context` / `res` share the signature line.
      if (
        (source.type === 'interprocedural_param' || PARAM_SCOPED_SOURCE_RE.test(source.location ?? '')) &&
        source.variable &&
        def.kind === 'param' &&
        def.variable !== source.variable
      ) {
        continue;
      }
      // A parameter source stands for the parameter's binding only. Other
      // definitions that share the signature line are not the parameter:
      // `const ident = async (x) => x;` defines `ident` there, and seeding it
      // tainted every `ident(…)` result with the parameter's taint (#490).
      if (source.type === 'interprocedural_param' && def.kind !== 'param') {
        continue;
      }
      tainted.push({
        variable: def.variable,
        defId: def.id,
        line: def.line,
        sourceType: source.type,
        sourceLine: source.line,
        confidence: source.confidence,
      });
    }

    // Also check the next line (for cases like: String x = request.getParameter("foo"))
    //
    // cognium-dev #101 (Sprint 14 Phase E): when the source carries a binding
    // variable (Java/JS/Python now set this via the LHS-recovery postprocess
    // in `taint-matcher.ts`), restrict next-line seeding to defs whose
    // variable matches `source.variable`. Without this guard, a bare
    // declaration on `source.line + 1` (e.g. `String cmd;` immediately after
    // `String type = req.getParameter("type");`) would be marked tainted
    // purely by line adjacency, then `propagateThroughChains` carries the
    // bogus taint forward to any sink that consumes `cmd` later in the
    // method — that was the FP-03 root cause from issue #101.
    //
    // cognium-dev#596: a source inside a complete `if (…)` / `while (…)` header
    // (`if (request.getParameter("a") != null)`) is a condition, not the start
    // of an expression that continues on the next line. The next line is the
    // body, so `target = "safe";` there must not be seeded by adjacency.
    //
    // cognium-dev#563: a source line that is a complete assignment
    // (`const qty = parseInt(req.query.qty, 10);`) does not continue on the
    // next line either; a local declared there (`const label = 'units';`)
    // is a new statement and gets no taint by adjacency.
    const closesOwnStatement = defsOnLine.length > 0 && /;\s*(?:\/\/.*)?$/.test(source.code ?? '');
    const defsNextLine = isCompleteConditionHeader(source.code)
      ? []
      : (defsByLine.get(source.line + 1) ?? []).filter(d => !(closesOwnStatement && d.kind === 'local'));
    for (const def of defsNextLine) {
      // Only include if there's a call on the source line
      const callsOnSourceLine = callsByLine.get(source.line) ?? [];
      if (callsOnSourceLine.length > 0) {
        if (source.variable && def.variable !== source.variable) continue;
        tainted.push({
          variable: def.variable,
          defId: def.id,
          line: def.line,
          sourceType: source.type,
          sourceLine: source.line,
          confidence: source.confidence * 0.9, // Slightly lower confidence
        });
      }
    }

    // Bash positional params ($1..$9, $@, $*) are extracted as synthetic param
    // defs at line 0 in the DFG, but the source emission happens at the use line
    // (the line the param is referenced on). Seed by variable name against line-0
    // param defs so the taint enters the DFG. Guarded on def.kind === 'param' to
    // keep the new path narrow.
    if (source.variable) {
      const paramDefs = defsByLine.get(0) ?? [];
      for (const def of paramDefs) {
        if (def.kind === 'param' && def.variable === source.variable) {
          tainted.push({
            variable: def.variable,
            defId: def.id,
            line: def.line,
            sourceType: source.type,
            sourceLine: source.line,
            confidence: source.confidence,
          });
        }
      }
    }
  }

  return tainted;
}

/**
 * True when `next` is a bare-parameter seed and `existing` already credits the
 * same definition to a real source: the real source keeps the definition.
 */
function yieldsToRealSource(existing: TaintedVariable | undefined, next: TaintedVariable): boolean {
  return existing !== undefined &&
    next.sourceType === 'interprocedural_param' &&
    existing.sourceType !== 'interprocedural_param';
}

/**
 * Propagate taint through def-use chains.
 * Accepts a pre-computed chainsByFromDef index (from CodeGraph) — no internal
 * adjacency list building needed.
 */
function propagateThroughChains(
  initialTaint: TaintedVariable[],
  chainsByFromDef: Map<number, DFGChain[]>,
  defById: Map<number, DFGDef>,
  sanitizersByLine: Map<number, TaintSanitizer[]>,
  taintBarrierDefIds: ReadonlySet<number>
): TaintedVariable[] {
  const propagated: TaintedVariable[] = [];
  const taintedDefIds = new Set<number>(initialTaint.map(t => t.defId));
  const taintInfoByDefId = new Map<number, TaintedVariable>();

  for (const t of initialTaint) {
    if (!yieldsToRealSource(taintInfoByDefId.get(t.defId), t)) taintInfoByDefId.set(t.defId, t);
  }

  // BFS to propagate taint
  const queue = [...initialTaint.map(t => t.defId)];
  const visited = new Set<number>(queue);

  while (queue.length > 0) {
    const currentDefId = queue.shift()!;
    const currentTaint = taintInfoByDefId.get(currentDefId);
    if (!currentTaint) continue;

    const outgoingChains = chainsByFromDef.get(currentDefId) ?? [];

    for (const chain of outgoingChains) {
      if (visited.has(chain.to_def)) continue;
      // A measure/test of the value or a constant-table lookup (#568, #667).
      if (taintBarrierDefIds.has(chain.to_def)) continue;

      const targetDef = defById.get(chain.to_def);
      if (!targetDef) continue;

      // Check if there's a sanitizer between source and this def
      const sanitizeCheck = checkSanitized(
        currentTaint.sourceLine,
        targetDef.line,
        currentTaint.sourceType,
        sanitizersByLine
      );

      if (!sanitizeCheck.sanitized) {
        const newTaint: TaintedVariable = {
          variable: targetDef.variable,
          defId: targetDef.id,
          line: targetDef.line,
          sourceType: currentTaint.sourceType,
          sourceLine: currentTaint.sourceLine,
          confidence: currentTaint.confidence * 0.95, // Decay confidence slightly
        };

        propagated.push(newTaint);
        taintedDefIds.add(targetDef.id);
        taintInfoByDefId.set(targetDef.id, newTaint);
        visited.add(targetDef.id);
        queue.push(targetDef.id);
      }
    }
  }

  return propagated;
}

// Sink types recognised by the sanitizer patterns.  Used to distinguish
// "propagation context" (sinkType is a source type like 'request_param') from
// "sink-check context" (sinkType is a real sink type like 'sql_injection').
const KNOWN_SINK_TYPES = new Set<string>([
  'sql_injection', 'xss', 'path_traversal', 'command_injection',
  'ssrf', 'ldap_injection', 'xpath_injection', 'log_injection',
  'xxe', 'deserialization', 'code_injection', 'mybatis_mapper_call',
  'redos', 'format_string', 'crlf', 'mass_assignment',
]);

/**
 * Check if a taint flow is sanitized at the target line.
 *
 * Strategy: check for a sanitizer call AT `toLine` only — NOT a range scan
 * between fromLine and toLine. A range scan is intentionally avoided because
 * it was too aggressive: a sanitizer on a *different* variable (e.g.
 * `clean = sanitize(name); sink(name)`) would incorrectly mark the unsanitized
 * path as safe.
 *
 * Checking AT `toLine` is variable-specific: in the propagation chain
 * `from_def → to_def`, if there is a sanitizer at `to_def.line`, the
 * assignment is `to_def.variable = sanitizer(from_def.variable)` — the
 * result variable is the sanitized output and taint should not propagate.
 *
 * Context differentiation via `sinkType`:
 *   Known sink type (e.g. 'sql_injection') — sink-check context; require the
 *     sanitizer to cover that specific type.
 *   Unknown / source type (e.g. 'request_param') — propagation context; accept
 *     any recognised sanitizer, since the eventual sink type is not yet known.
 *     This may miss cross-type scenarios (XSS sanitizer applied to data that
 *     later flows to a SQL sink) but eliminates false positives for correctly
 *     sanitized code.
 */
function readBalancedArg(text: string, openParen: number): string | null {
  let depth = 0;
  let quote: '"' | "'" | null = null;
  let escaped = false;
  for (let i = openParen; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (escaped) { escaped = false; continue; }
      if (c === '\\') { escaped = true; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '(') depth++;
    else if (c === ')') {
      depth--;
      if (depth === 0) return text.slice(openParen + 1, i);
    }
  }
  return null;
}

interface SanitizerCallRef {
  receiver?: string;
  methodName: string;
}

function sanitizerCallRefs(sanitizers: TaintSanitizer[], sinkType: string): SanitizerCallRef[] {
  const refs: SanitizerCallRef[] = [];
  for (const san of sanitizers) {
    if (!sanitizerCoversSink(san, sinkType)) continue;
    const m = /(?:(\w+)\.)?(\w+)\(\)/.exec(san.method);
    if (!m?.[2]) continue;
    refs.push({ receiver: m[1], methodName: m[2] });
  }
  return refs;
}

function maskSanitizerCalls(expr: string, refs: SanitizerCallRef[]): string {
  let out = expr;
  for (const ref of refs) {
    const needles = ref.receiver
      ? [`${ref.receiver}.${ref.methodName}`, ref.methodName]
      : [ref.methodName];
    for (const needle of needles) {
      const re = new RegExp(`\\b${needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\(`);
      for (let guard = 0; guard < 8; guard++) {
        const m = re.exec(out);
        if (!m) break;
        const open = m.index + m[0].length - 1;
        const arg = readBalancedArg(out, open);
        if (arg === null) break;
        out = out.slice(0, m.index) + ' ' + out.slice(open + arg.length + 2);
      }
    }
  }
  return out;
}

function maskLengthOf(expr: string): string {
  return expr
    .replace(/\b(?:len|strlen|count)\s*\(\s*[\w$.]+\s*\)/g, ' 0 ')
    .replace(/[\w$.]+\s*\.\s*(?:length|size|count)\s*(?:\(\s*\))?(?![\w$(])/g, ' 0 ');
}

function blankStringLiterals(expr: string): string {
  return expr
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''");
}

/**
 * True when `variable` still appears in a sink-call argument after covering
 * sanitizer calls on that line are removed (cognium-dev#641).
 *
 * `println(escapeHtml4(a) + b)` keeps `b`. `escapeHtml4(a) + escapeHtml4(b)`
 * keeps nothing. The sanitizer call itself is skipped, so its own argument
 * is not a raw operand.
 */
export function identifierOutsideSanitizerCalls(
  variable: string,
  calls: CallInfo[],
  sanitizers: TaintSanitizer[],
  sinkType: string,
): boolean {
  if (!/^[A-Za-z_$][\w$]*$/.test(variable)) return false;
  const refs = sanitizerCallRefs(sanitizers, sinkType);
  if (refs.length === 0) return false;
  const re = new RegExp(
    `(?:^|[^A-Za-z0-9_$])${variable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:[^A-Za-z0-9_$]|$)`,
  );
  for (const call of calls) {
    if (refs.some(r => r.methodName === call.method_name)) continue;
    // A same-line guard (`IsLocalUrl(next); Redirect(next)`) is not a
    // partial wrap. Only a call with an argument that itself contains the
    // sanitizer call can leave a raw operand: in that argument, or in a
    // sibling argument of the same call (`Printf("%s %s", clean(a), b)`).
    const masked = call.arguments.map(arg => {
      const expr = arg.expression ?? '';
      return { expr, masked: expr ? maskSanitizerCalls(expr, refs) : expr };
    });
    if (!masked.some(m => m.masked !== m.expr)) continue;
    for (const m of masked) {
      if (!m.masked) continue;
      // A sibling that passes only the value's length (`len(s)`,
      // `s.length()`, `s.size()`) carries no attacker-controlled text.
      const text = m.masked === m.expr ? maskLengthOf(m.masked) : m.masked;
      if (re.test(blankStringLiterals(text))) return true;
    }
  }
  return false;
}

function checkSanitized(
  fromLine: number,
  toLine: number,
  sinkType: string,
  sanitizersByLine: Map<number, TaintSanitizer[]>,
  ctx?: SanitizerCheckCtx
): { sanitized: boolean; sanitizer?: TaintSanitizer } {
  const isKnownSinkType = KNOWN_SINK_TYPES.has(sinkType);

  // Per-line fast path — preserves 3.154.0 semantics for site #1 (propagation
  // hop check) and site #3 (interprocedural fallback), and remains the primary
  // hit for site #2 whenever the sanitizer lives at the sink line itself.
  const sanitizersAtTarget = sanitizersByLine.get(toLine);
  if (sanitizersAtTarget && sanitizersAtTarget.length > 0) {
    for (const san of sanitizersAtTarget) {
      if (isKnownSinkType) {
        // H8 (#254 3.171.0): Set-backed lookup — O(1) after first call.
        if (sanitizerCoversSink(san, sinkType)) {
          return { sanitized: true, sanitizer: san };
        }
      } else if (san.sanitizes.length > 0) {
        return { sanitized: true, sanitizer: san };
      }
    }
  }

  // cognium-dev #238 — widen the search to the transitive reaching-def chain
  // of the tainted use. Only fires when the caller opts in via `ctx` (site #2
  // sink-reachability check). Cycle-safe + bounded via walkBackwardDefs.
  //
  // cognium-dev #249 3.162.0 — bound sanitizer credit to lines >= fromLine.
  // When a re-taint source (e.g. `URLDecoder.decode` on a previously-encoded
  // value) sits between an upstream sanitizer and the sink, the backward
  // reaching-def walk crosses through the re-taint source. Sanitizers on
  // lines strictly before the current taint's origin cannot cover the
  // freshly re-introduced taint (SecuriBench Micro `sanitizers/Sanitizers5.java`
  // encode-then-decode bypass). The upper hop cap already bounds the walk;
  // this lower bound closes the semantic gap without affecting the classical
  // `safe = escape(x); sink(safe)` credit path (that sanitizer is at
  // `fromLine == taintInfo.line`, which the `>=` check preserves).
  if (ctx) {
    const walk = walkBackwardDefs(
      ctx.startDefId,
      ctx.chainsByToDef,
      ctx.defById,
      { maxHops: ctx.maxHops ?? 32 }
    );
    for (const line of walk.lines) {
      if (line === toLine) continue; // already checked above
      if (line < fromLine) continue; // upstream of the current taint's origin
      const sansAtLine = sanitizersByLine.get(line);
      if (!sansAtLine || sansAtLine.length === 0) continue;
      for (const san of sansAtLine) {
        if (isKnownSinkType) {
          // H8 (#254 3.171.0): Set-backed lookup — O(1) after first call.
          if (sanitizerCoversSink(san, sinkType)) {
            return { sanitized: true, sanitizer: san };
          }
        } else if (san.sanitizes.length > 0) {
          return { sanitized: true, sanitizer: san };
        }
      }
    }
  }

  return { sanitized: false };
}

/**
 * Build a taint flow path from source to sink.
 */
function buildTaintFlow(
  source: TaintSource,
  sink: TaintSink,
  taintInfo: TaintedVariable
): TaintFlow {
  const path: TaintFlowStep[] = [];

  // Start with source.
  //
  // Label this step with the SOURCE's own variable, not the propagated one.
  // Using `taintInfo.variable` here named the sink-side variable at the
  // source's line — for `void Run(string input) { var v = input; … sink(v); }`
  // the first step read `v@4`, a variable that does not exist on line 4.
  //
  // That is not only wrong in rendered output: `TaintPropagationPass` runs
  // every path step through the const-prop FP check, so the check was asked
  // "is `v` tainted at line 4?" instead of "is `input` tainted at line 4?".
  // For a reassigned local const-prop tracks but never marks tainted (its
  // intra-procedural seeding does not model `interprocedural_param`), the
  // answer suppressed a real flow. Same class as the two FN regressions
  // already recorded on that check — cognium-dev#77 (JS) and #104 (OOP field
  // paths) — with the fix here at the mislabelled input rather than by
  // weakening the guard. cognium-dev#287.
  path.push({
    variable: source.variable ?? taintInfo.variable,
    line: source.line,
    type: 'source',
    description: `Tainted data enters via ${source.type}`,
  });

  // Add intermediate assignments if we can trace them
  // For now, just add the tainted variable assignment
  if (taintInfo.line !== source.line) {
    path.push({
      variable: taintInfo.variable,
      line: taintInfo.line,
      type: 'assignment',
      description: `Tainted value assigned to ${taintInfo.variable}`,
    });
  }

  // End with sink
  path.push({
    variable: taintInfo.variable,
    line: sink.line,
    type: 'sink',
    description: `Tainted value reaches ${sink.type} sink`,
  });

  return {
    source,
    sink,
    path,
    sanitized: false,
    confidence: taintInfo.confidence * 0.9, // Factor in path length
  };
}

/**
 * Analyze method returns to propagate taint through return values.
 */
export function analyzeMethodReturns(
  dfg: DFG,
  calls: CallInfo[],
  taintedVars: TaintedVariable[]
): TaintedVariable[] {
  const additionalTaint: TaintedVariable[] = [];
  const taintedDefIds = new Set(taintedVars.map(t => t.defId));

  // Find return statements that return tainted values
  const returnDefs = dfg.defs.filter(d => d.kind === 'return');

  // For each return def, check if the returned value is tainted
  for (const returnDef of returnDefs) {
    // Find uses on the same line that might be the returned value
    const usesOnLine = dfg.uses.filter(u => u.line === returnDef.line);

    for (const use of usesOnLine) {
      if (use.def_id !== null && taintedDefIds.has(use.def_id)) {
        // This return statement returns a tainted value
        // Now find calls to this method and taint their results
        // (This would require method-level analysis which we'll add later)
      }
    }
  }

  return additionalTaint;
}

/**
 * Calculate confidence score for a taint flow.
 */
export function calculateFlowConfidence(flow: TaintFlow): number {
  let confidence = 1.0;

  // Factor 1: Source confidence
  confidence *= flow.source.confidence;

  // Factor 2: Path length (longer paths = less confident)
  const pathLength = flow.path.length;
  confidence *= Math.pow(0.95, pathLength - 2); // -2 for source and sink

  // Factor 3: Sanitization
  if (flow.sanitized) {
    confidence = 0;
  }

  return Math.max(0, Math.min(1, confidence));
}

/**
 * Get summary statistics for taint propagation.
 */
export function getTaintStats(result: TaintPropagationResult): {
  totalTaintedVars: number;
  totalFlows: number;
  flowsBySinkType: Map<string, number>;
  avgConfidence: number;
} {
  const flowsBySinkType = new Map<string, number>();

  for (const flow of result.flows) {
    const count = flowsBySinkType.get(flow.sink.type) ?? 0;
    flowsBySinkType.set(flow.sink.type, count + 1);
  }

  const avgConfidence = result.flows.length > 0
    ? result.flows.reduce((sum, f) => sum + f.confidence, 0) / result.flows.length
    : 0;

  return {
    totalTaintedVars: result.taintedVars.length,
    totalFlows: result.flows.length,
    flowsBySinkType,
    avgConfidence,
  };
}
