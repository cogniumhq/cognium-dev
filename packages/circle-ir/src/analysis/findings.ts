/**
 * Finding generator
 *
 * Combines taint sources, sinks, and data flow analysis to generate
 * vulnerability findings with paths and remediation suggestions.
 */

import type {
  TaintSource,
  TaintSink,
  TaintSanitizer,
  DFG,
  DFGDef,
  DFGUse,
  DFGChain,
  Finding,
  TaintHop,
  SinkType,
  TypeInfo,
  TaintFlowInfo,
} from '../types/index.js';
import {
  calculateSeverity as calcSeverity,
  getRemediation,
  getSourceDescription,
  getSinkDescription,
} from './rules.js';
import { isNonExecutableSourceLine } from './non-executable-lines.js';
import { sanitizerCoversSink } from './sanitizer-index.js';
import { walkBackwardDefs } from './dfg-walk.js';

/**
 * Generate vulnerability findings from taint analysis results.
 *
 * cognium-dev#250 — When `sourceCode` and `language` are supplied,
 * candidate sources whose `line` points at an import/package/comment/
 * annotation-only/const-literal-declaration line are dropped before
 * pair emission. This is a defense-in-depth gate against fabricated
 * flows introduced upstream (LLM enrichment hallucinations or
 * detector regressions). Both parameters are optional to preserve
 * backward compatibility with pre-3.165 callers.
 */
export function generateFindings(
  sources: TaintSource[],
  sinks: TaintSink[],
  dfg: DFG,
  fileName: string,
  sourceCode?: string,
  language?: string,
  sanitizers: TaintSanitizer[] = [],
  types: TypeInfo[] = [],
  flowsArg?: TaintFlowInfo[],
): Finding[] {
  const flows = flowsArg ?? [];
  const findings: Finding[] = [];
  // cognium-dev#361 — method ranges for the proximity gate below. Optional and
  // trailing: a caller that does not pass `types` keeps the pre-existing
  // line-window behaviour exactly.
  // cognium-dev#387 — sink-level flow backing. `generateFindings` accepts a
  // pair on a DFG path OR the proximity fallback, while the taint layer's flow
  // builders refuse most of those pairs; measured on OWASP Benchmark Java,
  // 2800 flow rows against 8801 findings rows, 75.4% of findings with no flow
  // reaching the same sink. Recording which side a finding falls on is the
  // cheapest way to let a consumer rank on proven detections, and it is pure
  // metadata: no finding is added, removed, re-severitied or re-ordered.
  //
  // Keyed on (sink_type, sink_line), NOT the source line: a finding whose
  // source was re-attributed by #361/#372 is still the same proven detection.
  const flowBackedSinks = new Set<string>();
  for (const fl of flows) {
    if (typeof fl.sink_line === 'number') flowBackedSinks.add(`${fl.sink_type}@${fl.sink_line}`);
  }
  // `flows` is an optional trailing parameter, so distinguish "no flow reaches
  // this sink" from "the caller never gave us flows to check against". Keyed on
  // whether the argument was PASSED, not on its length: an empty array is the
  // taint layer saying it proved nothing in this file, which is exactly where
  // unbacked pairings concentrate — those must read `false`, not "unknown".
  const flowsKnown = flowsArg !== undefined;
  const isFlowBacked = (t: string, line: number): boolean | undefined =>
    flowsKnown ? flowBackedSinks.has(`${t}@${line}`) : undefined;

  const methodRanges = buildMethodRanges(types);
  const fieldNames = buildFieldNames(types);
  let findingId = 1;

  // cognium-dev: sanitizer-awareness for the scan path. Historically
  // `generateFindings` did its own source→sink DFG path-finding and ignored the
  // pass-level `TaintSanitizer`s that `taint.flows` honors — so a guarded value
  // that `taint.flows` correctly suppressed still surfaced here (the scan path
  // downstream consumers build reports from). This mirrors the two
  // `taint-propagation-pass` filter tiers. Backward-compatible: callers that
  // pass no `sanitizers` get the pre-existing behavior.
  const sanitizersByLine = new Map<number, TaintSanitizer[]>();
  for (const san of sanitizers) {
    const arr = sanitizersByLine.get(san.line) ?? [];
    arr.push(san);
    sanitizersByLine.set(san.line, arr);
  }
  // Reaching-def indexes for the DFG-walk tier, built from the `dfg` argument.
  const defById = new Map<number, DFGDef>();
  const chainsByToDef = new Map<number, DFGChain[]>();
  const usesByLine = new Map<number, DFGUse[]>();
  if (sanitizers.length > 0) {
    for (const d of dfg.defs) defById.set(d.id, d);
    for (const c of dfg.chains ?? []) {
      const arr = chainsByToDef.get(c.to_def) ?? [];
      arr.push(c);
      chainsByToDef.set(c.to_def, arr);
    }
    for (const u of dfg.uses) {
      const arr = usesByLine.get(u.line) ?? [];
      arr.push(u);
      usesByLine.set(u.line, arr);
    }
  }
  const lineCoversSink = (line: number, sinkType: SinkType): boolean => {
    const sans = sanitizersByLine.get(line);
    if (!sans) return false;
    for (const san of sans) if (sanitizerCoversSink(san, sinkType)) return true;
    return false;
  };
  const isPairSanitized = (
    source: TaintSource,
    sink: TaintSink,
    pathResult: PathResult,
  ): boolean => {
    if (sanitizers.length === 0) return false;
    // Tier 1 — a sanitizer AT the sink line covering the sink type.
    if (lineCoversSink(sink.line, sink.type)) return true;
    // Tier 2 — DFG reaching-def walk: a sanitizer on a def line feeding the
    // sink's tainted variable, bounded to `[source.line, sink.line)`. Mirrors
    // the taint-propagation-pass DFG-walk credit (the `n = sanitize(x); sink(n)`
    // shape where the sanitizer is on the assignment line, not the sink line).
    const sinkVar = pathResult.hops.length > 0
      ? pathResult.hops[pathResult.hops.length - 1].variable
      : undefined;
    for (const use of usesByLine.get(sink.line) ?? []) {
      if (sinkVar && use.variable !== sinkVar) continue;
      if (use.def_id === null || use.def_id === undefined) continue;
      const walk = walkBackwardDefs(use.def_id, chainsByToDef, defById, { maxHops: 32 });
      for (const line of walk.lines) {
        if (line === sink.line || line < source.line) continue;
        if (lineCoversSink(line, sink.type)) return true;
      }
    }
    return false;
  };

  // cognium-dev#250 — drop sources whose line is provably non-executable
  // (import, package, comment, annotation-only, const-with-literal).
  // No-op when `sourceCode` / `language` aren't supplied (legacy callers).
  const gatedSources = (sourceCode && language)
    ? sources.filter(s => !isNonExecutableSourceLine(sourceCode, s.line, language))
    : sources;

  // For each source, find potential paths to sinks
  for (const source of gatedSources) {
    for (const sink of sinks) {
      // Check if this source type can reach this sink type
      if (!canSourceReachSink(source.type, sink.type)) {
        continue;
      }

      // Try to find a path through the DFG
      const pathResult = findTaintPath(source, sink, dfg);

      if (pathResult.pathExists || isProximityVulnerability(source, sink, methodRanges, fieldNames)) {
        // Drop the pair when a sanitizer covers the sink (at the sink line, or
        // on a reaching-def line feeding the sink var) — aligns the scan path
        // with taint.flows. No-op when the caller passed no sanitizers.
        if (isPairSanitized(source, sink, pathResult)) {
          continue;
        }
        // cognium-dev #281 — thread `confidence` into the severity rules.
        // `calculateSeverity` accepts it and gates two escalations on
        // `confidence > 0.8`, but this call site never passed it, so it always
        // fell back to the 0.5 default and neither rule could fire. The
        // practical consequence was that every HIGH_SINKS type (`xss`,
        // `path_traversal`, `xxe`, `ssrf`, `ldap_injection`, `xpath_injection`)
        // was structurally incapable of being rated `high` on this path — it
        // capped at `medium` no matter how strong the evidence.
        //
        // The value was already being computed one statement below; only the
        // order changed. Note this is monotonic: every confidence gate is a
        // `> 0.8` escalation placed ahead of the lower fallbacks, and no rule
        // tests for LOW confidence, so threading it can raise a severity but
        // never lower one, and the finding SET is untouched.
        const confidence = calculateConfidence(source, sink, pathResult);
        const severity = calcSeverity({
          sourceType: source.type,
          sinkType: sink.type,
          pathExists: pathResult.pathExists,
          confidence,
        });

        findings.push({
          id: `vuln${findingId++}`,
          type: sink.type,
          cwe: sink.cwe,
          severity,
          confidence,
          // #134: canonical "go-to-line" coordinate. For taint findings
          // this is the sink line (primary actionable location).
          line: sink.line,
          source: {
            type: source.type,
            file: fileName,
            line: source.line,
            code: source.location,
          },
          sink: {
            type: sink.type,
            file: fileName,
            line: sink.line,
            code: sink.location,
          },
          path: pathResult.hops.length > 0 ? pathResult.hops : undefined,
          exploitable: pathResult.pathExists && confidence > 0.7,
          explanation: generateExplanation(source, sink, pathResult),
          remediation: getRemediation(sink.type),
          verification: {
            graph_path_exists: pathResult.pathExists,
            flow_backed: isFlowBacked(sink.type, sink.line),
            llm_verified: false,
            llm_confidence: 0,
            discoveryMethod: computeDiscoveryMethod(source, sink),
          },
        });
      }
    }
  }

  // cognium-dev#372 — emit findings for DFG-backed flows the source x sink
  // pairing cannot reach.
  //
  // That loop iterates `sources`, and that list is not always the one
  // `taint.flows` used. Measured on BenchmarkTest01193.py:
  //
  //     taint.sources = [interprocedural_param@21]   <- init()'s `app` param
  //     taint.flows   = [http_param@42->45]          <- the real source
  //
  // So the only pair formable was 21 -> 45: right sink, wrong source, credited
  // purely by the 50-line proximity window. Scoping proximity to the enclosing
  // method (#361) correctly rejects that pair — and the finding then vanished
  // instead of being re-attributed, because the real line-42 source is absent
  // from `sources`. Measured cost of that alone: 433 file-level true positives
  // (OWASP 305, BenchmarkPython 125, SecuriBench 3).
  //
  // A flow is the stronger signal: DFG-backed, already sanitizer-checked by the
  // propagation layer, and carrying the correct source line. Pushed BEFORE the
  // grouping below so it merges with any pair on the same (sink line, type) —
  // and since the grouping keeps the highest-confidence source, a flow's
  // correct attribution wins over a proximity guess rather than duplicating it.
  for (const fl of flows) {
    if (fl.sanitized) continue;
    const sink = sinks.find(sk => sk.line === fl.sink_line && sk.type === fl.sink_type);
    if (!sink) continue;
    const src = sources.find(sc => sc.line === fl.source_line)
      ?? { type: fl.source_type, location: `${fl.source_type} at line ${fl.source_line}`,
           severity: 'high' as const, line: fl.source_line, confidence: fl.confidence };
    const hops = (fl.path ?? []).map(st => ({ variable: st.variable, line: st.line, type: st.type }));
    // PathResult needs `variables` too — `generateExplanation` reads it.
    const pathResult: PathResult = {
      pathExists: true,
      hops: hops as never[],
      variables: (fl.path ?? []).map(st => st.variable).filter(Boolean),
    };
    findings.push({
      id: `vuln${findingId++}`,
      type: sink.type,
      cwe: sink.cwe,
      severity: calcSeverity({
        sourceType: fl.source_type,
        sinkType: fl.sink_type,
        pathExists: true,
        confidence: fl.confidence,
      }),
      confidence: fl.confidence,
      line: sink.line,
      source: { type: fl.source_type, file: fileName, line: fl.source_line, code: src.location },
      sink: { type: sink.type, file: fileName, line: sink.line, code: sink.location },
      path: hops.length > 0 ? (hops as never[]) : undefined,
      exploitable: fl.confidence > 0.7,
      explanation: generateExplanation(src as TaintSource, sink, pathResult),
      remediation: getRemediation(sink.type),
      verification: {
        graph_path_exists: true,
        // #387 — derived FROM a flow by construction, so backed by definition.
        flow_backed: true,
        llm_verified: false,
        llm_confidence: 0,
        discoveryMethod: computeDiscoveryMethod(src as TaintSource, sink),
      },
      ...(fl.tags && fl.tags.length > 0 ? { tags: fl.tags } : {}),
    } as Finding);
  }

  // Deduplicate: group by (sink.line, type), keep highest confidence,
  // aggregate all contributing sources into evidence
  const grouped = new Map<string, Finding>();
  for (const f of findings) {
    const key = `${f.sink.line}:${f.type}`;
    const existing = grouped.get(key);
    if (!existing) {
      f.evidence = {
        ...f.evidence,
        sources: [{ file: f.source.file, line: f.source.line }],
      };
      grouped.set(key, f);
    } else {
      const sources = ((existing.evidence?.sources as Array<{ file: string; line: number }>) ?? []);
      sources.push({ file: f.source.file, line: f.source.line });
      existing.evidence = { ...existing.evidence, sources };
      const mergedDiscovery = mergeDiscoveryMethod(
        existing.verification.discoveryMethod,
        f.verification.discoveryMethod,
      );
      if (f.confidence > existing.confidence) {
        existing.confidence = f.confidence;
        existing.source = f.source;
        existing.path = f.path;
        existing.explanation = f.explanation;
        existing.verification = f.verification;
        existing.exploitable = f.exploitable;
        existing.severity = f.severity;
      }
      existing.verification.discoveryMethod = mergedDiscovery;
    }
  }

  const deduped = Array.from(grouped.values());

  // Sort by severity and confidence
  deduped.sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
    if (severityDiff !== 0) return severityDiff;
    return b.confidence - a.confidence;
  });

  return deduped;
}

/**
 * Compute the provenance label for a finding from its contributing
 * source and sink. Absent `discoveryMethod` on an input is treated as
 * `'static'` (preserves pre-3.45.0 behavior for callers that don't tag
 * their inputs).
 */
function computeDiscoveryMethod(
  source: TaintSource,
  sink: TaintSink,
): 'static' | 'llm' | 'mixed' {
  const src = source.discoveryMethod ?? 'static';
  const snk = sink.discoveryMethod ?? 'static';
  if (src === snk) return src;
  return 'mixed';
}

/**
 * Combine two finding-level discoveryMethod values during dedup. Any
 * disagreement (including 'mixed' meeting either base label) collapses
 * to 'mixed'; identical labels are preserved.
 */
function mergeDiscoveryMethod(
  a: 'static' | 'llm' | 'mixed' | undefined,
  b: 'static' | 'llm' | 'mixed' | undefined,
): 'static' | 'llm' | 'mixed' {
  const left = a ?? 'static';
  const right = b ?? 'static';
  if (left === right) return left;
  return 'mixed';
}

/**
 * Check if a source type can potentially reach a sink type.
 *
 * Exported so detection passes (e.g. `detectExpressionScanFlows` in
 * `taint-propagation-pass.ts`) can gate emit-time flows on the same
 * source-to-sink coverage matrix that `generateFindings` uses below.
 */
export function canSourceReachSink(sourceType: string, sinkType: SinkType): boolean {
  const sourceToSinkMapping: Record<string, SinkType[]> = {
    // code_injection added to http_param/http_query/http_header/http_cookie:
    // `eval(req.query.x)`, `Function(req.header('x'))`, `vm.runInThisContext(req.cookies.c)`
    // are all real RCE patterns in JS web apps (cognium-dev #83).
    // crlf added to http_param/http_query/http_header/http_cookie/http_body:
    // setHeader/setCookie/redirect of any user-controlled string is CRLF / response
    // splitting (CWE-113) — Sprint 6, issue #86.
    // mass_assignment added to http_body / http_param: Object.assign(user, req.body),
    // User(**request.form) — CWE-915.
    // open_redirect added to http_param/http_query/http_header/http_cookie/http_body/http_path
    // Sprint 82 (#189): a user-controlled value reaching res.sendRedirect /
    // res.redirect / Location header / append_header(("Location", x)) /
    // Header().Set("Location", x) IS open_redirect (CWE-601). The reach map
    // previously omitted open_redirect so the inline-colocation flow detector
    // silently skipped all `http_* → open_redirect` co-located flows
    // (java sendRedirect, JS res.redirect, Rust append_header tuple, etc.).
    // trust_boundary added Sprint 91 (#117): a user-controlled value reaching
    // HttpSession.setAttribute / ServletContext.setAttribute /
    // HttpServletRequest.setAttribute IS a Trust Boundary Violation (CWE-501).
    // The reach map previously omitted trust_boundary so the inline-colocation
    // flow detector silently dropped `http_* → trust_boundary` co-located
    // flows like `req.getSession().setAttribute("u", req.getParameter("u"))`
    // (0% recall on OWASP Java trustbound category).
    // deserialization added Sprint 93 (#189): SnakeYAML/Jackson/etc. sinks
    // like `new Yaml().load(req.getParameter("y"))` are real RCE gadget chains
    // (CWE-502). The reach map previously restricted deserialization to
    // http_body so http_param/http_query request-derived values feeding
    // Yaml.load, ObjectInputStream ctor, XMLDecoder ctor, etc. silently
    // dropped their inline-colocation flow. Typed-overload FPs are gated by
    // the sink pattern's `safe_if_class_literal_at` flag (Jackson readValue,
    // Yaml.loadAs, Gson.fromJson) so the wider reach does not regress.
    // log_injection / format_string / nosql_injection added (cognium-ai#129):
    // these families were absent from the whole reach map, so `generateFindings`
    // (and the colocation flow detector that shares this predicate) dropped
    // every `http_* → {log_injection,format_string,nosql_injection}` flow even
    // though `taint.flows` already validated reachability — the two paths
    // disagreed. log_injection (CWE-117) and format_string (CWE-134) are
    // reachable from any user-controlled value that is logged / used as a
    // format string; nosql_injection (CWE-943) mirrors sql_injection's sources.
    // prompt_injection (CWE-1427 / OWASP LLM01) added cognium-ai#281: an
    // attacker-controlled value reaching an LLM prompt sink (CreateChatCompletion
    // et al.) is prompt injection. The reach map omitted it entirely, so the
    // scan path (`generateFindings`) dropped every `http_*/io/network/interproc →
    // prompt_injection` flow even though `taint.flows` / the trust pass reported
    // it — the same "two paths disagree" shape as #129. Now emitted from scan too.
    // xxe added (cognium-dev #282): `request.getParameter("xml")` reaching an
    // XML parser (DocumentBuilder.parse etc.) is XXE, but xxe was absent from
    // http_param/http_query (present on http_body/io_input/file_input), so the
    // pairing was gated out and generateFindings dropped it — same class as the
    // #129 log_injection/format_string/nosql_injection drop. Mirrors how
    // deserialization already sits on both http_param and http_query.
    http_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'xpath_injection', 'ldap_injection', 'ssrf', 'mybatis_mapper_call', 'code_injection', 'crlf', 'mass_assignment', 'open_redirect', 'trust_boundary', 'deserialization', 'xxe', 'log_injection', 'format_string', 'nosql_injection', 'prompt_injection'],
    http_body: ['sql_injection', 'command_injection', 'deserialization', 'xxe', 'xss', 'code_injection', 'mybatis_mapper_call', 'crlf', 'mass_assignment', 'open_redirect', 'trust_boundary', 'log_injection', 'format_string', 'nosql_injection', 'prompt_injection'],
    http_header: ['sql_injection', 'xss', 'ssrf', 'mybatis_mapper_call', 'code_injection', 'crlf', 'open_redirect', 'trust_boundary', 'log_injection', 'format_string', 'nosql_injection', 'prompt_injection'],
    http_cookie: ['sql_injection', 'xss', 'mybatis_mapper_call', 'code_injection', 'crlf', 'open_redirect', 'trust_boundary', 'log_injection', 'format_string', 'nosql_injection', 'prompt_injection'],
    // xss added cognium-dev 3.163.0: URL path components (getRequestURI,
    // getRequestURL, getPathInfo, getServletPath) reflected back into HTML
    // output are a classic reflected-XSS vector — cf. Basic35 in
    // SecuriBench Micro where `writer.println(req.getRequestURL())` is
    // annotated `/* BAD */`. Prior to 3.163.0 the reach map omitted xss
    // so http_path → xss inline-colocation flows were silently dropped.
    http_path: ['path_traversal', 'sql_injection', 'ssrf', 'mybatis_mapper_call', 'open_redirect', 'trust_boundary', 'xss', 'log_injection', 'format_string', 'prompt_injection'],
    http_query: ['sql_injection', 'command_injection', 'xss', 'ssrf', 'mybatis_mapper_call', 'code_injection', 'crlf', 'mass_assignment', 'open_redirect', 'trust_boundary', 'deserialization', 'xxe', 'log_injection', 'format_string', 'nosql_injection', 'prompt_injection'],
    // ssrf added Sprint 57 #200: bash CGI/webhook handlers and scripts that
    // take a URL on stdin or as a positional CLI arg (`curl "$1"`,
    // `wget "$(read line)"`) and curl/wget it server-side are textbook SSRF
    // (CVE-2022-41040 ProxyShell-class). Cross-language: `socket.urlopen(input())`
    // (Python), `axios.get(readline())` (JS) etc. also benefit.
    io_input: ['command_injection', 'path_traversal', 'deserialization', 'xxe', 'code_injection', 'xss', 'ssrf', 'log_injection', 'format_string', 'prompt_injection'],
    env_input: ['command_injection', 'path_traversal'],
    db_input: ['xss', 'sql_injection', 'log_injection'], // Second-order injection
    file_input: ['deserialization', 'xxe', 'path_traversal', 'command_injection', 'code_injection'],
    network_input: ['sql_injection', 'command_injection', 'xss', 'ssrf', 'log_injection', 'format_string', 'nosql_injection', 'prompt_injection'],
    config_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'ssrf', 'log_injection', 'format_string'], // Servlet init params
    interprocedural_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'xpath_injection', 'ldap_injection', 'ssrf', 'code_injection', 'mybatis_mapper_call', 'crlf', 'mass_assignment', 'open_redirect', 'trust_boundary', 'log_injection', 'format_string', 'nosql_injection', 'prompt_injection', 'xxe', 'deserialization'], // Cross-method taint; Sprint 82 (#189) — open_redirect added; Sprint 91 (#117) — trust_boundary added; cognium-ai#129 — log_injection/format_string/nosql_injection added; cognium-ai#281 — prompt_injection added; cognium-ai#317 — xxe/deserialization added (C# xxe/deser sinks are reached via param-seeded sources and were silently dropped, 0% finding conversion)
    plugin_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'code_injection', 'log_injection', 'format_string'], // Plugin/config parameters
  };

  const validSinks = sourceToSinkMapping[sourceType];
  return validSinks ? validSinks.includes(sinkType) : false;
}

/**
 * Source-semantics gate (cognium-dev #138).
 *
 * Consumed by `taint-propagation-pass.ts` (both colocation and
 * variable-scan flow generators) to drop flows whose source has been
 * tagged as a compile-time constant or an SPI-loaded value by
 * `SourceSemanticsPass`. The `demoPath` tag is deliberately NOT
 * consumed here — it is used by `scan-secrets-pass.ts` to downgrade
 * hardcoded-credential severity but never to drop flows.
 *
 * Policy (hardcoded per-sink allowlist):
 *   - `source.constant === true`  → drop for every taint sink type.
 *     Compile-time constants cannot carry attacker-controlled data,
 *     so no taint flow is possible. Hardcoded-credential emission
 *     happens in `scan-secrets-pass` and does not go through this
 *     predicate, so it is unaffected.
 *   - `source.spi === true`       → drop for every sink EXCEPT
 *     `code_injection`. Stage 9f in `sink-filter-pass.ts` already
 *     downgrades `Class.forName(spiLoaded)` to a library-API-surface
 *     tag; dropping again here would double-suppress real reflection
 *     bugs.
 *   - No relevant tags set        → allowed (default is to preserve
 *     the flow — this predicate is a subtractive gate only).
 *
 * The predicate must be called AFTER `canSourceReachSink` (which is
 * the coarse sink-type reachability check). Both must pass for the
 * flow to be emitted.
 */
export function sourceSemanticsAllowed(
  source: { constant?: boolean; spi?: boolean },
  sinkType: SinkType,
): boolean {
  if (source.constant === true) {
    // Compile-time constants cannot carry attacker input.
    return false;
  }
  if (source.spi === true) {
    // SPI-loaded values are provider-controlled configuration, not
    // attacker-controlled input. `code_injection` is preserved so
    // Stage 9f's library-API-surface downgrade remains the single
    // decision point for reflection-based RCE.
    return sinkType === 'code_injection';
  }
  return true;
}

interface PathResult {
  pathExists: boolean;
  hops: TaintHop[];
  variables: string[];
}

/**
 * Find a taint path from source to sink through the DFG.
 */
function findTaintPath(source: TaintSource, sink: TaintSink, dfg: DFG): PathResult {
  const hops: TaintHop[] = [];
  const variables: string[] = [];

  // Find definitions near the source line
  const sourceDefs = dfg.defs.filter(d =>
    d.line >= source.line - 1 && d.line <= source.line + 1
  );

  // Find uses near the sink line
  const sinkUses = dfg.uses.filter(u =>
    u.line >= sink.line - 1 && u.line <= sink.line + 1
  );

  if (sourceDefs.length === 0 || sinkUses.length === 0) {
    return { pathExists: false, hops: [], variables: [] };
  }

  // Use DFG chains to find path
  const chains = dfg.chains ?? [];

  // Try to find a path from any source def to any sink use
  for (const sourceDef of sourceDefs) {
    for (const sinkUse of sinkUses) {
      const path = findPathThroughChains(sourceDef.id, sinkUse.def_id, chains, dfg);
      if (path.length > 0) {
        // Build hops from path
        for (const defId of path) {
          const def = dfg.defs.find(d => d.id === defId);
          if (def) {
            hops.push({
              file: '', // Will be filled by caller
              method: '',
              line: def.line,
              code: `${def.variable} = ...`,
              variable: def.variable,
            });
            variables.push(def.variable);
          }
        }

        return { pathExists: true, hops, variables };
      }
    }
  }

  // Fallback: check for simple proximity-based path
  // If source and sink are close, there might be a direct flow
  if (Math.abs(source.line - sink.line) <= 10) {
    // Look for common variables
    const sourceVars = new Set(sourceDefs.map(d => d.variable));
    const sinkVars = new Set(sinkUses.map(u => u.variable));

    for (const v of sourceVars) {
      if (sinkVars.has(v)) {
        hops.push({
          file: '',
          method: '',
          line: source.line,
          code: `${v} = <source>`,
          variable: v,
        });
        hops.push({
          file: '',
          method: '',
          line: sink.line,
          code: `sink(${v})`,
          variable: v,
        });
        variables.push(v);
        return { pathExists: true, hops, variables };
      }
    }
  }

  return { pathExists: false, hops: [], variables: [] };
}

/**
 * Find a path through DFG chains from source def to target def.
 */
function findPathThroughChains(
  fromDefId: number,
  toDefId: number | null,
  chains: DFGChain[],
  dfg: DFG,
  visited: Set<number> = new Set(),
  path: number[] = []
): number[] {
  if (toDefId === null) return [];
  if (fromDefId === toDefId) return [...path, fromDefId];
  if (visited.has(fromDefId)) return [];

  visited.add(fromDefId);
  path.push(fromDefId);

  // Find chains that start from this def
  const outgoingChains = chains.filter(c => c.from_def === fromDefId);

  for (const chain of outgoingChains) {
    const result = findPathThroughChains(chain.to_def, toDefId, chains, dfg, visited, [...path]);
    if (result.length > 0) {
      return result;
    }
  }

  return [];
}

/**
 * Check if source and sink are close enough to suggest vulnerability.
 */
/**
 * Flat list of method line ranges, used to answer "are these two lines in the
 * same method?" without trusting `in_method`, which is populated unevenly:
 * Java sources carry it, Java SINKS do not, and C# carries it on neither
 * (verified on both). `ir.types[].methods[]` has reliable `start_line` /
 * `end_line` for every language that populates `types`.
 */
interface MethodRange { start: number; end: number; key: string }

/**
 * Names of every declared field across the file's types.
 *
 * A source that writes a FIELD is not scoped to the method that writes it —
 * the taint lives on the object, so any other method can read it back. See
 * `isProximityVulnerability` for why that exempts the pair from method
 * scoping entirely.
 */
function buildFieldNames(types: TypeInfo[]): Set<string> {
  const out = new Set<string>();
  for (const t of types ?? []) {
    for (const f of t.fields ?? []) {
      if (f?.name) out.add(f.name);
    }
  }
  return out;
}

function buildMethodRanges(types: TypeInfo[]): MethodRange[] {
  const out: MethodRange[] = [];
  for (const t of types ?? []) {
    for (const m of t.methods ?? []) {
      if (typeof m.start_line !== 'number' || typeof m.end_line !== 'number') continue;
      out.push({ start: m.start_line, end: m.end_line, key: `${t.name}.${m.name}` });
    }
  }
  return out;
}

/** True when at least one known method range contains `line`. */
function anyMethodContains(line: number, ranges: MethodRange[]): boolean {
  return ranges.some((r) => line >= r.start && line <= r.end);
}

/**
 * True when a SINGLE method range contains both lines.
 *
 * Containment, not innermost-method identity: methods nest. A Flask
 * `def init(app)` wraps its route handlers, and a Java/C# local function or
 * lambda body sits inside its declaring method. In every such case the outer
 * range contains both lines and the pair is genuinely reachable, even though
 * the innermost range around each line differs.
 */
function sharedMethod(a: number, b: number, ranges: MethodRange[]): boolean {
  return ranges.some((r) => a >= r.start && a <= r.end && b >= r.start && b <= r.end);
}

/**
 * Proximity fallback for a source/sink pair with no DFG path.
 *
 * cognium-dev#361 — the comment here used to say "within same method" while
 * the code checked only `Math.abs(source.line - sink.line) <= 50`, in EITHER
 * direction. So any source within 50 lines of a type-compatible sink became a
 * finding: across method boundaries, and even when the source appears AFTER
 * the sink. Observed consequence — a `BinaryFormatter.Deserialize` sink in one
 * controller action reported against a `Request.Query` read in the NEXT
 * action, six lines below it.
 *
 * Now the comment is enforced when the information exists: if BOTH lines fall
 * inside some known method and NO single method contains both, the pair is
 * rejected. When either side falls outside every known range — no `types`
 * passed, a top-level script, a language that does not populate `types` — the
 * original line window is used unchanged, so nothing regresses for callers
 * that cannot supply ranges.
 *
 * The test is containment rather than innermost-method identity, because
 * methods nest (BenchmarkPython wraps every route handler in `def init(app)`;
 * local functions and lambdas nest the same way). Comparing innermost methods
 * rejected 63 real detections across 46 files of BenchmarkPython where the
 * source sat on the enclosing function and the sink in a nested handler.
 *
 * Deliberately NOT changed here: the direction. A source below its sink looks
 * wrong, but a field or `interprocedural_param` source legitimately sits
 * outside the method body, and a loop can carry a later line's value back
 * round. Method scoping already rejects the reported case; ordering needs its
 * own evidence.
 */
function isProximityVulnerability(
  source: TaintSource,
  sink: TaintSink,
  methodRanges: MethodRange[] = [],
  fieldNames: Set<string> = new Set(),
): boolean {
  if (Math.abs(source.line - sink.line) > 50) return false;
  // A source that writes a field escapes its writing method by construction,
  // so method scoping must not apply. SecuriBench `Refl2` is the case:
  //
  //   41  protected void doGet(...)          { name = req.getParameter(...); }  // field write
  //   51  private void f(ServletResponse r)  { writer.println(myName); }        // reads it back
  //
  // `doGet` and `f` are disjoint siblings, yet the flow is real (and marked
  // BAD in the corpus) because the taint travels through the field `name`.
  // Rejecting on method boundaries lost this true positive.
  if (source.variable && fieldNames.has(source.variable)) return true;
  if (methodRanges.length > 0) {
    const sourceKnown = anyMethodContains(source.line, methodRanges);
    const sinkKnown = anyMethodContains(sink.line, methodRanges);
    if (sourceKnown && sinkKnown && !sharedMethod(source.line, sink.line, methodRanges)) {
      return false;
    }
  }
  return true;
}


/**
 * Calculate confidence score.
 */
function calculateConfidence(source: TaintSource, sink: TaintSink, pathResult: PathResult): number {
  let confidence = 0.5; // Base confidence

  // Path exists: high confidence
  if (pathResult.pathExists) {
    confidence += 0.3;
  }

  // More hops = more confidence in the path
  if (pathResult.hops.length > 0) {
    confidence += Math.min(pathResult.hops.length * 0.05, 0.1);
  }

  // Source and sink confidence
  confidence = confidence * source.confidence * sink.confidence;

  // Proximity bonus
  const lineDiff = Math.abs(source.line - sink.line);
  if (lineDiff <= 5) {
    confidence += 0.1;
  } else if (lineDiff <= 15) {
    confidence += 0.05;
  }

  return Math.min(confidence, 1.0);
}

/**
 * Generate explanation for the finding.
 */
function generateExplanation(source: TaintSource, sink: TaintSink, pathResult: PathResult): string {
  const sourceDesc = getSourceDescription(source.type);
  const sinkDesc = getSinkDescription(sink.type);

  if (pathResult.pathExists && pathResult.variables.length > 0) {
    const vars = pathResult.variables.join(' -> ');
    return `${sourceDesc} flows through variables (${vars}) to ${sinkDesc} without proper sanitization.`;
  }

  if (pathResult.pathExists) {
    return `${sourceDesc} flows to ${sinkDesc} without proper sanitization.`;
  }

  return `${sourceDesc} may reach ${sinkDesc}. Manual verification recommended.`;
}

