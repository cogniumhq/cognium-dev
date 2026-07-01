/**
 * Finding generator
 *
 * Combines taint sources, sinks, and data flow analysis to generate
 * vulnerability findings with paths and remediation suggestions.
 */

import type {
  TaintSource,
  TaintSink,
  DFG,
  DFGChain,
  Finding,
  TaintHop,
  SinkType,
} from '../types/index.js';
import {
  calculateSeverity as calcSeverity,
  getRemediation,
  getSourceDescription,
  getSinkDescription,
} from './rules.js';

/**
 * Generate vulnerability findings from taint analysis results.
 */
export function generateFindings(
  sources: TaintSource[],
  sinks: TaintSink[],
  dfg: DFG,
  fileName: string
): Finding[] {
  const findings: Finding[] = [];
  let findingId = 1;

  // For each source, find potential paths to sinks
  for (const source of sources) {
    for (const sink of sinks) {
      // Check if this source type can reach this sink type
      if (!canSourceReachSink(source.type, sink.type)) {
        continue;
      }

      // Try to find a path through the DFG
      const pathResult = findTaintPath(source, sink, dfg);

      if (pathResult.pathExists || isProximityVulnerability(source, sink)) {
        const severity = calcSeverity({
          sourceType: source.type,
          sinkType: sink.type,
          pathExists: pathResult.pathExists,
        });
        const confidence = calculateConfidence(source, sink, pathResult);

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
            llm_verified: false,
            llm_confidence: 0,
            discoveryMethod: computeDiscoveryMethod(source, sink),
          },
        });
      }
    }
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
    http_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'xpath_injection', 'ldap_injection', 'ssrf', 'mybatis_mapper_call', 'code_injection', 'crlf', 'mass_assignment', 'open_redirect', 'trust_boundary', 'deserialization'],
    http_body: ['sql_injection', 'command_injection', 'deserialization', 'xxe', 'xss', 'code_injection', 'mybatis_mapper_call', 'crlf', 'mass_assignment', 'open_redirect', 'trust_boundary'],
    http_header: ['sql_injection', 'xss', 'ssrf', 'mybatis_mapper_call', 'code_injection', 'crlf', 'open_redirect', 'trust_boundary'],
    http_cookie: ['sql_injection', 'xss', 'mybatis_mapper_call', 'code_injection', 'crlf', 'open_redirect', 'trust_boundary'],
    http_path: ['path_traversal', 'sql_injection', 'ssrf', 'mybatis_mapper_call', 'open_redirect', 'trust_boundary'],
    http_query: ['sql_injection', 'command_injection', 'xss', 'ssrf', 'mybatis_mapper_call', 'code_injection', 'crlf', 'mass_assignment', 'open_redirect', 'trust_boundary', 'deserialization'],
    // ssrf added Sprint 57 #200: bash CGI/webhook handlers and scripts that
    // take a URL on stdin or as a positional CLI arg (`curl "$1"`,
    // `wget "$(read line)"`) and curl/wget it server-side are textbook SSRF
    // (CVE-2022-41040 ProxyShell-class). Cross-language: `socket.urlopen(input())`
    // (Python), `axios.get(readline())` (JS) etc. also benefit.
    io_input: ['command_injection', 'path_traversal', 'deserialization', 'xxe', 'code_injection', 'xss', 'ssrf'],
    env_input: ['command_injection', 'path_traversal'],
    db_input: ['xss', 'sql_injection'], // Second-order injection
    file_input: ['deserialization', 'xxe', 'path_traversal', 'command_injection', 'code_injection'],
    network_input: ['sql_injection', 'command_injection', 'xss', 'ssrf'],
    config_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'ssrf'], // Servlet init params
    interprocedural_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'xpath_injection', 'ldap_injection', 'ssrf', 'code_injection', 'mybatis_mapper_call', 'crlf', 'mass_assignment', 'open_redirect', 'trust_boundary'], // Cross-method taint; Sprint 82 (#189) — open_redirect added; Sprint 91 (#117) — trust_boundary added
    plugin_param: ['sql_injection', 'command_injection', 'path_traversal', 'xss', 'code_injection'], // Plugin/config parameters
  };

  const validSinks = sourceToSinkMapping[sourceType];
  return validSinks ? validSinks.includes(sinkType) : false;
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
function isProximityVulnerability(source: TaintSource, sink: TaintSink): boolean {
  // Within same method (roughly 50 lines for complex functions)
  return Math.abs(source.line - sink.line) <= 50;
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

