/**
 * Require-entry-path anchor (cognium-dev#234, ships 3.153.0).
 *
 * Post-pipeline, project-level helper that:
 *   1. Annotates high+critical (H+C) taint findings with an
 *      `entryPath[]` chain of methods traversed from a classified
 *      Tier-1 entry point (Spring MVC handler, JAX-RS resource,
 *      Servlet lifecycle method, Netty channel handler, `main(String[])`,
 *      …) down to the finding's sink method.
 *   2. Drops H+C findings under `application` / `server` / `cli` /
 *      `plugin` / `unknown` project profiles when the reverse-BFS
 *      conclusively returns no such chain — i.e. the finding lives on a
 *      method that no HTTP / RPC / lifecycle entry point in the scan can
 *      reach.
 *
 * # Why
 *
 * cognium-ai#189 §1 (2026-07 Tier-2 Java cohort — hutool, Sentinel,
 * plantuml, mockserver) surfaced 1942 H+C findings on hutool with
 * *zero* classified HTTP/RPC entry point and no reachable path from
 * `main`. #236 (source-side profile gate, 3.151.0) and #232
 * (sink-side profile gate, 3.152.0) each attacked the problem via
 * profile-conditional per-file drops, but both leave the residual
 * signal on files whose profile is `application/*` or `unknown` even
 * though the enclosing method is manifestly unreachable from any
 * classified boundary.
 *
 * This helper closes that hole: no entry point → no path from an
 * entry point → no H+C finding. Every remaining H+C finding under
 * `application/*` carries a demonstrable call chain from a real
 * boundary as evidence, materialised on `entryPath[]` for consumers
 * (CLI, SARIF, cognium-ai) to display.
 *
 * # Scope
 *
 * - Java only (relies on `classifyEntryPointTier`, which is Java-primary).
 *   Non-Java files: pass-through, no annotation, no drop.
 * - Project-level only. Per-file `analyze()` never runs this helper —
 *   the reachability question is meaningful only across a full scan.
 * - Only H+C findings from taint passes are candidates for drop. Metric
 *   findings, `medium` / `low` taint findings, and findings without a
 *   resolved containing method are always preserved.
 *
 * # Interaction with #236 / #232
 *
 * Both #236 and #232 fire when `projectProfile` starts with `library/`:
 * the source / sink is dropped BEFORE the flow is materialised. This
 * helper therefore no-ops under `library/*` (an already-dropped flow
 * never reaches us) but still ANNOTATES findings with `entryPath[]`
 * whenever a chain is available, so downstream consumers can see the
 * anchor regardless of the drop decision.
 *
 * # Reference
 *
 * - cognium-dev#234 — this ticket.
 * - cognium-dev#128 — entry-point tier classifier.
 * - cognium-dev#236 (3.151.0) — source-side library-profile gate.
 * - cognium-dev#232 (3.152.0) — sink-side library-profile gate.
 * - cognium-ai#189  — Tier-2 Java cohort audit.
 * - `docs/ARCHITECTURE.md` ADR-010.
 */

import type {
  CircleIR,
  MethodInfo,
  ProjectProfile,
  SastFinding,
  TaintHop,
  TypeInfo,
} from '../types/index.js';
import { classifyEntryPointTier } from './entry-point-detection.js';

// ---------------------------------------------------------------------------
// Public rule id + constants
// ---------------------------------------------------------------------------

/** Rule identifier used for `disabledPasses` lookups. */
export const RULE_ID_REQUIRE_ENTRY_PATH = 'require-entry-path';

/**
 * BFS visit budget. Chosen empirically to comfortably cover the
 * largest-repo call graphs we see on the Tier-2 cohort (`plantuml`
 * ~7k methods, `sentinel` ~6k) while still guaranteeing the pass
 * terminates in bounded time. Findings whose BFS hits the budget are
 * treated as `unknown` and preserved — never dropped on a bailout.
 */
const MAX_VISITED_METHODS = 2000;

/**
 * Taint-flow `rule_id` allowlist (cognium-dev #246 REG-155-02).
 *
 * The docstring at the top of this module scopes the reachability drop
 * to "H+C findings from taint passes". Structurally, taint findings
 * carry a `rule_id` matching the `SinkType` union (underscore-cased
 * sink name), while rule-based crypto / config-anti-pattern passes
 * (`weak-crypto`, `weak-hash`, `weak-random`, `tls-verify-disabled`,
 * `jwt-verify-disabled`, `csrf-protection-disabled`, `security-headers`,
 * `insecure-cookie`, `scan-secrets`, …) emit their pass name as
 * `rule_id`. Those passes flag defects that exist regardless of
 * reachability from an HTTP / RPC / lifecycle boundary — an
 * `AES/ECB/PKCS5Padding` construction, a disabled TLS check, or a
 * plaintext credential is a bug whether or not any classified entry
 * point can reach the enclosing method.
 *
 * Before 3.158.0 the drop was scoped only on `category === 'security'`,
 * which over-broadly captured every rule-based crypto finding as well.
 * cognium-dev #246 REG-155-02 reproduced the mask on a plain
 * `AES/ECB` sink (`weak-crypto`, CWE-327) in an `unknown`-profile
 * scan with no entry point in the corpus. Restricting the drop to
 * this taint-only allowlist restores rule-based crypto/config
 * findings to full recall under `unknown` / `application` profiles
 * while preserving the H+C taint-drop behaviour that #234 was
 * designed for.
 */
const TAINT_FLOW_RULE_IDS: ReadonlySet<string> = new Set([
  // Underscore-cased (SinkType convention — used by production emitters
  // in language-sources-pass and the sink→finding lowering path).
  'sql_injection',
  'nosql_injection',
  'command_injection',
  'path_traversal',
  'xss',
  'xxe',
  'deserialization',
  'insecure_deserialization',
  'ldap_injection',
  'xpath_injection',
  'ssrf',
  'open_redirect',
  'code_injection',
  'log_injection',
  'redos',
  'format_string',
  'crlf',
  'mass_assignment',
  'mybatis_mapper_call',
  'external_taint_escape',
  'template_injection',
  // Dash-cased (used by some test fixtures and a handful of emitters
  // in the language-sources / cross-file paths for consistency with
  // metric-style rule ids). Kept side-by-side with the underscore
  // forms so both conventions are honoured until a future refactor
  // canonicalises on one spelling.
  'sql-injection',
  'nosql-injection',
  'command-injection',
  'path-traversal',
  'ldap-injection',
  'xpath-injection',
  'open-redirect',
  'code-injection',
  'log-injection',
  'format-string',
  'mass-assignment',
  'template-injection',
  'insecure-deserialization',
]);

// ---------------------------------------------------------------------------
// Public entrypoint
// ---------------------------------------------------------------------------

export interface ApplyRequireEntryPathOptions {
  /**
   * Caller-resolved profile for each file. Same semantics as
   * `AnalyzerOptions.projectProfile`. When absent, the helper treats
   * every file as `'unknown'` — i.e. drops still apply.
   */
  projectProfile?: ProjectProfile | Map<string, ProjectProfile>;
  /**
   * Set of disabled pass ids (from `AnalyzerOptions.disabledPasses`).
   * If it contains `'require-entry-path'`, the helper is a full no-op
   * (no annotation, no drop).
   */
  disabledPasses?: ReadonlySet<string> | ReadonlyArray<string>;
}

/**
 * Apply the entry-path gate + annotation to every file's findings in
 * `fileAnalyses`, mutating each `analysis.findings` array in place.
 *
 * The mutation is idempotent — running twice produces the same result
 * (BFS is deterministic; annotation always overwrites prior fields
 * with the same values).
 */
export function applyRequireEntryPath(
  fileAnalyses: ReadonlyArray<{ file: string; analysis: CircleIR }>,
  options: ApplyRequireEntryPathOptions = {},
): void {
  const disabledSet = normalizeDisabled(options.disabledPasses);
  if (disabledSet.has(RULE_ID_REQUIRE_ENTRY_PATH)) return;

  // Build the project-wide method index + reverse-caller adjacency once.
  const graph = buildProjectMethodGraph(fileAnalyses);
  if (graph.methodsByKey.size === 0) return;

  // Classify entry points once — reused for every finding.
  const entryPointKeys = collectEntryPointKeys(graph);

  const profileResolver = makeProfileResolver(options.projectProfile);

  for (const fa of fileAnalyses) {
    const findings = fa.analysis.findings;
    if (!findings || findings.length === 0) continue;
    const kept: SastFinding[] = [];
    for (const finding of findings) {
      const decision = classifyFinding(
        finding,
        fa.analysis,
        graph,
        entryPointKeys,
        profileResolver(fa.file),
      );
      switch (decision.action) {
        case 'keep':
          kept.push(finding);
          break;
        case 'annotate':
          kept.push({
            ...finding,
            entryPath: decision.entryPath,
            entryPathTier: decision.tier,
          });
          break;
        case 'drop':
          // Findings dropped by the entry-path gate carry no
          // side-channel signal — downstream consumers see them
          // as if they were never emitted.
          break;
      }
    }
    fa.analysis.findings = kept.length > 0 ? kept : undefined;
  }
}

// ---------------------------------------------------------------------------
// Method graph
// ---------------------------------------------------------------------------

interface MethodRecord {
  key: string;               // `${file}|${className}#${methodName}@${startLine}`
  file: string;
  className: string;
  method: MethodInfo;
  enclosingType: TypeInfo;
  language: string;
}

interface CallEdge {
  callerKey: string;
  calleeKey: string;
  callSiteLine: number;
  code: string;
}

interface ProjectMethodGraph {
  /** Method key → record. */
  methodsByKey: Map<string, MethodRecord>;
  /** Method simple name → candidate method keys (dispatch fallback). */
  methodsByName: Map<string, string[]>;
  /** Callee key → incoming call edges (reverse adjacency for BFS). */
  callersOf: Map<string, CallEdge[]>;
}

function buildProjectMethodGraph(
  fileAnalyses: ReadonlyArray<{ file: string; analysis: CircleIR }>,
): ProjectMethodGraph {
  const methodsByKey = new Map<string, MethodRecord>();
  const methodsByName = new Map<string, string[]>();
  const callersOf = new Map<string, CallEdge[]>();

  // Pass 1 — index every method.
  for (const fa of fileAnalyses) {
    const language = (fa.analysis.meta.language ?? '').toLowerCase();
    for (const type of fa.analysis.types ?? []) {
      for (const method of type.methods ?? []) {
        const key = makeMethodKey(fa.file, type.name, method.name, method.start_line);
        methodsByKey.set(key, {
          key,
          file: fa.file,
          className: type.name,
          method,
          enclosingType: type,
          language,
        });
        const bucket = methodsByName.get(method.name);
        if (bucket) bucket.push(key);
        else methodsByName.set(method.name, [key]);
      }
    }
  }

  // Pass 2 — index every call and resolve callee(s) into edges.
  for (const fa of fileAnalyses) {
    const calls = fa.analysis.calls ?? [];
    for (const call of calls) {
      if (!call.in_method) continue;
      const callerKey = resolveCallerKey(fa, call.in_method, call.location.line);
      if (!callerKey) continue;

      const calleeKeys = resolveCalleeKeys(call, methodsByKey, methodsByName);
      if (calleeKeys.length === 0) continue;

      const code = call.receiver
        ? `${call.receiver}.${call.method_name}(...)`
        : `${call.method_name}(...)`;

      for (const calleeKey of calleeKeys) {
        const edge: CallEdge = {
          callerKey,
          calleeKey,
          callSiteLine: call.location.line,
          code,
        };
        const bucket = callersOf.get(calleeKey);
        if (bucket) bucket.push(edge);
        else callersOf.set(calleeKey, [edge]);
      }
    }
  }

  return { methodsByKey, methodsByName, callersOf };
}

function makeMethodKey(
  file: string,
  className: string,
  methodName: string,
  startLine: number,
): string {
  return `${file}|${className}#${methodName}@${startLine}`;
}

function resolveCallerKey(
  fa: { file: string; analysis: CircleIR },
  inMethod: string,
  callLine: number,
): string | null {
  // `in_method` is the simple method name of the enclosing method.
  // Disambiguate by finding the type whose method range contains
  // `callLine` (handles overloaded methods sharing the same name).
  for (const type of fa.analysis.types ?? []) {
    for (const method of type.methods ?? []) {
      if (method.name !== inMethod) continue;
      if (callLine >= method.start_line && callLine <= method.end_line) {
        return makeMethodKey(fa.file, type.name, method.name, method.start_line);
      }
    }
  }
  return null;
}

function resolveCalleeKeys(
  call: { method_name: string; receiver_type?: string | null },
  methodsByKey: Map<string, MethodRecord>,
  methodsByName: Map<string, string[]>,
): string[] {
  const candidates = methodsByName.get(call.method_name);
  if (!candidates || candidates.length === 0) return [];

  // Prefer receiver-type match when we have it — cuts the fan-out on
  // common names like `execute` / `run` / `handle` from ~50 to ~1.
  if (call.receiver_type) {
    const simple = call.receiver_type.replace(/<.*$/, '').trim();
    const matches: string[] = [];
    for (const key of candidates) {
      const rec = methodsByKey.get(key);
      if (rec?.className === simple) matches.push(key);
    }
    if (matches.length > 0) return matches;
  }

  // Fallback — name-only. Duplicates fan out the BFS but the visit
  // budget bounds it. Wrong callees do not corrupt correctness: a
  // spurious edge only expands the reachable set, never contracts it,
  // and this helper only DROPS on empty-reachable.
  return candidates;
}

// ---------------------------------------------------------------------------
// Entry-point classification
// ---------------------------------------------------------------------------

function collectEntryPointKeys(graph: ProjectMethodGraph): Set<string> {
  const entryPoints = new Set<string>();
  for (const rec of graph.methodsByKey.values()) {
    const tier = classifyEntryPointTier(rec.method, rec.enclosingType, {
      types: [rec.enclosingType],
      language: rec.language,
    });
    if (tier === 'TIER_1_ENTRY_POINT') entryPoints.add(rec.key);
  }
  return entryPoints;
}

// ---------------------------------------------------------------------------
// Finding classification
// ---------------------------------------------------------------------------

type FindingDecision =
  | { action: 'keep' }
  | { action: 'annotate'; entryPath: TaintHop[]; tier: NonNullable<SastFinding['entryPathTier']> }
  | { action: 'drop' };

function classifyFinding(
  finding: SastFinding,
  ir: CircleIR,
  graph: ProjectMethodGraph,
  entryPointKeys: Set<string>,
  profile: ProjectProfile,
): FindingDecision {
  // Only taint findings from the security category are in scope.
  if (finding.category !== 'security') return { action: 'keep' };

  // cognium-dev #246 REG-155-02 — restrict to taint-flow findings.
  // Rule-based crypto / config-anti-pattern findings (`weak-crypto`,
  // `weak-hash`, `tls-verify-disabled`, `scan-secrets`, …) do not
  // depend on source→sink reachability and must not be dropped by
  // this gate. See the `TAINT_FLOW_RULE_IDS` docstring.
  if (!TAINT_FLOW_RULE_IDS.has(finding.rule_id)) return { action: 'keep' };

  // Only H+C findings are candidates for drop; lower-severity findings
  // are preserved regardless of reachability (may still be annotated
  // when we can).
  const isHighOrCritical = finding.severity === 'high' || finding.severity === 'critical';

  // Java-only. The classifier is Java-primary (`classifyEntryPointTier`
  // returns `TIER_UNKNOWN` for every other language), so applying the
  // reachability drop to non-Java findings would strip legitimate
  // signal on Python / Node / Go / Rust — pass through unchanged.
  const language = (ir.meta.language ?? '').toLowerCase();
  if (language !== 'java') return { action: 'keep' };

  // Resolve containing method by (file, line-range) lookup.
  const containing = findContainingMethod(finding, ir, graph);
  if (!containing) {
    // Sink lives in a field initializer, static block, or another
    // no-method context — cannot classify. Never drop.
    return { action: 'keep' };
  }

  // Reverse BFS from the containing method.
  const bfs = reverseBfsToEntryPoint(containing.key, graph, entryPointKeys);
  if (bfs.status === 'hit') {
    const entryPath = reconstructPath(bfs.entryKey!, containing.key, bfs.parent, graph, finding);
    return {
      action: 'annotate',
      entryPath,
      tier: 'tier1-entry-point',
    };
  }

  if (bfs.status === 'budget') {
    // Depth bailout — insufficient evidence, preserve.
    return { action: 'keep' };
  }

  // bfs.status === 'miss' — no entry point reaches this method.
  if (!isHighOrCritical) return { action: 'keep' };
  if (!shouldDropUnderProfile(profile)) return { action: 'keep' };

  return { action: 'drop' };
}

function findContainingMethod(
  finding: SastFinding,
  ir: CircleIR,
  graph: ProjectMethodGraph,
): MethodRecord | null {
  const line = finding.line;
  for (const type of ir.types ?? []) {
    for (const method of type.methods ?? []) {
      if (line >= method.start_line && line <= method.end_line) {
        const key = makeMethodKey(finding.file, type.name, method.name, method.start_line);
        const rec = graph.methodsByKey.get(key);
        if (rec) return rec;
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Reverse BFS
// ---------------------------------------------------------------------------

interface BfsResult {
  status: 'hit' | 'miss' | 'budget';
  entryKey: string | null;
  parent: Map<string, CallEdge>;
}

function reverseBfsToEntryPoint(
  startKey: string,
  graph: ProjectMethodGraph,
  entryPointKeys: Set<string>,
): BfsResult {
  const parent = new Map<string, CallEdge>();
  const visited = new Set<string>([startKey]);
  const queue: string[] = [startKey];

  // Corner case: the sink method is itself an entry point.
  if (entryPointKeys.has(startKey)) {
    return { status: 'hit', entryKey: startKey, parent };
  }

  while (queue.length > 0) {
    if (visited.size > MAX_VISITED_METHODS) {
      return { status: 'budget', entryKey: null, parent };
    }
    const current = queue.shift()!;
    const incoming = graph.callersOf.get(current) ?? [];
    // Deterministic ordering — sort by caller key for reproducibility.
    incoming.sort((a, b) => a.callerKey.localeCompare(b.callerKey));
    for (const edge of incoming) {
      if (visited.has(edge.callerKey)) continue;
      visited.add(edge.callerKey);
      parent.set(edge.callerKey, edge);
      if (entryPointKeys.has(edge.callerKey)) {
        return { status: 'hit', entryKey: edge.callerKey, parent };
      }
      queue.push(edge.callerKey);
    }
  }

  return { status: 'miss', entryKey: null, parent };
}

function reconstructPath(
  entryKey: string,
  sinkKey: string,
  parent: Map<string, CallEdge>,
  graph: ProjectMethodGraph,
  finding: SastFinding,
): TaintHop[] {
  // Walk from entry down to sink by iteratively following the parent
  // map forward. `parent.get(x)` yields the edge whose `callerKey === x`
  // (i.e. the call FROM x to its callee on the path).
  const hops: TaintHop[] = [];
  let cursor = entryKey;
  const guard = new Set<string>();
  while (cursor !== sinkKey) {
    if (guard.has(cursor)) break; // paranoia — should never cycle
    guard.add(cursor);
    const rec = graph.methodsByKey.get(cursor);
    const edge = parent.get(cursor);
    if (!rec || !edge) break;
    hops.push({
      file: rec.file,
      method: `${rec.className}.${rec.method.name}`,
      line: edge.callSiteLine,
      code: edge.code,
      variable: '',
    });
    cursor = edge.calleeKey;
  }

  // Terminal hop — the sink method itself, at the finding's line.
  const sinkRec = graph.methodsByKey.get(sinkKey);
  if (sinkRec) {
    hops.push({
      file: sinkRec.file,
      method: `${sinkRec.className}.${sinkRec.method.name}`,
      line: finding.line,
      code: finding.message,
      variable: '',
    });
  }

  return hops;
}

// ---------------------------------------------------------------------------
// Profile predicate
// ---------------------------------------------------------------------------

function shouldDropUnderProfile(profile: ProjectProfile): boolean {
  // #236 / #232 already own the `library/*` drop path — this helper
  // must not double-drop findings that survived those gates on
  // library files, so we only fire on non-library profiles.
  if (profile === 'unknown') return true;
  if (profile.startsWith('library/')) return false;
  return true;
}

function makeProfileResolver(
  input: ProjectProfile | Map<string, ProjectProfile> | undefined,
): (file: string) => ProjectProfile {
  if (input === undefined) return () => 'unknown';
  if (typeof input === 'string') return () => input;
  return (file) => input.get(file) ?? 'unknown';
}

function normalizeDisabled(
  input: ReadonlySet<string> | ReadonlyArray<string> | undefined,
): ReadonlySet<string> {
  if (!input) return new Set<string>();
  if (input instanceof Set) return input;
  return new Set(input);
}
