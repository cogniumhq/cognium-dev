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
 * - Java + Python + JS/TS + Go + Bash (as of 3.166.0, #237). Rust /
 *   HTML / Vue / unknown languages pass through unchanged. The
 *   `SUPPORTED_LANGUAGES` set below controls language admission; the
 *   per-language safety guard (`entryPointKeysByLanguage.get(lang) === 0
 *   → keep`) preserves recall on library-only bundles where the
 *   classifier truly has no signal.
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
  ImportInfo,
  MethodInfo,
  ProjectProfile,
  SastFinding,
  SinkType,
  TaintFlowInfo,
  TaintHop,
  TypeInfo,
} from '../types/index.js';
import {
  classifyEntryPointTier,
  isSupertypeLifecycleMethod,
  pathLooksLikeLibraryOrTest,
} from './entry-point-detection.js';

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
  'xml_entity_expansion',
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
  'xml-entity-expansion',
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
 *
 * Returns how many findings and taint flows were dropped, so a caller
 * can report the gate's effect instead of leaving it invisible.
 */
export function applyRequireEntryPath(
  fileAnalyses: ReadonlyArray<{ file: string; analysis: CircleIR }>,
  options: ApplyRequireEntryPathOptions = {},
): number {
  const disabledSet = normalizeDisabled(options.disabledPasses);
  if (disabledSet.has(RULE_ID_REQUIRE_ENTRY_PATH)) return 0;

  // Build the project-wide method index + reverse-caller adjacency once.
  const graph = buildProjectMethodGraph(fileAnalyses);
  if (graph.methodsByKey.size === 0) return 0;
  let dropped = 0;

  // Per-file classifier context (calls, runtime_registrations) — used
  // by the polyglot classifier for Go inline call walks and JS/TS +
  // Python handler resolution. Added 3.166.0 (#237).
  const fileContext = buildFileContext(fileAnalyses);

  // Classify entry points once — reused for every finding.
  const entryPointKeys = collectEntryPointKeys(graph, fileContext, indexTypesByName(fileAnalyses));
  for (const key of collectImportedRouteHandlerKeys(fileAnalyses)) entryPointKeys.add(key);

  // Per-language entry-point-key count — used by the safety guard
  // (#237): if a language has ZERO classified entry points across the
  // whole scan, findings on that language MUST be preserved regardless
  // of profile / BFS. Otherwise, the polyglot expansion could over-drop
  // on languages where the classifier's positive signal is thin.
  const entryPointKeysByLanguage = countEntryPointKeysByLanguage(graph, entryPointKeys);

  const profileResolver = makeProfileResolver(options.projectProfile);

  for (const fa of fileAnalyses) {
    const profile = profileResolver(fa.file);

    // ------------------------------------------------------------------
    // Channel 1 — `analysis.findings[]` (rule-based emitters and
    // language-sources / sink→finding lowering path).
    // ------------------------------------------------------------------
    const findings = fa.analysis.findings;
    if (findings && findings.length > 0) {
      const kept: SastFinding[] = [];
      for (const finding of findings) {
        const decision = classifyFinding(
          finding,
          fa.analysis,
          graph,
          entryPointKeys,
          entryPointKeysByLanguage,
          profile,
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
            // The finding itself is removed; only the returned count
            // (`ProjectAnalysis.entry_path_dropped`) records it.
            dropped++;
            break;
        }
      }
      fa.analysis.findings = kept.length > 0 ? kept : undefined;
    }

    // ------------------------------------------------------------------
    // Channel 2 — `analysis.taint.flows[]` (cognium-dev #237 follow-up,
    // 3.167.0). The CLI, cognium-ai harness, and downstream SARIF/JSON
    // consumers all read taint flows as first-class vulnerabilities.
    // Prior to 3.167.0, `applyRequireEntryPath` only mutated
    // `findings[]`, which meant SSRF / SQL-injection / XSS / path-
    // traversal signal produced by `TaintPropagationPass` bypassed the
    // reachability gate entirely — the JS / interop FPs in #237 that
    // shipped as unresolved in 3.166.1 turned out to be dropped
    // correctly from `findings[]` but retained on `taint.flows[]`.
    // ------------------------------------------------------------------
    const flows = fa.analysis.taint?.flows;
    if (flows && flows.length > 0) {
      const keptFlows: TaintFlowInfo[] = [];
      for (const flow of flows) {
        const pseudo = flowToPseudoFinding(fa.file, flow);
        if (!pseudo) {
          // Low/medium sink severity — never a drop candidate under
          // the H+C predicate. Preserve unchanged.
          keptFlows.push(flow);
          continue;
        }
        const decision = classifyFinding(
          pseudo,
          fa.analysis,
          graph,
          entryPointKeys,
          entryPointKeysByLanguage,
          profile,
        );
        if (decision.action !== 'drop') keptFlows.push(flow);
        else dropped++;
      }
      fa.analysis.taint.flows = keptFlows;
    }
  }
  return dropped;
}

// ---------------------------------------------------------------------------
// Taint-flow → pseudo-finding synthesis
// ---------------------------------------------------------------------------

/**
 * Minimal H+C severity map for `TaintFlowInfo.sink_type`. Only sink
 * types whose canonical severity is `high` or `critical` are drop
 * candidates under the entry-path gate — medium/low sinks (e.g.
 * `open_redirect`, `log_injection`, `redos`, `crlf`) are always
 * preserved regardless of reachability, matching the H+C predicate
 * enforced by `classifyFinding`.
 *
 * Sourced from `packages/cli/src/formatters.ts:SINK_SEVERITY`. Kept in
 * sync manually — the CLI copy is the source of truth for user-facing
 * severity, this copy is only used to decide whether the entry-path
 * gate is even in scope for a given flow.
 */
const SINK_HC_SEVERITY: Partial<Record<SinkType, 'high' | 'critical'>> = {
  sql_injection: 'critical',
  nosql_injection: 'high',
  command_injection: 'critical',
  path_traversal: 'high',
  xss: 'high',
  xxe: 'critical',
  deserialization: 'critical',
  ldap_injection: 'high',
  xpath_injection: 'high',
  ssrf: 'high',
  code_injection: 'critical',
  format_string: 'high',
  mass_assignment: 'high',
};

/**
 * Synthesize a minimal `SastFinding` shape from a taint flow so the
 * shared `classifyFinding()` reachability logic can run over it.
 * Returns `null` when the sink type is not in `SINK_HC_SEVERITY` — in
 * that case the flow is not an H+C drop candidate and must be
 * preserved unconditionally.
 *
 * Only fields actually consulted by `classifyFinding` are populated
 * (`category`, `rule_id`, `severity`, `file`, `line`, `message`). All
 * other `SastFinding` fields (`id`, `pass`, `cwe`, `level`, `fix`,
 * `snippet`, …) are set to safe placeholders — this object never
 * escapes this module.
 */
function flowToPseudoFinding(
  file: string,
  flow: TaintFlowInfo,
): SastFinding | null {
  const severity = SINK_HC_SEVERITY[flow.sink_type];
  if (!severity) return null;
  return {
    id: `taint-flow:${file}:${flow.sink_line}:${flow.sink_type}`,
    pass: 'taint-propagation',
    category: 'security',
    rule_id: flow.sink_type,
    cwe: '',
    severity,
    level: 'error',
    message: `${flow.sink_type} at line ${flow.sink_line}`,
    file,
    line: flow.sink_line,
  };
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

function collectEntryPointKeys(
  graph: ProjectMethodGraph,
  fileContext: Map<string, FileClassifierContext>,
  typesByName: Map<string, TypeInfo[]>,
): Set<string> {
  const entryPoints = new Set<string>();
  for (const rec of graph.methodsByKey.values()) {
    const fileCtx = fileContext.get(rec.file);
    const tier = classifyEntryPointTier(rec.method, rec.enclosingType, {
      types: [rec.enclosingType],
      language: rec.language,
      filePath: rec.file,
      calls: fileCtx?.calls ?? null,
      runtimeRegistrations: fileCtx?.runtimeRegistrations ?? null,
    });
    if (tier === 'TIER_1_ENTRY_POINT' || inheritsLifecycleEntry(rec.method.name, rec.enclosingType, typesByName)) {
      entryPoints.add(rec.key);
    }
  }
  return entryPoints;
}

/** Every type in the scan, by simple name (several when packages differ). */
function indexTypesByName(
  fileAnalyses: ReadonlyArray<{ file: string; analysis: CircleIR }>,
): Map<string, TypeInfo[]> {
  const byName = new Map<string, TypeInfo[]>();
  for (const fa of fileAnalyses) {
    for (const t of fa.analysis.types ?? []) {
      const list = byName.get(t.name) ?? [];
      list.push(t);
      byName.set(t.name, list);
    }
  }
  return byName;
}

const simpleName = (ref: string): string => {
  const name = ref.replace(/<.*$/, '').trim();
  return name.substring(name.lastIndexOf('.') + 1);
};

/**
 * True when `methodName` is a lifecycle entry of a framework supertype that
 * the enclosing type reaches through in-project base classes:
 * `Basic1 extends BasicTestCase` where `BasicTestCase extends HttpServlet`
 * makes `Basic1.doGet` a servlet entry point. The per-type classifier sees
 * only the direct parent, so before this every handler behind a project base
 * servlet was gated as unreachable and its findings dropped.
 */
function inheritsLifecycleEntry(
  methodName: string,
  enclosingType: TypeInfo | undefined,
  typesByName: Map<string, TypeInfo[]>,
): boolean {
  if (!methodName || !enclosingType?.extends) return false;
  const seen = new Set<TypeInfo>([enclosingType]);
  let frontier = typesByName.get(simpleName(enclosingType.extends)) ?? [];
  for (let depth = 0; depth < 8 && frontier.length > 0; depth++) {
    const next: TypeInfo[] = [];
    for (const ancestor of frontier) {
      if (seen.has(ancestor)) continue;
      seen.add(ancestor);
      const supers = [ancestor.extends, ...(ancestor.implements ?? [])].filter((x): x is string => !!x);
      if (supers.some(sup => isSupertypeLifecycleMethod(sup, methodName))) return true;
      if (ancestor.extends) next.push(...(typesByName.get(simpleName(ancestor.extends)) ?? []));
    }
    frontier = next;
  }
  return false;
}

// ---------------------------------------------------------------------------
// JS/TS route handlers imported from another file (cognium-dev #1323)
// ---------------------------------------------------------------------------

const JSTS_LANGUAGES: ReadonlySet<string> = new Set(['javascript', 'typescript', 'tsx', 'jsx']);

const JSTS_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mts', '.cts', '.mjs', '.cjs'];

type ScannedFile = { file: string; analysis: CircleIR };

/**
 * Method keys of exported functions that a router file registers by name:
 * `import { run } from './handler'` then `router.get('/run', run)`. The
 * per-file classifier only matches a handler name against methods of the
 * registering file, so an imported handler was never an entry point and,
 * once any other JS/TS entry point existed, the gate dropped its findings.
 *
 * Handles named, default and namespace / `require` imports, member access
 * (`handlers.run`, `Controller.run`), and one re-export hop (`index.ts`).
 * Only relative specifiers that resolve to a file in the scan are followed.
 */
function collectImportedRouteHandlerKeys(fileAnalyses: ReadonlyArray<ScannedFile>): Set<string> {
  const out = new Set<string>();
  const byPath = new Map<string, ScannedFile>();
  for (const fa of fileAnalyses) {
    if (JSTS_LANGUAGES.has((fa.analysis.meta.language ?? '').toLowerCase())) byPath.set(normalizePath(fa.file), fa);
  }
  if (byPath.size < 2) return out;

  for (const fa of byPath.values()) {
    if (pathLooksLikeLibraryOrTest(fa.file)) continue;
    for (const reg of fa.analysis.runtime_registrations ?? []) {
      if (reg.kind !== 'http_route' && reg.kind !== 'middleware') continue;
      const ref = reg.handler?.name?.match(/^([A-Za-z_$][\w$]*)(?:\.([A-Za-z_$][\w$]*))?$/);
      if (!ref) continue;
      const [, head, member] = ref;
      const imp = (fa.analysis.imports ?? []).find(i => localName(i) === head);
      if (!imp?.from_package || imp.is_type_only) continue;
      const target = resolveModule(fa.file, imp.from_package, byPath);
      if (!target) continue;
      if (imp.is_wildcard) {
        // `import * as handlers` / `const handlers = require(...)`, then `handlers.run`.
        if (member) addExportedFunction(target, member, null, byPath, out);
      } else if (member) {
        // `import { Controller }`, then `Controller.run`.
        addClassMethod(target, imp.imported_name, member, out);
      } else {
        addExportedFunction(target, imp.imported_name, head, byPath, out);
      }
    }
  }
  return out;
}

/** The name an import binds in the importing file. */
function localName(imp: ImportInfo): string {
  return imp.alias ?? imp.imported_name;
}

/**
 * Mark the module-scope function exported as `name` from `target`. A default
 * import matches a function named like its local binding, else the file's
 * only module-scope function. When nothing matches, follow one hop of the
 * file's re-exports (`export { run } from './run'`, `export * from …`) and its
 * imports of the same name.
 */
function addExportedFunction(
  target: ScannedFile,
  name: string,
  defaultLocal: string | null,
  byPath: Map<string, ScannedFile>,
  out: Set<string>,
  hop = 0,
): void {
  const moduleType = (target.analysis.types ?? []).find(t => t.name === '<module>');
  const methods = moduleType?.methods ?? [];
  let hits = name === 'default'
    ? methods.filter(m => m.name === defaultLocal)
    : methods.filter(m => m.name === name);
  if (hits.length === 0 && name === 'default' && methods.length === 1) hits = methods;
  if (hits.length > 0) {
    for (const m of hits) out.add(makeMethodKey(target.file, '<module>', m.name, m.start_line));
    return;
  }
  if (hop > 0 || name === 'default') return;
  for (const imp of target.analysis.imports ?? []) {
    if (!imp.from_package || imp.is_type_only) continue;
    // Re-exports are recorded as un-aliased wildcard imports.
    const reExport = imp.is_wildcard && imp.alias === null;
    if (!reExport && localName(imp) !== name) continue;
    const next = resolveModule(target.file, imp.from_package, byPath);
    if (next && next !== target) addExportedFunction(next, reExport ? name : imp.imported_name, name, byPath, out, hop + 1);
  }
}

function addClassMethod(target: ScannedFile, className: string, methodName: string, out: Set<string>): void {
  for (const t of target.analysis.types ?? []) {
    if (t.name !== className) continue;
    for (const m of t.methods ?? []) {
      if (m.name === methodName) out.add(makeMethodKey(target.file, t.name, m.name, m.start_line));
    }
  }
}

/** Resolve a relative specifier against `fromFile` to a scanned JS/TS file. */
function resolveModule(fromFile: string, spec: string, byPath: Map<string, ScannedFile>): ScannedFile | null {
  if (!spec.startsWith('./') && !spec.startsWith('../')) return null;
  const from = normalizePath(fromFile);
  const base = normalizePath(`${from.slice(0, from.lastIndexOf('/') + 1)}${spec}`);
  // TS ESM imports name the emitted `.js` file: `./handler.js` → `handler.ts`.
  const stem = base.replace(/\.(?:[cm]?js|jsx)$/, '');
  const candidates = [base, ...JSTS_EXTENSIONS.map(e => stem + e), ...JSTS_EXTENSIONS.map(e => `${base}/index${e}`)];
  for (const c of candidates) {
    const hit = byPath.get(c);
    if (hit) return hit;
  }
  return null;
}

/** Forward slashes, with `.` and `..` segments collapsed. */
function normalizePath(p: string): string {
  const parts: string[] = [];
  for (const seg of p.replace(/\\/g, '/').split('/')) {
    if (seg === '.') continue;
    if (seg === '..' && parts.length > 0 && parts[parts.length - 1] !== '..' && parts[parts.length - 1] !== '') parts.pop();
    else parts.push(seg);
  }
  return parts.join('/');
}

/**
 * Per-file context bag consumed by the polyglot classifier — the Go
 * classifier walks `ir.calls`, the JS/TS + Python classifiers consume
 * `ir.runtime_registrations`. Built once per project in
 * `buildFileContext`.
 */
interface FileClassifierContext {
  language: string;
  calls: ReadonlyArray<import('../types/index.js').CallInfo> | null;
  runtimeRegistrations: ReadonlyArray<import('../types/index.js').RuntimeRegistration> | null;
}

function buildFileContext(
  fileAnalyses: ReadonlyArray<{ file: string; analysis: CircleIR }>,
): Map<string, FileClassifierContext> {
  const out = new Map<string, FileClassifierContext>();
  for (const fa of fileAnalyses) {
    out.set(fa.file, {
      language: (fa.analysis.meta.language ?? '').toLowerCase(),
      calls: fa.analysis.calls ?? null,
      runtimeRegistrations: fa.analysis.runtime_registrations ?? null,
    });
  }
  return out;
}

/**
 * Bucket the entry-point-keys set by the language of each key's method
 * record. Used by `classifyFinding` to enforce the per-language safety
 * guard: if a language has zero Tier-1 entry points, keep every
 * finding on that language (preserves recall — see #237 plan).
 */
function countEntryPointKeysByLanguage(
  graph: ProjectMethodGraph,
  entryPointKeys: Set<string>,
): Map<string, number> {
  const out = new Map<string, number>();
  for (const key of entryPointKeys) {
    const rec = graph.methodsByKey.get(key);
    if (!rec) continue;
    out.set(rec.language, (out.get(rec.language) ?? 0) + 1);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Finding classification
// ---------------------------------------------------------------------------

type FindingDecision =
  | { action: 'keep' }
  | { action: 'annotate'; entryPath: TaintHop[]; tier: NonNullable<SastFinding['entryPathTier']> }
  | { action: 'drop' };

/**
 * Languages whose entry-point classifier is expected to emit at least
 * some Tier-1 signal on a well-formed application. Files whose
 * language is NOT in this set short-circuit to `keep` — the classifier
 * would return `TIER_UNKNOWN` and dropping on the miss branch would
 * strip legitimate signal on languages we haven't taught the
 * classifier yet (Rust, HTML, Vue).
 *
 * Added 3.166.0 for cognium-dev #237 polyglot expansion — replaces the
 * hardcoded `if (language !== 'java')` gate.
 */
const SUPPORTED_LANGUAGES: ReadonlySet<string> = new Set([
  'java',
  'python',
  'javascript',
  'typescript',
  'tsx',
  'jsx',
  'go',
  'bash',
  'shell',
]);

function classifyFinding(
  finding: SastFinding,
  ir: CircleIR,
  graph: ProjectMethodGraph,
  entryPointKeys: Set<string>,
  entryPointKeysByLanguage: Map<string, number>,
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

  // Polyglot-supported languages (#237). Rust / HTML / Vue / unknown
  // route via `keep` — the classifier lacks the framework tables to
  // decide, and misclassifying to TIER_UNKNOWN cannot support a drop.
  const language = (ir.meta.language ?? '').toLowerCase();
  if (!SUPPORTED_LANGUAGES.has(language)) return { action: 'keep' };

  // Safety guard (#237). If the language's classifier found ZERO
  // Tier-1 entry points across the whole scan, the reachability
  // question has no answer we can trust — preserve the finding. This
  // is what keeps recall on library / helper-only bundles where the
  // classifier truly has no signal, and matches the plan's per-file-
  // language guard specification.
  if ((entryPointKeysByLanguage.get(language) ?? 0) === 0) {
    return { action: 'keep' };
  }

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
