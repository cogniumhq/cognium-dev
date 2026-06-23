/**
 * Findings instrumentation hook (cognium-dev #145, re-scoped per
 * cognium-ai feedback).
 *
 * Opt-in, off by default. When enabled via `setFindingsInstrumentation(true)`,
 * the per-file analyzer emits one `[finding]` JSON line on stderr for every
 * `SastFinding` produced by the pipeline, plus one `[findings-summary]` line
 * per file with aggregate counts. The payload carries the fields required to
 * re-derive coalesce candidates after the fact (#143):
 * `rule_id`, `file`, `line`, `pass`, `category`, `severity`, `cwe`,
 * `sink_type`, `source_type`, `confidence`, `dedup_group_id`.
 *
 * Browser-safe: no Node-only APIs. `console.error` is universal and bypasses
 * the logger DI by design so the output stays grep-friendly regardless of
 * log level.
 *
 * Read-only contract: this module never mutates the findings array or any
 * other pipeline output. Disabling the flag fully no-ops the emission.
 */

import type { SastFinding, TaintSource, TaintSink } from '../types/index.js';

let instrumentEnabled = false;

/**
 * Toggle the per-file findings instrumentation on or off. Off by default.
 *
 * The CLI wires this to the `CIRCLE_IR_INSTRUMENT_FINDINGS=1` environment
 * variable; library consumers can call it directly.
 */
export function setFindingsInstrumentation(enabled: boolean): void {
  instrumentEnabled = enabled;
}

/**
 * Current state of the instrumentation flag. Exposed for tests and for
 * consumers that want to gate their own diagnostics off the same switch.
 */
export function isFindingsInstrumentationEnabled(): boolean {
  return instrumentEnabled;
}

/**
 * Build a `${file}:${line}:${rule_id}` key for a finding. Matches the dedup
 * convention used elsewhere in the codebase (e.g. ScanSecretsPass) so
 * downstream analysis can group candidates without a second pass.
 */
function dedupGroupId(f: SastFinding): string {
  return `${f.file}:${f.line}:${f.rule_id}`;
}

/**
 * Emit one stderr line per `SastFinding` plus one summary line for the file.
 * Cheap no-op when the flag is off.
 *
 * Called by `analyze()` once per file, right after the pipeline has
 * accumulated all findings and right before the per-file result object is
 * assembled. See `src/analyzer.ts`.
 */
export function emitFindingsInstrumentation(
  filePath: string,
  findings: readonly SastFinding[],
  taint: { sources: readonly TaintSource[]; sinks: readonly TaintSink[] },
): void {
  if (!instrumentEnabled) return;

  // Pre-index sinks/sources by line for O(1) lookup. Many findings per file,
  // many sinks per file; nested .find() would be O(F*S) per file.
  const sinkByLine = new Map<number, TaintSink>();
  for (const s of taint.sinks) {
    // First sink at a line wins; matches finding's primary "go-to-line".
    if (!sinkByLine.has(s.line)) sinkByLine.set(s.line, s);
  }
  const sourceByLine = new Map<number, TaintSource>();
  for (const s of taint.sources) {
    if (!sourceByLine.has(s.line)) sourceByLine.set(s.line, s);
  }

  const groupCounts = new Map<string, number>();
  const byRule = new Map<string, number>();
  const bySeverity = new Map<string, number>();

  for (const f of findings) {
    const gid = dedupGroupId(f);
    groupCounts.set(gid, (groupCounts.get(gid) ?? 0) + 1);
    byRule.set(f.rule_id, (byRule.get(f.rule_id) ?? 0) + 1);
    bySeverity.set(f.severity, (bySeverity.get(f.severity) ?? 0) + 1);

    const sink = sinkByLine.get(f.line);
    const source = sink ? undefined : sourceByLine.get(f.line);
    const payload = {
      file: f.file,
      line: f.line,
      rule_id: f.rule_id,
      pass: f.pass,
      category: f.category,
      severity: f.severity,
      cwe: f.cwe,
      sink_type: sink?.type,
      source_type: source?.type,
      confidence: sink?.confidence,
      dedup_group_id: gid,
    };
    console.error(`[finding] ${JSON.stringify(payload)}`);
  }

  let maxPerGroup = 0;
  for (const c of groupCounts.values()) {
    if (c > maxPerGroup) maxPerGroup = c;
  }

  const summary = {
    file: filePath,
    total: findings.length,
    unique_groups: groupCounts.size,
    max_findings_per_group: maxPerGroup,
    sources_count: taint.sources.length,
    sinks_count: taint.sinks.length,
    by_rule: Object.fromEntries(byRule),
    by_severity: Object.fromEntries(bySeverity),
  };
  console.error(`[findings-summary] ${JSON.stringify(summary)}`);
}
