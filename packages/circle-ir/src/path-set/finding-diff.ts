/**
 * Finding diff of a version pair: the lines a change touched, and the
 * findings at the new version whose source or sink sits on a touched line and
 * that have no match at the old version.
 *
 * Findings are the engine's own: taint flows (per-file flows and cross-file
 * paths) and the pass findings. A finding is matched at the old version by
 * stable declaration ids where `ids@0.1` covers both versions of its files,
 * otherwise by rule × file × line mapped through the line diff; each new
 * finding says which. Facts only: whether a new finding matters is the
 * caller's to decide.
 *
 * Pure: IR and file text in, values out. Browser and Node compatible.
 */

import type { StableIdFile } from '../stable-ids/types.js';
import type { CircleIR, ProjectAnalysis } from '../types/index.js';
import { diffLines, splitLines, type LineDiff } from './line-diff.js';
import { declAt, normalizeCwe } from './path-set.js';

export interface FindingDiffSide {
  project: ProjectAnalysis;
  /** File text by repository-relative path, for every file of the tree the caller read. */
  texts: Record<string, string>;
  /** `ids@0.1` per file, where the ids cover the language. */
  stableIds?: Record<string, StableIdFile>;
}

export type MatchedBy = 'stable-id' | 'rule-file-line';

export interface NewFinding {
  /** Sink type for a flow, `rule_id` for a pass finding. */
  rule: string;
  cwe?: string;
  /** The sink's file and line for a flow; the finding's for a pass finding. */
  file: string;
  line: number;
  kind: 'flow' | 'pass';
  /** Which ends sit on a changed line: `source` and/or `sink` for a flow, `line` for a pass finding. */
  onChangedLine: Array<'source' | 'sink' | 'line'>;
  /** For a flow: where its source is. */
  source?: { file: string; line: number };
  matchedBy: MatchedBy;
}

export interface FindingDiff {
  /** 1-based lines of the new version not carried over from the old one, per file; files with none omitted. */
  changedLines: Record<string, number[]>;
  /** Sorted by file, line, rule. */
  newFindings: NewFinding[];
  /** What the comparison could not cover, sorted. */
  partial: Array<{ file?: string; reason: string }>;
  /** The match methods used, sorted. */
  matchedBy: MatchedBy[];
}

interface Finding {
  rule: string;
  cwe?: string;
  kind: 'flow' | 'pass';
  file: string;
  line: number;
  source?: { file: string; line: number };
}

function cweOf(ir: CircleIR, line: number, type: string): string | undefined {
  const s = ir.taint.sinks.find(x => x.line === line && x.type === type);
  return s ? normalizeCwe(s.cwe) : undefined;
}

function findingsOf(project: ProjectAnalysis): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  const add = (f: Finding): void => {
    const k = `${f.kind}|${f.rule}|${f.file}:${f.line}|${f.source?.file}:${f.source?.line}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push(f);
  };
  for (const { file, analysis: ir } of project.files) {
    for (const fl of ir.taint.flows ?? []) {
      const cwe = cweOf(ir, fl.sink_line, fl.sink_type);
      add({ rule: fl.sink_type, ...(cwe ? { cwe } : {}), kind: 'flow', file, line: fl.sink_line, source: { file, line: fl.source_line } });
    }
    for (const f of ir.findings ?? []) {
      add({ rule: f.rule_id, ...(f.cwe ? { cwe: f.cwe } : {}), kind: 'pass', file: f.file || file, line: f.line });
    }
  }
  for (const p of project.taint_paths ?? []) {
    if (!p.path_exists) continue;
    add({ rule: p.sink.type, cwe: normalizeCwe(p.sink.cwe), kind: 'flow', file: p.sink.file, line: p.sink.line, source: { file: p.source.file, line: p.source.line } });
  }
  return out;
}

/** A finding's identity across versions by stable declaration ids (no line numbers). */
function stableKey(f: Finding, side: FindingDiffSide, all: Finding[]): string | null {
  const ir = (file: string): CircleIR | undefined => side.project.files.find(x => x.file === file)?.analysis;
  const ids = side.stableIds ?? {};
  const files = [f.file, ...(f.source ? [f.source.file] : [])];
  if (!files.every(x => ids[x] && ir(x))) return null;
  const decl = (file: string, line: number): string => declAt(file, ir(file) as CircleIR, line, ids[file]).id;
  const d = decl(f.file, f.line);
  const s = f.source ? decl(f.source.file, f.source.line) : '';
  // ordinal among findings of the same rule and kind in the same declarations, by position
  const peers = all
    .filter(o => o.kind === f.kind && o.rule === f.rule && decl(o.file, o.line) === d && (o.source ? decl(o.source.file, o.source.line) : '') === s)
    .sort((a, b) => a.line - b.line || (a.source?.line ?? 0) - (b.source?.line ?? 0));
  return `${f.kind}|${f.rule}|${s}|${d}|#${peers.indexOf(f)}`;
}

/**
 * The finding diff of a version pair. `maxDiff` bounds the line-diff edit
 * distance per file; past it the whole file counts as changed and the file is
 * listed in `partial`.
 */
export function findingDiff(before: FindingDiffSide, after: FindingDiffSide, options: { maxDiff?: number } = {}): FindingDiff {
  const partial: FindingDiff['partial'] = [];
  const diffs = new Map<string, LineDiff>();
  const changedLines: Record<string, number[]> = {};
  for (const file of Object.keys(after.texts).sort()) {
    const newLines = splitLines(after.texts[file]);
    const oldText = before.texts[file];
    let d: LineDiff | null = diffLines(oldText === undefined ? [] : splitLines(oldText), newLines, options.maxDiff);
    if (d === null) {
      partial.push({ file, reason: 'diff-too-large' });
      d = { changed: newLines.map((_, i) => i + 1), toOld: new Map() };
    }
    diffs.set(file, d);
    if (d.changed.length > 0) changedLines[file] = d.changed;
  }

  // what the analysis did not cover
  const analysed = new Set(after.project.files.map(f => f.file));
  for (const file of Object.keys(changedLines)) if (!analysed.has(file)) partial.push({ file, reason: 'not-analysed' });
  for (const f of after.project.files) {
    if (f.analysis.parse_status && !f.analysis.parse_status.success && changedLines[f.file]) partial.push({ file: f.file, reason: 'parse-error' });
  }
  if (after.project.cross_file_budget_exceeded) partial.push({ reason: 'cross_file_budget_exceeded' });
  if (after.project.per_file_budget_exceeded) partial.push({ reason: 'per_file_budget_exceeded' });
  if (after.project.project_size_budget_exceeded) partial.push({ reason: 'project_size_budget_exceeded' });

  const isChanged = (file: string, line: number): boolean => diffs.get(file)?.changed.includes(line) ?? false;
  const toOld = (file: string, line: number): number | undefined => diffs.get(file)?.toOld.get(line);

  const afterFindings = findingsOf(after.project);
  const beforeFindings = findingsOf(before.project);
  const beforeKeys = new Set(beforeFindings.map(f => stableKey(f, before, beforeFindings)).filter((k): k is string => k !== null));

  const newFindings: NewFinding[] = [];
  const used = new Set<MatchedBy>();
  for (const f of afterFindings) {
    const on: NewFinding['onChangedLine'] = [];
    if (f.kind === 'pass') {
      if (isChanged(f.file, f.line)) on.push('line');
    } else {
      if (f.source && isChanged(f.source.file, f.source.line)) on.push('source');
      if (isChanged(f.file, f.line)) on.push('sink');
    }
    if (on.length === 0) continue;

    const key = stableKey(f, after, afterFindings);
    const beforeCovered = [f.file, ...(f.source ? [f.source.file] : [])].every(x => before.stableIds?.[x] || before.texts[x] === undefined);
    let matched: boolean;
    let by: MatchedBy;
    if (key !== null && beforeCovered) {
      by = 'stable-id';
      matched = beforeKeys.has(key);
    } else {
      by = 'rule-file-line';
      const sinkOld = toOld(f.file, f.line);
      const srcOld = f.source ? toOld(f.source.file, f.source.line) : undefined;
      matched = (sinkOld !== undefined || srcOld !== undefined) && beforeFindings.some(o =>
        o.kind === f.kind && o.rule === f.rule && o.file === f.file &&
        (sinkOld === undefined || o.line === sinkOld) &&
        (!f.source || (o.source?.file === f.source.file && (srcOld === undefined || o.source.line === srcOld))));
    }
    used.add(by);
    if (matched) continue;
    const nf: NewFinding = { rule: f.rule, file: f.file, line: f.line, kind: f.kind, onChangedLine: on, matchedBy: by };
    if (f.cwe) nf.cwe = f.cwe;
    if (f.source) nf.source = f.source;
    newFindings.push(nf);
  }
  newFindings.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || a.rule.localeCompare(b.rule)));
  partial.sort((a, b) => ((a.file ?? '') < (b.file ?? '') ? -1 : (a.file ?? '') > (b.file ?? '') ? 1 : a.reason.localeCompare(b.reason)));
  return { changedLines, newFindings, partial, matchedBy: [...used].sort() };
}
