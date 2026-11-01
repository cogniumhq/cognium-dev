/**
 * `recheck` — the deterministic re-check of a code-fix change (E20/engine).
 *
 * Run once on the changed files before the change and once after it, on the same
 * file list. Each finding is keyed by CWE × declaration × rule, where the
 * declaration is the enclosing method's stable id (`ids@0.1`) when the language
 * has stable ids (Java, TypeScript, JavaScript, Python, Go), else its qualified
 * name. The key therefore survives edits that only move lines. With
 * `--baseline <json>` (the "before" report), every key gets a verdict:
 *
 *   gone           in the baseline, not after
 *   still-present  in both
 *   new-high       not in the baseline, severity high or critical
 *   new-other      not in the baseline, lower severity
 *
 * The no-new-high rule passes when `new-high` is empty; the process exits 1 when
 * it fails, so a pipeline can gate on the exit code alone. No model, no network:
 * the same files give the same report.
 */

import { existsSync, readFileSync, statSync } from 'fs';
import { extname, isAbsolute, join, relative, resolve } from 'path';
import {
  analyzeProject,
  declAt,
  deriveStableIds,
  stableIdsSupport,
  type StableIdFile,
  type SupportedLanguage,
} from 'circle-ir';
import { SINK_CWE, SINK_SEVERITY } from './formatters.js';
import { UsageError } from './utils/options.js';

export const RECHECK_SCHEMA = 'cognium-recheck@0.1';

const LANG_BY_EXT: Record<string, SupportedLanguage> = {
  '.java': 'java', '.ts': 'typescript', '.tsx': 'typescript', '.js': 'javascript', '.jsx': 'javascript',
  '.mjs': 'javascript', '.cjs': 'javascript', '.py': 'python', '.go': 'go', '.cs': 'csharp', '.rs': 'rust',
} as Record<string, SupportedLanguage>;

const HIGH = new Set(['high', 'critical']);

export interface RecheckOptions {
  changed: string[];
  baseline?: string;
  output?: string;
}

export interface RecheckFinding {
  /** `cwe|file|declaration|rule` — the identity a verdict is about. */
  key: string;
  cwe: string;
  rule: string;
  severity: string;
  file: string;
  line: number;
  decl: { scheme: string; id: string; name: string };
  kind: 'flow' | 'pass';
}

export interface RecheckVerdict {
  key: string;
  verdict: 'gone' | 'still-present' | 'new-high' | 'new-other';
  cwe: string;
  rule: string;
  severity: string;
  file: string;
  /** Line after the change; the baseline line for `gone`. */
  line: number;
}

export interface RecheckReport {
  schema: typeof RECHECK_SCHEMA;
  files: string[];
  /** Files that could not be analysed (missing after the change, unsupported language). */
  skipped: Array<{ file: string; reason: string }>;
  findings: RecheckFinding[];
  /** Present only with --baseline. */
  verdicts?: RecheckVerdict[];
  summary?: { gone: number; stillPresent: number; newHigh: number; newOther: number };
  /** Present only with --baseline. */
  noNewHigh?: 'pass' | 'fail';
}

type Raw = Record<string, string | boolean | undefined>;

export function parseRecheckOptions(o: Raw): RecheckOptions {
  const c = o.changed;
  if (c === undefined || typeof c !== 'string' || c.trim() === '') {
    throw new UsageError('recheck requires --changed <file[,file…]> (or --changed @list.txt)');
  }
  const raw = c.startsWith('@') ? readFileSync(c.slice(1), 'utf8').split(/[\n,]/) : c.split(',');
  const changed = [...new Set(raw.map(s => s.trim()).filter(Boolean))].sort();
  if (changed.length === 0) throw new UsageError('--changed lists no files');
  const baseline = typeof o.baseline === 'string' ? o.baseline : undefined;
  if (o.baseline !== undefined && !baseline) throw new UsageError('--baseline needs a file');
  if (baseline && !existsSync(baseline)) throw new UsageError(`--baseline ${baseline}: no such file`);
  const output = typeof (o.output ?? o.o) === 'string' ? (o.output ?? o.o) as string : undefined;
  return { changed, baseline, output };
}

function norm(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '');
}

/** Analyse the changed files under `root` and key every security finding. */
export async function computeRecheck(root: string, opts: RecheckOptions): Promise<RecheckReport> {
  const base = resolve(root);
  if (!existsSync(base) || !statSync(base).isDirectory()) throw new UsageError(`recheck: ${root} is not a directory`);
  const skipped: RecheckReport['skipped'] = [];
  const inputs: Array<{ code: string; filePath: string; language: SupportedLanguage }> = [];
  const files: string[] = [];
  for (const f of opts.changed) {
    const rel = norm(isAbsolute(f) ? relative(base, f) : f);
    const abs = join(base, rel);
    files.push(rel);
    const language = LANG_BY_EXT[extname(rel).toLowerCase()];
    if (!language) { skipped.push({ file: rel, reason: 'unsupported language' }); continue; }
    if (!existsSync(abs)) { skipped.push({ file: rel, reason: 'not present' }); continue; }
    inputs.push({ code: readFileSync(abs, 'utf8'), filePath: rel, language });
  }

  const findings: RecheckFinding[] = [];
  if (inputs.length > 0) {
    const project = await analyzeProject(inputs);
    for (const { file, analysis: ir } of project.files) {
      const input = inputs.find(i => i.filePath === file);
      let ids: StableIdFile | undefined;
      if (input && stableIdsSupport(input.language)) {
        try { ids = await deriveStableIds(input.code, file, input.language); } catch { ids = undefined; }
      }
      const add = (kind: 'flow' | 'pass', rule: string, cwe: string | undefined, severity: string, line: number): void => {
        if (!cwe) return; // security findings only: the re-check is about CWEs
        const d = declAt(file, ir, line, ids);
        const decl = { scheme: d.scheme, id: d.id, name: d.name };
        findings.push({ key: `${cwe}|${file}|${decl.id}|${rule}`, cwe, rule, severity, file, line, decl, kind });
      };
      for (const flow of ir.taint.flows ?? []) {
        const t = flow.sink_type as keyof typeof SINK_CWE;
        add('flow', flow.sink_type, SINK_CWE[t], SINK_SEVERITY[t] ?? 'high', flow.sink_line);
      }
      for (const f of ir.findings ?? []) {
        if (f.category !== 'security') continue;
        add('pass', f.rule_id, f.cwe, f.severity, f.line);
      }
    }
  }
  // One entry per key (the first by line), sorted: same files → same report.
  const byKey = new Map<string, RecheckFinding>();
  for (const f of findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.key.localeCompare(b.key))) {
    if (!byKey.has(f.key)) byKey.set(f.key, f);
  }
  const report: RecheckReport = {
    schema: RECHECK_SCHEMA,
    files: files.sort(),
    skipped: skipped.sort((a, b) => a.file.localeCompare(b.file)),
    findings: [...byKey.values()],
  };
  if (opts.baseline) applyBaseline(report, readBaseline(opts.baseline));
  return report;
}

function readBaseline(path: string): RecheckReport {
  let b: RecheckReport;
  try {
    b = JSON.parse(readFileSync(path, 'utf8')) as RecheckReport;
  } catch {
    throw new UsageError(`--baseline ${path}: not JSON`);
  }
  if (b.schema !== RECHECK_SCHEMA || !Array.isArray(b.findings)) {
    throw new UsageError(`--baseline ${path}: not a ${RECHECK_SCHEMA} report (run recheck on the files before the change first)`);
  }
  return b;
}

/** Verdicts for `after` against `before` (pure). */
export function applyBaseline(after: RecheckReport, before: RecheckReport): RecheckReport {
  const now = new Map(after.findings.map(f => [f.key, f]));
  const then = new Map(before.findings.map(f => [f.key, f]));
  const verdicts: RecheckVerdict[] = [];
  for (const [key, f] of then) {
    const a = now.get(key);
    verdicts.push({ key, verdict: a ? 'still-present' : 'gone', cwe: f.cwe, rule: f.rule, severity: (a ?? f).severity, file: f.file, line: (a ?? f).line });
  }
  for (const [key, f] of now) {
    if (then.has(key)) continue;
    verdicts.push({ key, verdict: HIGH.has(f.severity) ? 'new-high' : 'new-other', cwe: f.cwe, rule: f.rule, severity: f.severity, file: f.file, line: f.line });
  }
  verdicts.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.key.localeCompare(b.key));
  const count = (v: RecheckVerdict['verdict']) => verdicts.filter(x => x.verdict === v).length;
  after.verdicts = verdicts;
  after.summary = { gone: count('gone'), stillPresent: count('still-present'), newHigh: count('new-high'), newOther: count('new-other') };
  after.noNewHigh = after.summary.newHigh === 0 ? 'pass' : 'fail';
  return after;
}
