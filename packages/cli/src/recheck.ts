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
 *   gone           in the baseline, not after; `reason` says why
 *   still-present  in both
 *   new-high       not in the baseline, severity high or critical
 *   new-other      not in the baseline, lower severity
 *   unknown        in the baseline, but its file did not parse fully after the
 *                  change or was not analysed: never read as `gone`
 *
 * Every finding and verdict carries its evidence: source, sink, hops,
 * sanitizers in the path and a line-free flow fingerprint.
 *
 * `--changed-from <ref>` derives the changed files from git (deletions and
 * renames included), takes the baseline from `<ref>` itself and scopes by
 * change closure: the whole tree is analysed and every finding whose sink,
 * source or path touches a changed file is reported.
 *
 * `--expect-gone <key[,…]>` names the findings the change is meant to fix;
 * the fix passes only when each of them is `gone` (and not gone because a
 * sanitizer for another sink class appeared).
 *
 * Exit codes: 0 pass; 1 the no-new-high rule or the fix check fails; 2 a usage
 * error; 3 a verdict is `unknown` (a changed file did not parse fully, or a
 * baseline file was not analysed). No model, no network: the same files give
 * the same report.
 */

import { createHash } from 'crypto';
import { execFileSync } from 'child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'fs';
import { extname, isAbsolute, join, relative, resolve } from 'path';
import {
  analyzeProject,
  declAt,
  deriveStableIds,
  stableIdsSupport,
  type CircleIR,
  type StableIdFile,
  type SupportedLanguage,
  type TaintPath,
} from 'circle-ir';
import { SINK_CWE, SINK_SEVERITY } from './formatters.js';
import { materializeBase } from './graph-facts.js';
import { UsageError } from './utils/options.js';
import { isScanSkippedDirectory } from './utils/skip-dirs.js';

export const RECHECK_SCHEMA = 'cognium-recheck@0.2';
/** Baselines written by earlier versions; read, never written. */
const READABLE_SCHEMAS = new Set([RECHECK_SCHEMA, 'cognium-recheck@0.1']);

const LANG_BY_EXT: Record<string, SupportedLanguage> = {
  '.java': 'java', '.ts': 'typescript', '.tsx': 'typescript', '.js': 'javascript', '.jsx': 'javascript',
  '.mjs': 'javascript', '.cjs': 'javascript', '.py': 'python', '.go': 'go', '.cs': 'csharp', '.rs': 'rust',
} as Record<string, SupportedLanguage>;

const HIGH = new Set(['high', 'critical']);

export type RecheckScope = 'files' | 'closure';

export interface RecheckOptions {
  /** Repository-relative or absolute paths; empty when `changedFrom` derives them. */
  changed: string[];
  /** A git ref: the changed files are `git diff <ref>` plus untracked files, and the baseline is `<ref>`. */
  changedFrom?: string;
  baseline?: string;
  /** `files` analyses only the changed files; `closure` the whole tree, reporting what touches them. */
  scope: RecheckScope;
  /** Keys the change is meant to fix. */
  expectGone: string[];
  output?: string;
}

export interface RecheckEvidence {
  /** sha256 (16 hex) of CWE, sink file, declaration and type, source file, declaration and type: no lines. */
  fingerprint: string;
  source?: { file: string; line: number; type: string; code?: string };
  sink: { file: string; line: number; type: string; code?: string };
  hops: Array<{ file: string; line: number; method?: string; variable?: string }>;
  sanitizers_in_path: string[];
  confidence?: number;
  /** Pass findings: the engine's message. */
  message?: string;
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
  evidence?: RecheckEvidence;
}

export type GoneReason =
  | 'sanitized-by'
  | 'sink-removed'
  | 'source-removed'
  | 'declaration-removed'
  | 'file-removed'
  | 'flow-not-found'
  | 'not-reported';
export type UnknownReason = 'parse-error' | 'not-analysed';

export interface RecheckVerdict {
  key: string;
  verdict: 'gone' | 'still-present' | 'new-high' | 'new-other' | 'unknown';
  cwe: string;
  rule: string;
  severity: string;
  file: string;
  /** Line after the change; the baseline line for `gone` and `unknown`. */
  line: number;
  /** Why a key is `gone` or `unknown`. */
  reason?: GoneReason | UnknownReason;
  /** `sanitized-by`: the sanitizers now in the declaration, and whether any of them covers the sink class. */
  sanitizers?: Array<{ method: string; line: number; sanitizes: string[] }>;
  sanitizerCoversSink?: boolean;
  /** The finding after the change; the baseline's for `gone` and `unknown`. */
  evidence?: RecheckEvidence;
}

export interface RecheckTarget {
  key: string;
  verdict: RecheckVerdict['verdict'] | 'not-in-baseline';
  reason?: string;
  fixed: boolean;
}

export interface RecheckReport {
  schema: typeof RECHECK_SCHEMA;
  scope: RecheckScope;
  /** `--changed-from`: the ref the changed files and the baseline come from. */
  changedFrom?: string;
  files: string[];
  /** Files that could not be analysed (missing after the change, unsupported language). */
  skipped: Array<{ file: string; reason: string }>;
  /** Changed files that did not parse fully; a key on them is `unknown`, never `gone`. */
  partialFiles: Array<{ file: string; errors: number; firstError?: { line: number; column: number } }>;
  findings: RecheckFinding[];
  /** Present only with a baseline. */
  verdicts?: RecheckVerdict[];
  summary?: { gone: number; stillPresent: number; newHigh: number; newOther: number; unknown: number };
  /** Present only with a baseline. */
  noNewHigh?: 'pass' | 'fail';
  /** Present only with --expect-gone. */
  targets?: RecheckTarget[];
  fixed?: 'pass' | 'fail';
}

type Raw = Record<string, string | boolean | undefined>;

function listOption(name: string, v: string | boolean | undefined): string[] | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== 'string' || v.trim() === '') throw new UsageError(`--${name} needs a value`);
  const raw = v.startsWith('@') ? readFileSync(v.slice(1), 'utf8').split(/[\n,]/) : v.split(',');
  return [...new Set(raw.map(s => s.trim()).filter(Boolean))].sort();
}

export function parseRecheckOptions(o: Raw): RecheckOptions {
  const changed = listOption('changed', o.changed);
  const changedFrom = o['changed-from'];
  if (changedFrom !== undefined && (typeof changedFrom !== 'string' || changedFrom.trim() === '' || changedFrom.startsWith('-'))) {
    throw new UsageError('--changed-from needs a git ref');
  }
  if (changed && changedFrom) throw new UsageError('give --changed or --changed-from, not both');
  if (!changed && !changedFrom) {
    throw new UsageError('recheck requires --changed <file[,file…]> (or --changed @list.txt), or --changed-from <git-ref>');
  }
  if (changed && changed.length === 0) throw new UsageError('--changed lists no files');
  const baseline = typeof o.baseline === 'string' ? o.baseline : undefined;
  if (o.baseline !== undefined && !baseline) throw new UsageError('--baseline needs a file');
  if (baseline && !existsSync(baseline)) throw new UsageError(`--baseline ${baseline}: no such file`);
  const scopeRaw = o.scope ?? (changedFrom ? 'closure' : 'files');
  if (scopeRaw !== 'files' && scopeRaw !== 'closure') throw new UsageError('--scope must be files or closure');
  const expectGone = listOption('expect-gone', o['expect-gone']) ?? [];
  if (expectGone.length > 0 && !baseline && !changedFrom) {
    throw new UsageError('--expect-gone needs --baseline or --changed-from: a verdict needs a before');
  }
  const output = typeof (o.output ?? o.o) === 'string' ? (o.output ?? o.o) as string : undefined;
  return { changed: changed ?? [], changedFrom: changedFrom as string | undefined, baseline, scope: scopeRaw, expectGone, output };
}

function norm(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '');
}

/**
 * The files changed between `ref` and the working tree under `root`, relative
 * to `root`: modified, added, deleted, both sides of a rename, and untracked
 * files that are not ignored.
 */
export function changedFromGit(root: string, ref: string): string[] {
  const git = (args: string[]): string =>
    execFileSync('git', ['-C', root, ...args], { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 256 * 1024 * 1024 }).toString();
  try {
    git(['rev-parse', '--verify', '--quiet', `${ref}^{commit}`]);
  } catch {
    throw new UsageError(`--changed-from '${ref}' is not a commit in a git repository holding ${root}`);
  }
  const out = new Set<string>();
  // `--relative` keeps paths under `root` and makes them relative to it.
  for (const line of git(['diff', '--name-status', '-M', '--relative', ref, '--']).split('\n')) {
    const parts = line.split('\t');
    if (parts.length < 2) continue;
    for (const p of parts.slice(1)) out.add(norm(p));
  }
  for (const line of git(['ls-files', '--others', '--exclude-standard']).split('\n')) {
    if (line.trim()) out.add(norm(line.trim()));
  }
  return [...out].sort();
}

/** Every file of the given languages under `dir`, relative, skipping dot entries and dependency/output directories. */
function treeFiles(dir: string, languages: ReadonlySet<SupportedLanguage>, rel = ''): string[] {
  const out: string[] = [];
  const entries = readdirSync(join(dir, rel), { withFileTypes: true })
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const e of entries) {
    if (e.name.startsWith('.')) continue;
    const p = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) {
      if (!isScanSkippedDirectory(e.name)) out.push(...treeFiles(dir, languages, p));
    } else if (e.isFile()) {
      const lang = LANG_BY_EXT[extname(e.name).toLowerCase()];
      if (lang && languages.has(lang)) out.push(p);
    }
  }
  return out;
}

function fingerprint(parts: string[]): string {
  return createHash('sha256').update(parts.join('\u0000')).digest('hex').slice(0, 16);
}

/** What the after side holds per declaration, for the reason on a `gone`. */
interface DeclInventory {
  sinks: Set<string>;
  sources: number;
  sanitizers: Array<{ method: string; line: number; sanitizes: string[] }>;
}

/** Internal facts of one analysis that a verdict needs beyond the report. */
export interface RecheckContext {
  /** Every key found in the analysed tree, in scope or not (closure: a key is not `gone` just because its path left the changed files). */
  allKeys: Set<string>;
  /** Declaration ids present per file (stable ids or the qualified name fallback). */
  decls: Map<string, Set<string>>;
  /** `file|declId` → what the declaration holds. */
  inventory: Map<string, DeclInventory>;
  /** Files analysed (closure: the tree; files: the changed list minus skipped). */
  analysed: Set<string>;
}

interface Analysis {
  report: RecheckReport;
  ctx: RecheckContext;
}

async function analyse(base: string, changed: string[], scope: RecheckScope): Promise<Analysis> {
  const skipped: RecheckReport['skipped'] = [];
  const files: string[] = [];
  const changedSet = new Set<string>();
  const languages = new Set<SupportedLanguage>();
  for (const f of changed) {
    const rel = norm(isAbsolute(f) ? relative(base, f) : f);
    files.push(rel);
    changedSet.add(rel);
    const language = LANG_BY_EXT[extname(rel).toLowerCase()];
    if (!language) { skipped.push({ file: rel, reason: 'unsupported language' }); continue; }
    languages.add(language);
    if (!existsSync(join(base, rel))) { skipped.push({ file: rel, reason: 'not present' }); continue; }
  }
  const skippedSet = new Set(skipped.map(s => s.file));
  const toRead = scope === 'closure' && languages.size > 0
    ? treeFiles(base, languages)
    : files.filter(f => !skippedSet.has(f));
  const inputs = toRead.map(rel => ({
    code: readFileSync(join(base, rel), 'utf8'),
    filePath: rel,
    language: LANG_BY_EXT[extname(rel).toLowerCase()],
  }));

  const findings: RecheckFinding[] = [];
  const partialFiles: RecheckReport['partialFiles'] = [];
  const ctx: RecheckContext = { allKeys: new Set(), decls: new Map(), inventory: new Map(), analysed: new Set(toRead) };
  if (inputs.length > 0) {
    const project = await analyzeProject(inputs);
    const byFile = new Map(project.files.map(f => [f.file, f.analysis]));
    const inputByFile = new Map(inputs.map(i => [i.filePath, i]));
    const idsCache = new Map<string, StableIdFile | undefined>();
    const idsOf = async (file: string): Promise<StableIdFile | undefined> => {
      if (idsCache.has(file)) return idsCache.get(file);
      const input = inputByFile.get(file);
      let ids: StableIdFile | undefined;
      if (input && stableIdsSupport(input.language)) {
        try { ids = await deriveStableIds(input.code, file, input.language); } catch { ids = undefined; }
      }
      idsCache.set(file, ids);
      return ids;
    };
    const declOf = async (file: string, line: number) => {
      const ir = byFile.get(file);
      if (!ir) return undefined;
      const d = declAt(file, ir, line, await idsOf(file));
      return { scheme: d.scheme, id: d.id, name: d.name };
    };
    // A finding is in scope when it sits in a changed file or its path touches one.
    const inScope = (file: string, ev?: RecheckEvidence): boolean =>
      changedSet.has(file)
      || (scope === 'closure' && !!ev && (
        (ev.source !== undefined && changedSet.has(ev.source.file)) || ev.hops.some(h => changedSet.has(h.file))));

    const add = async (
      file: string, ir: CircleIR, kind: 'flow' | 'pass', rule: string, cwe: string | undefined,
      severity: string, line: number, ev: Omit<RecheckEvidence, 'fingerprint'>, sourceDeclId?: string,
    ): Promise<void> => {
      if (!cwe) return; // security findings only: the re-check is about CWEs
      const d = declAt(file, ir, line, await idsOf(file));
      const decl = { scheme: d.scheme, id: d.id, name: d.name };
      const key = `${cwe}|${file}|${decl.id}|${rule}`;
      ctx.allKeys.add(key);
      const evidence: RecheckEvidence = {
        fingerprint: fingerprint([cwe, file, decl.id, ev.sink.type, ev.source?.file ?? '', sourceDeclId ?? '', ev.source?.type ?? '']),
        ...ev,
      };
      if (!inScope(file, evidence)) return;
      findings.push({ key, cwe, rule, severity, file, line, decl, kind, evidence });
    };

    for (const { file, analysis: ir } of project.files) {
      const ids = await idsOf(file);
      const ps = ir.parse_status;
      if (ps && !ps.success && changedSet.has(file)) {
        const first = [...(ps.error_locations ?? [])].sort((a, b) => a.line - b.line || a.column - b.column)[0];
        partialFiles.push({ file, errors: ps.error_count ?? 0, ...(first ? { firstError: { line: first.line, column: first.column } } : {}) });
      }
      // Declarations and what each holds, for the reason on a `gone`.
      const declIds = new Set<string>();
      for (const d of ids?.decls ?? []) declIds.add(d.id);
      const inv = (line: number): DeclInventory => {
        const id = declAt(file, ir, line, ids).id;
        declIds.add(id);
        const k = `${file}|${id}`;
        let e = ctx.inventory.get(k);
        if (!e) { e = { sinks: new Set(), sources: 0, sanitizers: [] }; ctx.inventory.set(k, e); }
        return e;
      };
      for (const s of ir.taint.sinks ?? []) inv(s.line).sinks.add(s.type);
      for (const s of ir.taint.sources ?? []) inv(s.line).sources++;
      for (const s of ir.taint.sanitizers ?? []) inv(s.line).sanitizers.push({ method: s.method, line: s.line, sanitizes: [...s.sanitizes] });
      ctx.decls.set(file, declIds);

      const sanitizersBetween = (a: number, b: number, sinkType: string): string[] => {
        const lo = Math.min(a, b), hi = Math.max(a, b);
        return (ir.taint.sanitizers ?? [])
          .filter(s => s.line >= lo && s.line <= hi && (s.sanitizes as string[]).includes(sinkType))
          .map(s => s.method);
      };
      for (const flow of ir.taint.flows ?? []) {
        const t = flow.sink_type as keyof typeof SINK_CWE;
        const path = findPath(project.taint_paths ?? [], file, flow);
        const sourceFile = path?.source.file ?? file;
        const sinkCode = path?.sink.code?.trim() ?? (ir.taint.sinks ?? []).find(s => s.line === flow.sink_line && s.type === flow.sink_type)?.code;
        const sourceCode = path?.source.code?.trim() ?? (sourceFile === file
          ? (ir.taint.sources ?? []).find(s => s.line === flow.source_line && s.type === flow.source_type)?.code
          : undefined);
        const hops = path
          ? path.hops.map(h => ({ file: h.file, line: h.line, ...(h.method ? { method: h.method } : {}), ...(h.variable ? { variable: h.variable } : {}) }))
          : flow.path.map(s => ({ file, line: s.line, ...(s.variable ? { variable: s.variable } : {}) }));
        const sanitizers = [...new Set([...(path?.sanitizers_in_path ?? []), ...(sourceFile === file ? sanitizersBetween(flow.source_line, flow.sink_line, flow.sink_type) : [])])].sort();
        const sourceDecl = await declOf(sourceFile, flow.source_line);
        await add(file, ir, 'flow', flow.sink_type, SINK_CWE[t], SINK_SEVERITY[t] ?? 'high', flow.sink_line, {
          source: { file: sourceFile, line: flow.source_line, type: flow.source_type, ...(sourceCode ? { code: sourceCode } : {}) },
          sink: { file, line: flow.sink_line, type: flow.sink_type, ...(sinkCode ? { code: sinkCode } : {}) },
          hops,
          sanitizers_in_path: sanitizers,
          confidence: path?.confidence ?? flow.confidence,
        }, sourceDecl?.id);
      }
      for (const f of ir.findings ?? []) {
        if (f.category !== 'security') continue;
        await add(file, ir, 'pass', f.rule_id, f.cwe, f.severity, f.line, {
          sink: { file, line: f.line, type: f.rule_id },
          hops: [],
          sanitizers_in_path: [],
          ...(f.message ? { message: f.message } : {}),
        });
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
    scope,
    files: files.sort(),
    skipped: skipped.sort((a, b) => a.file.localeCompare(b.file)),
    partialFiles: partialFiles.sort((a, b) => a.file.localeCompare(b.file)),
    findings: [...byKey.values()],
  };
  return { report, ctx };
}

/** The project taint path a per-file flow mirrors (same sink, same source line and type), if any. */
function findPath(paths: TaintPath[], file: string, flow: { sink_line: number; sink_type: string; source_line: number; source_type: string }): TaintPath | undefined {
  const hits = paths.filter(p =>
    p.path_exists && p.sink.file === file && p.sink.line === flow.sink_line && p.sink.type === flow.sink_type
    && p.source.line === flow.source_line && p.source.type === flow.source_type);
  // Prefer the in-file path, then the first by source file: deterministic.
  return hits.sort((a, b) => Number(b.source.file === file) - Number(a.source.file === file) || a.source.file.localeCompare(b.source.file))[0];
}

/** Analyse the changed files under `root` and key every security finding. */
export async function computeRecheck(root: string, opts: RecheckOptions): Promise<RecheckReport> {
  const base = resolve(root);
  if (!existsSync(base) || !statSync(base).isDirectory()) throw new UsageError(`recheck: ${root} is not a directory`);
  const changed = opts.changedFrom ? changedFromGit(base, opts.changedFrom) : opts.changed;
  const after = await analyse(base, changed, opts.scope);
  if (opts.changedFrom) after.report.changedFrom = opts.changedFrom;

  let before: RecheckReport | undefined;
  if (opts.baseline) {
    before = readBaseline(opts.baseline);
  } else if (opts.changedFrom) {
    const ref = materializeBase(base, opts.changedFrom);
    try {
      before = (await analyse(ref.dir, changed, opts.scope)).report;
    } finally {
      ref.cleanup();
    }
  }
  if (before) applyBaseline(after.report, before, after.ctx);
  if (opts.expectGone.length > 0) applyTargets(after.report, opts.expectGone);
  return after.report;
}

function readBaseline(path: string): RecheckReport {
  let b: RecheckReport;
  try {
    b = JSON.parse(readFileSync(path, 'utf8')) as RecheckReport;
  } catch {
    throw new UsageError(`--baseline ${path}: not JSON`);
  }
  if (!READABLE_SCHEMAS.has(b.schema) || !Array.isArray(b.findings)) {
    throw new UsageError(`--baseline ${path}: not a ${RECHECK_SCHEMA} report (run recheck on the files before the change first)`);
  }
  return b;
}

/** Why a baseline key is missing after the change; `unknown` when the after side cannot say. */
function explainMissing(
  f: RecheckFinding, after: RecheckReport, ctx: RecheckContext | undefined,
): Pick<RecheckVerdict, 'verdict' | 'reason' | 'sanitizers' | 'sanitizerCoversSink'> {
  const skip = (after.skipped ?? []).find(s => s.file === f.file);
  if (skip?.reason === 'not present') return { verdict: 'gone', reason: 'file-removed' };
  if ((after.partialFiles ?? []).some(p => p.file === f.file)) return { verdict: 'unknown', reason: 'parse-error' };
  const analysed = ctx ? ctx.analysed.has(f.file) : after.files.includes(f.file) && !skip;
  if (skip || !analysed) return { verdict: 'unknown', reason: 'not-analysed' };
  if (!ctx) return { verdict: 'gone' };
  const decls = ctx.decls.get(f.file);
  if (decls && !decls.has(f.decl.id)) return { verdict: 'gone', reason: 'declaration-removed' };
  if (f.kind === 'pass') return { verdict: 'gone', reason: 'not-reported' };
  const inv = ctx.inventory.get(`${f.file}|${f.decl.id}`);
  if (inv && inv.sanitizers.length > 0) {
    const sanitizers = [...inv.sanitizers].sort((a, b) => a.line - b.line || a.method.localeCompare(b.method));
    return { verdict: 'gone', reason: 'sanitized-by', sanitizers, sanitizerCoversSink: sanitizers.some(s => s.sanitizes.includes(f.rule)) };
  }
  if (!inv || !inv.sinks.has(f.rule)) return { verdict: 'gone', reason: 'sink-removed' };
  const src = f.evidence?.source;
  if (src && src.file === f.file && inv.sources === 0) return { verdict: 'gone', reason: 'source-removed' };
  return { verdict: 'gone', reason: 'flow-not-found' };
}

/**
 * Verdicts for `after` against `before`. Pure: `ctx` (the after side's
 * declarations and inventory) only refines the reason on a missing key; without
 * it a missing key is `gone` unless its file was skipped, partial or not listed.
 */
export function applyBaseline(after: RecheckReport, before: RecheckReport, ctx?: RecheckContext): RecheckReport {
  const now = new Map(after.findings.map(f => [f.key, f]));
  const then = new Map(before.findings.map(f => [f.key, f]));
  const verdicts: RecheckVerdict[] = [];
  const ev = (f: RecheckFinding) => (f.evidence ? { evidence: f.evidence } : {});
  for (const [key, f] of then) {
    const a = now.get(key);
    if (a || ctx?.allKeys.has(key)) {
      const cur = a ?? f;
      verdicts.push({ key, verdict: 'still-present', cwe: f.cwe, rule: f.rule, severity: cur.severity, file: f.file, line: cur.line, ...ev(cur) });
      continue;
    }
    const why = explainMissing(f, after, ctx);
    verdicts.push({ key, cwe: f.cwe, rule: f.rule, severity: f.severity, file: f.file, line: f.line, ...why, ...ev(f) });
  }
  for (const [key, f] of now) {
    if (then.has(key)) continue;
    verdicts.push({ key, verdict: HIGH.has(f.severity) ? 'new-high' : 'new-other', cwe: f.cwe, rule: f.rule, severity: f.severity, file: f.file, line: f.line, ...ev(f) });
  }
  verdicts.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.key.localeCompare(b.key));
  const count = (v: RecheckVerdict['verdict']) => verdicts.filter(x => x.verdict === v).length;
  after.verdicts = verdicts;
  after.summary = { gone: count('gone'), stillPresent: count('still-present'), newHigh: count('new-high'), newOther: count('new-other'), unknown: count('unknown') };
  after.noNewHigh = after.summary.newHigh === 0 ? 'pass' : 'fail';
  return after;
}

/**
 * `--expect-gone`: each target must be `gone`. A `gone` by a sanitizer that
 * covers none of the sink's class (an HTML encoder before a SQL sink) does not
 * count as fixed. Pure.
 */
export function applyTargets(report: RecheckReport, keys: string[]): RecheckReport {
  const byKey = new Map((report.verdicts ?? []).map(v => [v.key, v]));
  report.targets = [...new Set(keys)].sort().map((key): RecheckTarget => {
    const v = byKey.get(key);
    if (!v || v.verdict === 'new-high' || v.verdict === 'new-other') return { key, verdict: 'not-in-baseline', fixed: false };
    const fixed = v.verdict === 'gone' && !(v.reason === 'sanitized-by' && v.sanitizerCoversSink === false);
    return { key, verdict: v.verdict, ...(v.reason ? { reason: v.reason } : {}), fixed };
  });
  report.fixed = report.targets.every(t => t.fixed) ? 'pass' : 'fail';
  return report;
}

/** 3 when a verdict is `unknown`; 1 when the no-new-high rule or the fix check fails; else 0. */
export function recheckExitCode(report: RecheckReport): number {
  if ((report.summary?.unknown ?? 0) > 0) return 3;
  if (report.noNewHigh === 'fail' || report.fixed === 'fail') return 1;
  return 0;
}
