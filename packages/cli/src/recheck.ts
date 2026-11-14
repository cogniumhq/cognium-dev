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
 *   still-present  in both; or re-keyed: the declaration's id moved (an anonymous
 *                  handler is keyed by position, so an inserted import moves it)
 *                  and one after finding under a new key has the same flow
 *                  identity (`reason: rekeyed`, `rekeyedTo`)
 *   new-high       not in the baseline, severity high or critical
 *   new-other      not in the baseline, lower severity
 *   unknown        in the baseline, but its file did not parse fully after the
 *                  change or was not analysed, or more than one finding could be
 *                  it re-keyed (`rekey-ambiguous`): never read as `gone`
 *
 * Every finding and verdict carries its evidence: source, sink, hops,
 * sanitizers in the path and a line-free flow fingerprint.
 *
 * `--changed-from <ref>` derives the changed files from git (deletions and
 * renames included), takes the baseline from `<ref>` itself and scopes by
 * change closure: the whole tree is analysed and every finding whose sink,
 * source or path touches a changed file is reported.
 *
 * Moves across files: a key holds its file, so a method moved to another file,
 * or a class renamed together with its file, would read as a `gone` plus a new
 * finding. When the move is evidenced, the baseline finding is matched to the one
 * after finding of the same flow identity (file left out) in the file or
 * declaration it moved to: `still-present`, `reason: moved`, `movedFrom`. The
 * evidence is a git rename or copy (`--changed-from`), a caller's rename map
 * (`--renames`), or a declaration whose body settled as a move by its body hash
 * (circle-ir `detectMoves`). More than one candidate is `unknown`
 * (`move-ambiguous`), never `gone`; a moved finding whose flow changed (a
 * removed sink, an added sanitizer) is `gone`, its reason taken from where it
 * moved to. Without evidence nothing changes. A rename's new path is added to
 * `--changed`, so the file it moved to is analysed; a declaration moved into a
 * file that is not otherwise renamed is matched only when that file is analysed
 * (listed in `--changed`, or `--scope closure`, as `--changed-from` implies).
 *
 * Flows inside a key: one method can hold several flows of one rule (two SQL
 * sinks in one handler); they share the key. The report lists them under it
 * (`flows`, by flow identity), and a verdict on a key still reported says, per
 * baseline flow, whether it is still there: a key where some flows are gone and
 * others remain is `still-present` with `partial: true`, and a new flow of the
 * same rule in the same method is a `new-high` / `new-other` entry with
 * `newFlow: true` beside the key's own verdict. Needs a `cognium-recheck@0.4`
 * baseline; an earlier one kept only the first flow per key.
 *
 * `--expect-gone <key[,…]>` names the findings the change is meant to fix;
 * the fix passes only when each of them is `gone`, every flow of it (and not
 * gone because a sanitizer for another sink class appeared). A partial fix fails
 * with reason `partial-fix`.
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
  detectMoves,
  stableIdsSupport,
  type CircleIR,
  type StableIdFile,
  type StableDecl,
  type SupportedLanguage,
  type TaintPath,
} from 'circle-ir';
import { SINK_CWE, SINK_SEVERITY } from './formatters.js';
import { materializeBase } from './graph-facts.js';
import { UsageError } from './utils/options.js';
import { isScanSkippedDirectory } from './utils/skip-dirs.js';

export const RECHECK_SCHEMA = 'cognium-recheck@0.4';
/** Baselines written by earlier versions; read, never written. */
const READABLE_SCHEMAS = new Set([RECHECK_SCHEMA, 'cognium-recheck@0.3', 'cognium-recheck@0.2', 'cognium-recheck@0.1']);

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
  /** File renames the caller vouches for (`--renames`), baseline path → after path. */
  renames?: Array<[string, string]>;
  output?: string;
}

export interface RecheckEvidence {
  /** sha256 (16 hex) of CWE, sink file, declaration and type, source file, declaration and type: no lines. */
  fingerprint: string;
  /**
   * `params`: the source is a parameter of a named method (a Spring `@RequestParam`,
   * or an inter-procedural parameter), whose `code` is the method's header line.
   * The parameter's name, declared type and annotations identify the source without
   * the header. When the engine does not say which of the header's source
   * parameters the flow starts from, all of them are listed.
   */
  source?: { file: string; line: number; type: string; code?: string; params?: RecheckParamSource[] };
  sink: { file: string; line: number; type: string; code?: string };
  hops: Array<{ file: string; line: number; method?: string; variable?: string }>;
  sanitizers_in_path: string[];
  /**
   * Flow findings: every sanitizer call in the sink's enclosing declaration (method
   * names, sorted, repeats kept), whatever it sanitizes. A later `sanitized-by` is
   * given only for a sanitizer this list does not already hold.
   */
  decl_sanitizers?: string[];
  confidence?: number;
  /** Pass findings: the engine's message. */
  message?: string;
}

/** A method parameter as a flow source: what a rename of the method or another parameter leaves alone. */
export interface RecheckParamSource {
  name: string;
  type?: string;
  annotations: string[];
}

export interface RecheckFinding {
  /** `cwe|file|declaration|rule` — the identity a verdict is about. */
  key: string;
  cwe: string;
  rule: string;
  severity: string;
  file: string;
  line: number;
  /**
   * The enclosing declaration. For an `ids@0.1` declaration, also its kind, body
   * hash and body token count: what a later run needs to tell that the
   * declaration moved to another file (absent from baselines written before).
   */
  decl: { scheme: string; id: string; name: string; kind?: string; bodyHash?: string; tokens?: number };
  kind: 'flow' | 'pass';
  evidence?: RecheckEvidence;
  /**
   * Every distinct flow under the key (distinct by flow identity), by line, when
   * there is more than one: two SQL sinks in one method share a key. Absent when
   * the key holds one flow, which `evidence` describes (from `cognium-recheck@0.4`;
   * an earlier baseline kept only the first flow per key).
   */
  flows?: RecheckFlow[];
}

/** One flow (or one pass occurrence) under a key. */
export interface RecheckFlow {
  /** sha256 (16 hex) of the flow identity ({@link flowIdentity}): no line, no declaration. */
  identity: string;
  line: number;
  evidence: RecheckEvidence;
}

/**
 * A flow's verdict inside a key: `still-present` (an after flow of the same flow
 * identity), `gone` (none, and no after flow left to pair it with), `changed` (no
 * flow of its identity, paired in line order with an after flow that matches no
 * baseline flow: the same flow with its sink, source or sanitizers edited; it is
 * still there), or `new` (an after flow that matches and pairs with no baseline flow).
 */
export type RecheckFlowVerdict = 'still-present' | 'gone' | 'changed' | 'new';

export type GoneReason =
  | 'sanitized-by'
  | 'sink-removed'
  | 'source-removed'
  | 'declaration-removed'
  | 'file-removed'
  | 'flow-not-found'
  | 'not-reported';
export type UnknownReason = 'parse-error' | 'not-analysed' | 'rekey-ambiguous' | 'move-ambiguous';
/**
 * A `still-present` whose key changed: the declaration was re-keyed, the flow is
 * the same (`rekeyed`), or the finding moved to another file on evidence (`moved`).
 */
export type StillPresentReason = 'rekeyed' | 'moved';
/** Why a finding is taken to have moved to another file. */
export type MoveEvidenceKind = 'git-rename' | 'git-copy' | 'rename-map' | 'body-hash';

export interface RecheckVerdict {
  key: string;
  verdict: 'gone' | 'still-present' | 'new-high' | 'new-other' | 'unknown';
  cwe: string;
  rule: string;
  severity: string;
  file: string;
  /** Line after the change; the baseline line for `gone` and `unknown`. */
  line: number;
  /** Why a key is `gone` or `unknown`, or `rekeyed` for a `still-present` found under a new key. */
  reason?: GoneReason | UnknownReason | StillPresentReason;
  /**
   * `still-present` / `rekeyed`: the key the same flow has after the change. The
   * declaration's stable id moved (an anonymous handler is keyed by position), the
   * flow did not: same rule, CWE, file, sink and source code and types, sanitizers.
   */
  rekeyedTo?: string;
  /** How a baseline key was matched to a different after key. */
  matchedBy?: 'flow-identity' | 'move';
  /**
   * `still-present` / `moved`: the baseline file the finding moved from (`file` is
   * where it is after the change). `gone` after a move: the file the reason was
   * taken from is `movedTo`.
   */
  movedFrom?: string;
  movedTo?: string;
  /** `moved`, `move-ambiguous`, or a `gone` after a move: what evidences the move. */
  moveEvidence?: MoveEvidenceKind[];
  /** `unknown` / `rekey-ambiguous` or `move-ambiguous`: the after keys that could be it, none chosen. */
  rekeyCandidates?: string[];
  /**
   * `gone`: the after declaration the reason was taken from when the baseline
   * declaration's id is gone but one after declaration has the same name once
   * positions are left out (an anonymous handler after an inserted import).
   */
  successorDecl?: string;
  /**
   * `sanitized-by`: the sanitizers in the declaration that the baseline finding's
   * declaration and path did not already hold, and whether any of them covers the
   * sink class.
   */
  sanitizers?: Array<{ method: string; line: number; sanitizes: string[] }>;
  sanitizerCoversSink?: boolean;
  /** The finding after the change; the baseline's for `gone` and `unknown`. */
  evidence?: RecheckEvidence;
  /**
   * Per-flow detail, when the baseline or the after key holds more than one flow
   * (needs a `cognium-recheck@0.4` baseline for a key that is still reported). Each
   * baseline flow, and each after flow that is new, with its verdict.
   */
  flows?: Array<{ identity: string; verdict: RecheckFlowVerdict; line: number; sink?: string }>;
  /**
   * `still-present`: some of the key's baseline flows are gone and others remain.
   * The key is not fixed.
   */
  partial?: boolean;
  /**
   * `new-high` / `new-other`: a new flow under a key that is still reported (`key`
   * is the key after the change), not a new key. A key's verdict stays one entry;
   * this entry is beside it, so a key can appear twice in `verdicts`.
   */
  newFlow?: boolean;
}

export interface RecheckTarget {
  key: string;
  verdict: RecheckVerdict['verdict'] | 'not-in-baseline';
  /** The verdict's reason; `partial-fix` when some of the key's flows are gone and others remain. */
  reason?: string;
  fixed: boolean;
  /** With per-flow detail: how many of the key's baseline flows are gone or remain, and how many are new. */
  flows?: { gone: number; remaining: number; new: number };
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
  const renames = parseRenames(o.renames);
  // A renamed file's new path is in scope: the finding that moved there is looked for.
  const changedAll = changed && renames ? [...new Set([...changed, ...renames.flatMap(([a, b]) => [norm(a), norm(b)])])].sort() : changed;
  return {
    changed: changedAll ?? [], changedFrom: changedFrom as string | undefined, baseline, scope: scopeRaw, expectGone, output,
    ...(renames ? { renames } : {}),
  };
}

/**
 * `--renames old=new[,…]` or `@file`: file renames the caller vouches for, one
 * per line or comma. A line may also be `old<TAB>new` or a
 * `git diff --name-status -M` line (`R100<TAB>old<TAB>new`, `C…` for a copy).
 */
function parseRenames(v: string | boolean | undefined): Array<[string, string]> | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== 'string' || v.trim() === '') throw new UsageError('--renames needs a value');
  const lines = v.startsWith('@') ? readFileSync(v.slice(1), 'utf8').split('\n') : v.split(',');
  const out = new Map<string, string>();
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    let parts = line.includes('\t') ? line.split('\t').map(x => x.trim()) : line.split('=').map(x => x.trim());
    if (parts.length === 3 && /^[RC]\d*$/.test(parts[0])) parts = parts.slice(1);
    if (parts.length !== 2 || !parts[0] || !parts[1] || parts[0] === parts[1]) {
      throw new UsageError(`--renames: '${line}' is not old=new`);
    }
    const [from, to] = [norm(parts[0]), norm(parts[1])];
    if (out.has(from) && out.get(from) !== to) throw new UsageError(`--renames: ${from} is renamed twice`);
    out.set(from, to);
  }
  if (out.size === 0) throw new UsageError('--renames lists no renames');
  return [...out].sort((a, b) => a[0].localeCompare(b[0]));
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

/**
 * The renames and copies git finds between `ref` and the working tree under
 * `root` (`git diff -M -C`), relative to `root`: evidence that a finding moved
 * with its file.
 */
export function renamesFromGit(root: string, ref: string): Array<{ from: string; to: string; evidence: MoveEvidenceKind }> {
  const out = execFileSync('git', ['-C', root, 'diff', '--name-status', '-M', '-C', '--relative', ref, '--'],
    { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 256 * 1024 * 1024 }).toString();
  const renames: Array<{ from: string; to: string; evidence: MoveEvidenceKind }> = [];
  for (const line of out.split('\n')) {
    const parts = line.split('\t');
    if (parts.length !== 3 || !/^[RC]/.test(parts[0])) continue;
    renames.push({ from: norm(parts[1]), to: norm(parts[2]), evidence: parts[0].startsWith('R') ? 'git-rename' : 'git-copy' });
  }
  return renames.sort((a, b) => a.from.localeCompare(b.from) || a.to.localeCompare(b.to));
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
  /** Qualified name per declaration id, per file. */
  declNames?: Map<string, Map<string, string>>;
  /** `file|declId` → what the declaration holds. */
  inventory: Map<string, DeclInventory>;
  /** Files analysed (closure: the tree; files: the changed list minus skipped). */
  analysed: Set<string>;
  /** The after side's `ids@0.1` declarations per analysed file, for move detection. */
  ids?: Map<string, StableIdFile>;
  /** Evidenced moves from the baseline to the after side ({@link detectFindingMoves}). */
  moves?: RecheckMoves;
}

/** Where baseline findings may have moved, and on what evidence. */
export interface RecheckMoves {
  /** File renames and copies: baseline path → after paths. */
  files: Map<string, Array<{ to: string; evidence: MoveEvidenceKind }>>;
  /**
   * `file|declId` of a baseline declaration → the after declarations it may have
   * moved to by body hash. `settled` is false for a shared body hash (more than one
   * declaration could be it): such a target can only make a verdict `unknown`.
   */
  decls: Map<string, Array<{ file: string; declId: string; settled: boolean }>>;
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
  const ctx: RecheckContext = { allKeys: new Set(), decls: new Map(), declNames: new Map(), inventory: new Map(), analysed: new Set(toRead), ids: new Map() };
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
      const ids = await idsOf(file);
      const d = declAt(file, ir, line, ids);
      const sd = d.scheme === 'ids@0.1' ? ids?.decls.find(x => x.id === d.id) : undefined;
      const decl: RecheckFinding['decl'] = {
        scheme: d.scheme, id: d.id, name: d.name,
        ...(sd && sd.body_hash ? { kind: sd.kind, bodyHash: sd.body_hash, tokens: sd.token_count } : {}),
      };
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
      if (ids) ctx.ids!.set(file, ids);
      const ps = ir.parse_status;
      if (ps && !ps.success && changedSet.has(file)) {
        const first = [...(ps.error_locations ?? [])].sort((a, b) => a.line - b.line || a.column - b.column)[0];
        partialFiles.push({ file, errors: ps.error_count ?? 0, ...(first ? { firstError: { line: first.line, column: first.column } } : {}) });
      }
      // Declarations and what each holds, for the reason on a `gone`.
      const declIds = new Set<string>();
      const names = new Map<string, string>();
      for (const d of ids?.decls ?? []) { declIds.add(d.id); names.set(d.id, d.qualified_name); }
      const inv = (line: number): DeclInventory => {
        const d = declAt(file, ir, line, ids);
        const id = d.id;
        declIds.add(id);
        if (!names.has(id)) names.set(id, d.name);
        const k = `${file}|${id}`;
        let e = ctx.inventory.get(k);
        if (!e) { e = { sinks: new Set(), sources: 0, sanitizers: [] }; ctx.inventory.set(k, e); }
        return e;
      };
      for (const s of ir.taint.sinks ?? []) inv(s.line).sinks.add(s.type);
      for (const s of ir.taint.sources ?? []) inv(s.line).sources++;
      for (const s of ir.taint.sanitizers ?? []) inv(s.line).sanitizers.push({ method: s.method, line: s.line, sanitizes: [...s.sanitizes] });
      ctx.decls.set(file, declIds);
      ctx.declNames!.set(file, names);
      const lines = inputByFile.get(file)?.code.split('\n') ?? [];

      const declSanitizers = (line: number): string[] =>
        (ctx.inventory.get(`${file}|${declAt(file, ir, line, ids).id}`)?.sanitizers ?? []).map(s => s.method).sort();
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
        const params = paramSources(byFile.get(sourceFile), flow);
        await add(file, ir, 'flow', flow.sink_type, SINK_CWE[t], SINK_SEVERITY[t] ?? 'high', flow.sink_line, {
          source: { file: sourceFile, line: flow.source_line, type: flow.source_type, ...(sourceCode ? { code: sourceCode } : {}), ...(params ? { params } : {}) },
          sink: { file, line: flow.sink_line, type: flow.sink_type, ...(sinkCode ? { code: sinkCode } : {}) },
          hops,
          sanitizers_in_path: sanitizers,
          decl_sanitizers: declSanitizers(flow.sink_line),
          confidence: path?.confidence ?? flow.confidence,
        }, sourceDecl?.id);
      }
      for (const f of ir.findings ?? []) {
        if (f.category !== 'security') continue;
        await add(file, ir, 'pass', f.rule_id, f.cwe, f.severity, f.line, {
          sink: { file, line: f.line, type: f.rule_id, ...(lines[f.line - 1]?.trim() ? { code: lines[f.line - 1].trim() } : {}) },
          hops: [],
          sanitizers_in_path: [],
          ...(f.message ? { message: f.message } : {}),
        });
      }
    }
  }
  // One entry per key (the first by line), sorted: same files → same report.
  // The key's other flows, distinct by flow identity, are listed under it.
  const byKey = new Map<string, RecheckFinding>();
  const flowsByKey = new Map<string, Map<string, RecheckFlow>>();
  for (const f of findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.key.localeCompare(b.key))) {
    if (!byKey.has(f.key)) byKey.set(f.key, f);
    const id = flowIdentity(f);
    if (!id || !f.evidence) continue;
    const m = flowsByKey.get(f.key) ?? new Map<string, RecheckFlow>();
    if (!m.has(id)) m.set(id, { identity: fingerprint([id]), line: f.line, evidence: f.evidence });
    flowsByKey.set(f.key, m);
  }
  for (const [key, m] of flowsByKey) if (m.size > 1) byKey.get(key)!.flows = [...m.values()];
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

/**
 * The parameters a flow's source is, when the source sits on the header of a named
 * method (on the parameter's own line, for a header split over lines). The flow's
 * first variable names the parameter when it is one (`name`, or `@RequestParam
 * name in handle`). Otherwise the engine does not
 * say which, and the candidates are the parameters on that line that the engine
 * lists as sources, plus, for a request source, the annotated ones; a single
 * candidate is the parameter, several are all listed. A parameter that is not a
 * source (an added `int page`) is left out, so adding it keeps the identity.
 * Undefined otherwise: a call such as `req.getParameter("id")`, or an anonymous
 * handler, which `ir.types` does not list, keeps its source code as its identity.
 */
function paramSources(
  ir: CircleIR | undefined,
  flow: { source_line: number; source_type: string; path: Array<{ variable: string; line: number; type: string }> },
): RecheckParamSource[] | undefined {
  if (!ir) return undefined;
  const line = flow.source_line;
  const method = (ir.types ?? []).flatMap(t => t.methods ?? [])
    .find(m => m.name && m.start_line <= line && m.end_line >= line && m.parameters.some(p => p.line === line));
  if (!method) return undefined;
  const onLine = method.parameters.filter(p => p.line === line);
  const of = (p: (typeof onLine)[number]): RecheckParamSource =>
    ({ name: p.name, ...(p.type ? { type: p.type.replace(/\s+/g, '') } : {}), annotations: [...p.annotations].sort() });
  const first = flow.path.find(s => s.type === 'source' && s.line === line) ?? (flow.path[0]?.line === line ? flow.path[0] : undefined);
  // An annotated request parameter's flow names it `@RequestParam name in method`.
  const variable = first?.variable.match(/^@\S+\s+(\S+)\s+in\s/)?.[1] ?? first?.variable;
  const named = onLine.find(p => p.name === variable);
  if (named) return [of(named)];
  const sourceVars = new Set((ir.taint.sources ?? []).filter(s => s.line === line && s.variable).map(s => s.variable!));
  const request = flow.source_type !== 'interprocedural_param';
  const candidates = onLine.filter(p => sourceVars.has(p.name) || (request && p.annotations.length > 0));
  if (candidates.length === 0) return undefined;
  return candidates.map(of).sort((a, b) => a.name.localeCompare(b.name));
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
  if (before) {
    const files: Array<{ from: string; to: string; evidence: MoveEvidenceKind }> = [];
    if (opts.changedFrom) files.push(...renamesFromGit(base, opts.changedFrom));
    for (const [from, to] of opts.renames ?? []) {
      const rel = (p: string) => norm(isAbsolute(p) ? relative(base, p) : p);
      files.push({ from: rel(from), to: rel(to), evidence: 'rename-map' });
    }
    after.ctx.moves = detectFindingMoves(before, after.ctx, files);
    applyBaseline(after.report, before, after.ctx);
  }
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

/** circle-ir `detectMoves`' default: a smaller body never settles a move by its hash alone. */
const MOVE_MIN_TOKENS = 12;

/**
 * Where the baseline's findings may have moved. File renames and copies are
 * taken as given. Declarations: the baseline's finding-holding `ids@0.1`
 * declarations that are gone from the after side are paired with the after
 * declarations by circle-ir's `detectMoves`; a pair that settles by equal body
 * hash (unique on both sides, at least {@link MOVE_MIN_TOKENS} tokens) into
 * another file is a settled target, and a shared body hash
 * (`body-hash-ambiguous`) gives unsettled targets, which can only make a verdict
 * `unknown`. Every after declaration not in the baseline's set counts as added,
 * so an after declaration elsewhere with the same body makes the hash shared:
 * the pairing errs towards `unknown`, never towards a match. Pure.
 */
export function detectFindingMoves(
  before: RecheckReport, ctx: RecheckContext,
  files: Array<{ from: string; to: string; evidence: MoveEvidenceKind }> = [],
): RecheckMoves {
  const moves: RecheckMoves = { files: new Map(), decls: new Map() };
  for (const r of files) {
    if (r.from === r.to) continue;
    const list = moves.files.get(r.from) ?? [];
    if (!list.some(x => x.to === r.to)) list.push({ to: r.to, evidence: r.evidence });
    moves.files.set(r.from, list);
  }
  if (!ctx.ids || ctx.ids.size === 0) return moves;
  // The baseline's declarations, as ids@0.1 records with what move detection reads.
  const fileOf = new Map<string, string>();
  const beforeDecls = new Map<string, StableDecl>();
  for (const f of before.findings) {
    const d = f.decl;
    if (d.scheme !== 'ids@0.1' || !d.bodyHash || !d.kind || beforeDecls.has(d.id)) continue;
    if (ctx.decls.get(f.file)?.has(d.id)) continue; // still there: not moved
    fileOf.set(`b:${d.id}`, f.file);
    beforeDecls.set(d.id, {
      id: d.id, body_id: `${d.id}.${d.bodyHash}`, body_hash: d.bodyHash, kind: d.kind as StableDecl['kind'],
      name: d.name.replace(/^.*[.:/]/, ''), qualified_name: d.name, signature: '', parent: null,
      start_line: 0, end_line: 0, start_column: 0, end_column: 0, flags: [], token_count: d.tokens ?? 0,
    });
  }
  if (beforeDecls.size === 0) return moves;
  const afterFiles = [...ctx.ids.values()];
  for (const f of afterFiles) for (const d of f.decls) if (!fileOf.has(`a:${d.id}`)) fileOf.set(`a:${d.id}`, f.file);
  const beforeFile: StableIdFile = { scheme: 'ids@0.1', file: '<baseline>', language: 'java', module: '<baseline>', decls: [...beforeDecls.values()], partial: false };
  const found = detectMoves([beforeFile], afterFiles, { minTokens: MOVE_MIN_TOKENS });
  const add = (from: StableDecl, to: StableDecl, settled: boolean) => {
    const bf = fileOf.get(`b:${from.id}`);
    const af = fileOf.get(`a:${to.id}`);
    if (!bf || !af || bf === af) return; // a move inside the file keeps the file: flow identity already matches it
    const k = `${bf}|${from.id}`;
    const list = moves.decls.get(k) ?? [];
    list.push({ file: af, declId: to.id, settled });
    moves.decls.set(k, list);
  };
  for (const m of found.moves) if (m.evidence === 'body-hash') add(m.from, m.to, true);
  for (const c of found.candidates) {
    if (c.evidence === 'body-hash-ambiguous' && c.from.token_count >= MOVE_MIN_TOKENS) add(c.from, c.to, false);
  }
  return moves;
}

/** A qualified name with the positional parts of ids@0.1 (`@4.0.1.1`) left out. */
function positionFree(name: string): string {
  return name.replace(/@[0-9]+(?:\.[0-9]+)*/g, '');
}

/**
 * The after declaration a baseline declaration became when its id is gone: the
 * one declaration in the file with the same name once positions are left out.
 * None when there is no such declaration or more than one.
 */
function successorDecl(f: RecheckFinding, ctx: RecheckContext): string | undefined {
  const names = ctx.declNames?.get(f.file);
  if (!names || !f.decl.name) return undefined;
  const want = positionFree(f.decl.name);
  const hits = [...names].filter(([, n]) => positionFree(n) === want).map(([id]) => id);
  return hits.length === 1 ? hits[0] : undefined;
}

/** Where one baseline finding may have moved: its file's renames and its declaration's body-hash moves. */
interface MoveLookup {
  targets: Array<{ file: string; declId?: string; settled: boolean; evidence: MoveEvidenceKind }>;
}

function moveTargets(f: RecheckFinding, moves: RecheckMoves): MoveLookup {
  const targets: MoveLookup['targets'] = [];
  for (const r of moves.files.get(f.file) ?? []) targets.push({ file: r.to, settled: true, evidence: r.evidence });
  for (const d of moves.decls.get(`${f.file}|${f.decl.id}`) ?? []) {
    targets.push({ file: d.file, declId: d.declId, settled: d.settled, evidence: 'body-hash' });
  }
  return { targets };
}

const evidenceFor = (m: MoveLookup, a: RecheckFinding): MoveEvidenceKind[] =>
  [...new Set(m.targets.filter(t => t.file === a.file && (t.declId === undefined || t.declId === a.decl.id)).map(t => t.evidence))].sort();

/**
 * A moved flow's source is where the baseline's was, or moved with it: to a
 * rename of its file, or, when it sat in the finding's own file, to the file
 * the finding moved to.
 */
function sourceFileFollows(f: RecheckFinding, a: RecheckFinding, moves: RecheckMoves): boolean {
  const was = f.evidence?.source?.file;
  const is = a.evidence?.source?.file;
  if (was === undefined || is === undefined) return was === is;
  if (is === was || (was === f.file && is === a.file)) return true;
  return (moves.files.get(was) ?? []).some(r => r.to === is);
}

const baseName = (file: string): string => file.replace(/^.*\//, '').replace(/\.[^.]*$/, '');
const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * The declaration in `file` (which a baseline finding's file was renamed to) that
 * is the baseline declaration: the one with the same position-free qualified
 * name, the old file's base name (a Java class named by its file) read as the
 * new one's. None when there is no such declaration or more than one.
 */
function renamedDecl(f: RecheckFinding, file: string, ctx: RecheckContext): string | undefined {
  const names = ctx.declNames?.get(file);
  if (!names || !f.decl.name) return undefined;
  const was = positionFree(f.decl.name);
  const [from, to] = [baseName(f.file), baseName(file)];
  const want = from && from !== to ? was.replace(new RegExp(`\\b${escapeRe(from)}\\b`, 'g'), to) : was;
  for (const w of new Set([want, was])) {
    const hits = [...names].filter(([, n]) => positionFree(n) === w).map(([id]) => id);
    if (hits.length === 1) return hits[0];
    if (hits.length > 1) return undefined;
  }
  return undefined;
}

type Explained = Pick<RecheckVerdict, 'verdict' | 'reason' | 'sanitizers' | 'sanitizerCoversSink' | 'successorDecl' | 'movedTo' | 'moveEvidence'>;

/**
 * Why a baseline key is missing after the change; `unknown` when the after side
 * cannot say. When its file or declaration is gone but moved on evidence
 * (`move`), the reason is taken from where it moved to (`movedTo`): a moved
 * finding is never `file-removed` or `declaration-removed` for the move alone.
 */
function explainMissing(f: RecheckFinding, after: RecheckReport, ctx: RecheckContext | undefined, move?: MoveLookup): Explained {
  const here = explainIn(f, f.file, after, ctx, () => (ctx ? successorDecl(f, ctx) : undefined));
  // A shared body hash is no evidence of where the declaration went, only that
  // a flow found there could be it: with no such flow it does not explain a loss.
  const settled = (move?.targets ?? []).filter(t => t.settled);
  if (!ctx || settled.length === 0) return here;
  if (here.verdict !== 'gone' || (here.reason !== 'file-removed' && here.reason !== 'declaration-removed')) return here;
  if (settled.length > 1) {
    return { verdict: 'unknown', reason: 'move-ambiguous', moveEvidence: [...new Set(settled.map(t => t.evidence))].sort() };
  }
  const t = settled[0];
  const there = explainIn(f, t.file, after, ctx, () => t.declId ?? renamedDecl(f, t.file, ctx));
  return { ...there, movedTo: t.file, moveEvidence: [t.evidence] };
}

/** {@link explainMissing} in one file, the declaration found by `locate` when its id is not there. */
function explainIn(
  f: RecheckFinding, file: string, after: RecheckReport, ctx: RecheckContext | undefined, locate: () => string | undefined,
): Explained {
  const skip = (after.skipped ?? []).find(s => s.file === file);
  if (skip?.reason === 'not present') return { verdict: 'gone', reason: 'file-removed' };
  if ((after.partialFiles ?? []).some(p => p.file === file)) return { verdict: 'unknown', reason: 'parse-error' };
  const analysed = ctx ? ctx.analysed.has(file) : after.files.includes(file) && !skip;
  if (skip || !analysed) return { verdict: 'unknown', reason: 'not-analysed' };
  if (!ctx) return { verdict: 'gone' };
  const decls = ctx.decls.get(file);
  let declId = f.decl.id;
  let successor: Pick<RecheckVerdict, 'successorDecl'> = {};
  if (decls && !decls.has(declId)) {
    // The id is gone; when one after declaration is the same one re-keyed (an
    // anonymous handler after an inserted import, or the declaration in the file
    // it moved to), the reason comes from it.
    const next = locate();
    if (!next) return { verdict: 'gone', reason: 'declaration-removed' };
    declId = next;
    successor = { successorDecl: ctx.declNames?.get(file)?.get(next) ?? next };
  }
  if (f.kind === 'pass') return { verdict: 'gone', reason: 'not-reported', ...successor };
  const inv = ctx.inventory.get(`${file}|${declId}`);
  // Only a sanitizer the change added explains the loss: one already in the
  // declaration (or the path) at the baseline did not stop the flow then.
  const added = inv ? newSanitizers(inv.sanitizers, f.evidence) : [];
  if (added.length > 0) {
    const sanitizers = added.sort((a, b) => a.line - b.line || a.method.localeCompare(b.method));
    return { verdict: 'gone', reason: 'sanitized-by', sanitizers, sanitizerCoversSink: sanitizers.some(s => s.sanitizes.includes(f.rule)), ...successor };
  }
  if (!inv || !inv.sinks.has(f.rule)) return { verdict: 'gone', reason: 'sink-removed', ...successor };
  const src = f.evidence?.source;
  if (src && src.file === f.file && inv.sources === 0) return { verdict: 'gone', reason: 'source-removed', ...successor };
  return { verdict: 'gone', reason: 'flow-not-found', ...successor };
}

/**
 * The after declaration's sanitizers that the baseline did not hold, counted per
 * method name: the baseline's are its declaration's (`decl_sanitizers`, absent
 * from baselines written before it) and its path's. A second call to a sanitizer
 * the method already used counts as new. The latest calls are taken as the new ones.
 */
function newSanitizers(
  now: DeclInventory['sanitizers'], ev: RecheckEvidence | undefined,
): DeclInventory['sanitizers'] {
  const had = new Map<string, number>();
  const count = (names: string[]) => {
    const m = new Map<string, number>();
    for (const n of names) m.set(n, (m.get(n) ?? 0) + 1);
    return m;
  };
  const inDecl = count(ev?.decl_sanitizers ?? []);
  const inPath = count(ev?.sanitizers_in_path ?? []);
  for (const n of new Set([...inDecl.keys(), ...inPath.keys()])) had.set(n, Math.max(inDecl.get(n) ?? 0, inPath.get(n) ?? 0));
  const out: DeclInventory['sanitizers'] = [];
  const byMethod = new Map<string, DeclInventory['sanitizers']>();
  for (const s of now) byMethod.set(s.method, [...(byMethod.get(s.method) ?? []), s]);
  for (const [method, calls] of byMethod) {
    const sorted = [...calls].sort((a, b) => a.line - b.line);
    out.push(...sorted.slice(had.get(method) ?? 0));
  }
  return out;
}

const noSpace = (s: string | undefined): string => (s ?? '').replace(/\s+/g, '');

/** A parameter source's identity: what it is, not the header line it sits on. */
const paramIdentity = (p: RecheckParamSource): string =>
  `param:${p.annotations.join(',')}:${p.type ?? ''}:${p.name}`;

/**
 * What a finding is without its declaration: rule, CWE, file and kind, the
 * sink's type and code, and for a flow the source's file, type and code and the
 * sanitizers in the path (for a pass finding, its message). A parameter source
 * (`source.params`) is identified by its name, declared type and annotations
 * instead of its code, the method's header line: renaming the method or adding a
 * parameter keeps it; renaming, retyping or re-annotating the parameter does not. Code is compared with
 * all whitespace removed. Moving the code, or inserting statements around it,
 * keeps it; changing the sink call, the source or the sanitizers does not.
 * Undefined when the finding carries no sink code (a 0.1 baseline): such a key is
 * never matched by identity.
 */
export function flowIdentity(f: RecheckFinding): string | undefined {
  return identity(f, true);
}

/**
 * {@link flowIdentity} with the file and the source's file left out: what a
 * finding that moved to another file keeps. Only compared under move evidence.
 */
function movedIdentity(f: RecheckFinding): string | undefined {
  return identity(f, false);
}

function identity(f: RecheckFinding, withFiles: boolean): string | undefined {
  const e = f.evidence;
  if (!e?.sink.code) return undefined;
  const parts = [f.kind, f.cwe, f.rule, withFiles ? f.file : '', e.sink.type, noSpace(e.sink.code)];
  if (f.kind === 'flow') {
    const src = e.source?.params ? e.source.params.map(paramIdentity).join(';') : noSpace(e.source?.code);
    parts.push(withFiles ? e.source?.file ?? '' : '', e.source?.type ?? '', src, [...e.sanitizers_in_path].sort().join(','));
  } else {
    parts.push(noSpace(e.message));
  }
  return parts.join('\u0000');
}

/**
 * Verdicts for `after` against `before`. Pure: `ctx` (the after side's
 * declarations and inventory) only refines the reason on a missing key; without
 * it a missing key is `gone` unless its file was skipped, partial or not listed.
 *
 * Findings are first matched by flow identity ({@link flowIdentity}), because a
 * declaration's id can move while its flow does not (an anonymous handler is
 * keyed by position: an import inserted above it re-keys it, and can hand its old
 * id to the next handler). Per identity:
 *
 *   one baseline finding, one after finding   still-present; `rekeyed` with
 *                                             `rekeyedTo` when the keys differ
 *   more on either side, every baseline key   still-present by key
 *     also an after key
 *   more on either side, otherwise            `unknown` (`rekey-ambiguous`), never
 *                                             `gone`; the candidates are not also
 *                                             `new-*` unless they outnumber the
 *                                             baseline findings
 *
 * A baseline finding with no after finding of its identity falls back to its key:
 * still-present when the key is there and not taken by another match (a fix that
 * changed the sink but is still reported), else, when `ctx.moves` evidences that
 * its file or declaration moved ({@link detectFindingMoves}), it is matched to
 * the after findings there of the same flow identity with the files left out:
 *
 *   one candidate, on settled evidence, wanted by     still-present, `moved`,
 *     no other baseline finding                       `movedFrom`, `rekeyedTo`
 *   otherwise                                         `unknown` (`move-ambiguous`)
 *
 * and else `gone` with a reason (from where it moved, when it did). An after
 * finding no match took is `new-high` or `new-other`.
 */
export function applyBaseline(after: RecheckReport, before: RecheckReport, ctx?: RecheckContext): RecheckReport {
  const now = new Map(after.findings.map(f => [f.key, f]));
  const then = new Map(before.findings.map(f => [f.key, f]));
  const verdicts: RecheckVerdict[] = [];
  const ev = (f: RecheckFinding) => (f.evidence ? { evidence: f.evidence } : {});
  const base = (f: RecheckFinding) => ({ key: f.key, cwe: f.cwe, rule: f.rule, file: f.file });
  const stillPresent = (f: RecheckFinding, cur: RecheckFinding): RecheckVerdict => ({
    ...base(f), verdict: 'still-present', severity: cur.severity, line: cur.line,
    ...(cur.key !== f.key ? { reason: 'rekeyed' as const, rekeyedTo: cur.key, matchedBy: 'flow-identity' as const } : {}),
    ...ev(cur),
  });

  const group = (findings: Iterable<RecheckFinding>): Map<string, RecheckFinding[]> => {
    const m = new Map<string, RecheckFinding[]>();
    for (const f of findings) {
      const id = flowIdentity(f);
      if (id) m.set(id, [...(m.get(id) ?? []), f]);
    }
    return m;
  };
  const beforeById = group(then.values());
  const afterById = group(now.values());
  const resolved = new Set<string>();
  const claimed = new Set<string>();
  for (const [id, bs] of beforeById) {
    const as = afterById.get(id);
    if (!as) continue;
    if (bs.length === 1 && as.length === 1) {
      verdicts.push(stillPresent(bs[0], as[0]));
      resolved.add(bs[0].key);
      claimed.add(as[0].key);
      continue;
    }
    const afterKeys = new Set(as.map(a => a.key));
    if (bs.every(b => afterKeys.has(b.key))) {
      for (const b of bs) {
        verdicts.push(stillPresent(b, now.get(b.key)!));
        resolved.add(b.key);
        claimed.add(b.key);
      }
      continue;
    }
    // Which after finding is which baseline finding cannot be told: never `gone`.
    if (as.length <= bs.length) for (const a of as) claimed.add(a.key);
    const rekeyCandidates = [...afterKeys].sort();
    for (const b of bs) {
      verdicts.push({
        ...base(b), verdict: 'unknown', severity: b.severity, line: b.line,
        reason: 'rekey-ambiguous', matchedBy: 'flow-identity', rekeyCandidates, ...ev(b),
      });
      resolved.add(b.key);
    }
  }

  const missing: RecheckFinding[] = [];
  for (const [key, f] of then) {
    if (resolved.has(key)) continue;
    const a = now.get(key);
    if ((a && !claimed.has(key)) || (!a && ctx?.allKeys.has(key))) {
      verdicts.push(stillPresent(f, a ?? f));
      claimed.add(key);
      continue;
    }
    missing.push(f);
  }

  // A lost key whose first flow matched nothing may still hold other flows: when
  // one unclaimed after key in its file holds any of its flows, it is that key
  // re-keyed (a fix of one flow plus an import above an anonymous handler); more
  // than one is `unknown`. Never `gone` while one of its flows is still reported.
  const flowIds = (f: RecheckFinding): Set<string> =>
    new Set(flowsOf(f).map(x => flowIdentity({ ...f, line: x.line, evidence: x.evidence })).filter((x): x is string => !!x));
  const flowHits = new Map<string, RecheckFinding[]>();
  for (const f of missing) {
    const ids = flowIds(f);
    if (ids.size === 0) continue;
    const hits = [...now.values()].filter(a => !claimed.has(a.key) && a.file === f.file && [...flowIds(a)].some(id => ids.has(id)));
    if (hits.length > 0) flowHits.set(f.key, hits);
  }
  const flowWanted = new Map<string, number>();
  for (const hits of flowHits.values()) for (const a of hits) flowWanted.set(a.key, (flowWanted.get(a.key) ?? 0) + 1);
  const stillMissing: RecheckFinding[] = [];
  for (const f of missing) {
    const hits = flowHits.get(f.key);
    if (!hits) { stillMissing.push(f); continue; }
    if (hits.length === 1 && flowWanted.get(hits[0].key) === 1) {
      verdicts.push(stillPresent(f, hits[0]));
      claimed.add(hits[0].key);
      continue;
    }
    if (hits.length === 1) claimed.add(hits[0].key);
    verdicts.push({
      ...base(f), verdict: 'unknown', severity: f.severity, line: f.line,
      reason: 'rekey-ambiguous', matchedBy: 'flow-identity', rekeyCandidates: hits.map(h => h.key).sort(), ...ev(f),
    });
  }
  missing.length = 0;
  missing.push(...stillMissing);

  // Moves across files, on evidence only: the after findings of the same flow
  // identity (files left out) where the finding's file or declaration moved to.
  const moves = ctx?.moves;
  const moveOf = new Map<string, MoveLookup>();
  if (moves) for (const f of missing) moveOf.set(f.key, moveTargets(f, moves));
  const matchesOf = new Map<string, RecheckFinding[]>();
  const nowByFile = new Map<string, RecheckFinding[]>();
  if (moves) for (const a of now.values()) nowByFile.set(a.file, [...(nowByFile.get(a.file) ?? []), a]);
  for (const f of missing) {
    const m = moveOf.get(f.key);
    const id = m && m.targets.length > 0 ? movedIdentity(f) : undefined;
    if (!m || !id) continue;
    const hits = [...new Set(m.targets.map(t => t.file))].flatMap(file => nowByFile.get(file) ?? []).filter(a =>
      !claimed.has(a.key) && m.targets.some(t => t.file === a.file && (t.declId === undefined || t.declId === a.decl.id))
      && movedIdentity(a) === id && sourceFileFollows(f, a, moves!));
    if (hits.length > 0) matchesOf.set(f.key, hits);
  }
  // An after finding two baseline findings could have moved to is neither's.
  const wanted = new Map<string, number>();
  for (const hits of matchesOf.values()) for (const a of hits) wanted.set(a.key, (wanted.get(a.key) ?? 0) + 1);
  for (const f of missing) {
    const m = moveOf.get(f.key);
    const hits = matchesOf.get(f.key);
    if (m && hits) {
      const a = hits[0];
      const t = m.targets.find(x => x.file === a.file && (x.declId === undefined || x.declId === a.decl.id))!;
      if (hits.length === 1 && t.settled && wanted.get(a.key) === 1) {
        verdicts.push({
          ...base(f), file: a.file, verdict: 'still-present', severity: a.severity, line: a.line,
          reason: 'moved', rekeyedTo: a.key, matchedBy: 'move', movedFrom: f.file, moveEvidence: evidenceFor(m, a), ...ev(a),
        });
        claimed.add(a.key);
        continue;
      }
      // One candidate is most likely it; several stay new, as one of them is.
      if (hits.length === 1) claimed.add(a.key);
      verdicts.push({
        ...base(f), verdict: 'unknown', severity: f.severity, line: f.line, reason: 'move-ambiguous', matchedBy: 'move',
        rekeyCandidates: hits.map(h => h.key).sort(), moveEvidence: [...new Set(hits.flatMap(h => evidenceFor(m, h)))].sort(), ...ev(f),
      });
      continue;
    }
    verdicts.push({ ...base(f), severity: f.severity, line: f.line, ...explainMissing(f, after, ctx, m), ...ev(f) });
  }
  // Per flow inside a key: which of the key's baseline flows are still there,
  // which are gone, and which after flows are new. A baseline written before
  // `cognium-recheck@0.4` kept one flow per key, so it gives no per-flow detail
  // for a key that is still reported.
  const perFlow = before.schema === RECHECK_SCHEMA;
  const newFlows: RecheckVerdict[] = [];
  for (const v of verdicts) {
    const f = then.get(v.key);
    if (!f) continue;
    if (v.verdict === 'gone') {
      if (f.flows) v.flows = f.flows.map(x => flowEntry(x, 'gone'));
      continue;
    }
    if (v.verdict !== 'still-present' || !perFlow) continue;
    const a = now.get(v.rekeyedTo ?? v.key);
    if (!a) continue; // still reported outside the analysed scope: no flows to compare
    const cmp = compareFlows(f, a);
    if (!cmp) continue;
    if (f.flows || a.flows) v.flows = cmp.entries;
    if (cmp.entries.some(e => e.verdict === 'gone')) v.partial = true;
    for (const x of cmp.added) {
      newFlows.push({
        key: a.key, verdict: HIGH.has(a.severity) ? 'new-high' : 'new-other', cwe: a.cwe, rule: a.rule, severity: a.severity,
        file: a.file, line: x.line, newFlow: true, evidence: x.evidence,
      });
    }
  }
  verdicts.push(...newFlows);
  for (const [key, f] of now) {
    if (claimed.has(key)) continue;
    verdicts.push({
      key, verdict: HIGH.has(f.severity) ? 'new-high' : 'new-other', cwe: f.cwe, rule: f.rule, severity: f.severity, file: f.file, line: f.line, ...ev(f),
      ...(f.flows ? { flows: f.flows.map(x => flowEntry(x, 'new')) } : {}),
    });
  }
  verdicts.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.key.localeCompare(b.key));
  const count = (v: RecheckVerdict['verdict']) => verdicts.filter(x => x.verdict === v).length;
  after.verdicts = verdicts;
  after.summary = { gone: count('gone'), stillPresent: count('still-present'), newHigh: count('new-high'), newOther: count('new-other'), unknown: count('unknown') };
  after.noNewHigh = after.summary.newHigh === 0 ? 'pass' : 'fail';
  return after;
}

/** A key's flows: its listed flows, or the one its evidence describes. */
function flowsOf(f: RecheckFinding): RecheckFlow[] {
  if (f.flows && f.flows.length > 0) return f.flows;
  const id = flowIdentity(f);
  return id && f.evidence ? [{ identity: fingerprint([id]), line: f.line, evidence: f.evidence }] : [];
}

const flowEntry = (x: RecheckFlow, verdict: RecheckFlowVerdict): NonNullable<RecheckVerdict['flows']>[number] =>
  ({ identity: x.identity, verdict, line: x.line, ...(x.evidence.sink.code ? { sink: x.evidence.sink.code } : {}) });

/**
 * The flows of a baseline key against the flows of the after key it matched.
 * A baseline flow with an after flow of the same flow identity (files left out
 * when the key moved to another file) is `still-present`. The flows left over on
 * both sides are paired as `changed`, same sink code first, then in line order:
 * an edited flow is still there, never `gone`. What is left after that is `gone` (baseline) or `new`
 * (after). Undefined when either side has no flow identity (no sink code).
 */
function compareFlows(f: RecheckFinding, a: RecheckFinding): { entries: NonNullable<RecheckVerdict['flows']>; added: RecheckFlow[] } | undefined {
  const moved = f.file !== a.file;
  const idOf = (owner: RecheckFinding, x: RecheckFlow) => {
    const g = { ...owner, line: x.line, evidence: x.evidence };
    return moved ? movedIdentity(g) : flowIdentity(g);
  };
  const was = flowsOf(f), is = flowsOf(a);
  if (was.length === 0 || is.length === 0) return undefined;
  const isIds = is.map(x => idOf(a, x));
  const wasIds = new Set(was.map(x => idOf(f, x)));
  const entries: NonNullable<RecheckVerdict['flows']> = [];
  const lostWas: RecheckFlow[] = [];
  for (const x of was) {
    if (isIds.includes(idOf(f, x))) entries.push(flowEntry(x, 'still-present'));
    else lostWas.push(x);
  }
  const byLine = (p: RecheckFlow, q: RecheckFlow) => p.line - q.line || p.identity.localeCompare(q.identity);
  const lostIs = is.filter((_, i) => !wasIds.has(isIds[i])).sort(byLine);
  lostWas.sort(byLine);
  // Pair the leftovers: first a flow whose sink code is unchanged (its source or
  // sanitizers changed), then in line order.
  const pairedWas = new Set<RecheckFlow>();
  const pairedIs = new Set<RecheckFlow>();
  for (const x of lostWas) {
    const y = lostIs.find(c => !pairedIs.has(c) && noSpace(c.evidence.sink.code) === noSpace(x.evidence.sink.code));
    if (y) { pairedWas.add(x); pairedIs.add(y); }
  }
  const restIs = lostIs.filter(y => !pairedIs.has(y));
  for (const x of lostWas) {
    if (pairedWas.has(x)) continue;
    const y = restIs.shift();
    if (y) { pairedWas.add(x); pairedIs.add(y); }
  }
  for (const x of lostWas) entries.push(flowEntry(x, pairedWas.has(x) ? 'changed' : 'gone'));
  const added = lostIs.filter(y => !pairedIs.has(y));
  for (const x of added) entries.push(flowEntry(x, 'new'));
  entries.sort((p, q) => p.line - q.line || p.identity.localeCompare(q.identity));
  return { entries, added };
}

/**
 * `--expect-gone`: each target must be `gone`. A `gone` by a sanitizer that
 * covers none of the sink's class (an HTML encoder before a SQL sink) does not
 * count as fixed. Pure.
 */
export function applyTargets(report: RecheckReport, keys: string[]): RecheckReport {
  // A new flow's entry shares its key with the key's own verdict: the key's verdict decides.
  const byKey = new Map((report.verdicts ?? []).filter(v => !v.newFlow).map(v => [v.key, v]));
  report.targets = [...new Set(keys)].sort().map((key): RecheckTarget => {
    const v = byKey.get(key);
    if (!v || v.verdict === 'new-high' || v.verdict === 'new-other') return { key, verdict: 'not-in-baseline', fixed: false };
    // A key is gone only when every one of its flows is: a partial fix reads still-present.
    const fixed = v.verdict === 'gone' && !(v.reason === 'sanitized-by' && v.sanitizerCoversSink === false);
    const reason = v.partial ? 'partial-fix' : v.reason;
    const flows = v.flows ? {
      gone: v.flows.filter(x => x.verdict === 'gone').length,
      remaining: v.flows.filter(x => x.verdict === 'still-present' || x.verdict === 'changed').length,
      new: v.flows.filter(x => x.verdict === 'new').length,
    } : undefined;
    return { key, verdict: v.verdict, ...(reason ? { reason } : {}), fixed, ...(flows ? { flows } : {}) };
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
