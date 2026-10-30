/**
 * Graph facts on the command line: `deadcode`, `reach` and `entries`.
 *
 * The engine's graph facts over stable ids (`dead-code@0.1`,
 * `removal-reach@0.1`) were reachable only through the MCP server's
 * `find_dead_code` / `removal_reach` tools. These commands build the same
 * call graph with its entry-point index (`buildTsCallGraph`,
 * `buildJavaGraph`, `buildPythonGraph`, `buildGoGraph`) and print the
 * engine's answer unchanged as JSON, adding only an envelope (`root`,
 * `engine`, filters). Verdicts are facts, never a removal decision, so the
 * commands exit 0 whatever they find.
 *
 * Options are validated before any file is read (#1006), and the process exits
 * only after stdout drains (#1001).
 */

import { existsSync, lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'fs';
import { execFileSync } from 'child_process';
import { createRequire } from 'module';
import { tmpdir } from 'os';
import { join, relative, resolve, sep } from 'path';
import {
  buildGoGraph,
  buildJavaGraph,
  buildPythonGraph,
  buildTsCallGraph,
  deadCode,
  deriveStableIds,
  entryIndexDigest,
  partialFileDetails,
  removalReach,
  type DeadCodeFact,
  type DeadCodeResult,
  type EntryKind,
  type PartialFile,
  type ReachInput,
  type RemovalReachResult,
  type StableIdFile,
  type TsPackageManifest,
  type TsSourceFile,
} from 'circle-ir';
import { UsageError, parseFormat } from './utils/options.js';
import { STRUCTURE_SKIPPED_DIRECTORIES } from './utils/skip-dirs.js';

// ─── Options ─────────────────────────────────────────────────────────────────

export type GraphLanguage = 'typescript' | 'java' | 'python' | 'go';

export const ENTRY_KINDS = [
  'route', 'listener', 'scheduled', 'main', 'export', 'bean', 'reflection', 'lifecycle', 'test',
] as const satisfies readonly EntryKind[];

export const VERDICTS = ['live', 'may-be-live', 'dead'] as const satisfies readonly DeadCodeFact['verdict'][];

const LANGUAGE_ALIASES: Record<string, GraphLanguage> = {
  ts: 'typescript', typescript: 'typescript', tsx: 'typescript',
  js: 'typescript', javascript: 'typescript', jsx: 'typescript',
  java: 'java',
  py: 'python', python: 'python',
  go: 'go', golang: 'go',
};

/** `--language`: one of the four graphs (`js`/`javascript` share the TypeScript graph). */
export function parseGraphLanguage(raw: unknown): GraphLanguage | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== 'string' || raw.trim() === '') {
    throw new UsageError('--language requires a value (ts|java|python|go)');
  }
  const lang = LANGUAGE_ALIASES[raw.trim().toLowerCase()];
  if (!lang) throw new UsageError(`unsupported --language '${raw}' for graph facts (expected ts|java|python|go)`);
  return lang;
}

function parseList<T extends string>(name: string, raw: unknown, allowed: readonly T[]): T[] | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== 'string' || raw.trim() === '') {
    throw new UsageError(`--${name} requires a value (${allowed.join(',')})`);
  }
  const parts = raw.split(',').map((s) => s.trim().toLowerCase()).filter((s) => s.length > 0);
  if (parts.length === 0) throw new UsageError(`--${name} requires a value (${allowed.join(',')})`);
  for (const p of parts) {
    if (!(allowed as readonly string[]).includes(p)) {
      throw new UsageError(`unknown ${name} value '${p}' (expected ${allowed.join(',')})`);
    }
  }
  return [...new Set(parts)] as T[];
}

/** `--root-kinds route,main,…`: entry kinds used as product roots. */
export function parseRootKinds(raw: unknown): EntryKind[] | undefined {
  return parseList('root-kinds', raw, ENTRY_KINDS);
}

/** `--verdicts dead,may-be-live`: which facts to list (the summary always counts all). */
export function parseVerdicts(raw: unknown): DeadCodeFact['verdict'][] | undefined {
  return parseList('verdicts', raw, VERDICTS);
}

export interface DeadCodeCliOptions {
  language?: GraphLanguage;
  format: 'text' | 'json' | 'sarif';
  rootKinds?: EntryKind[];
  verdicts: DeadCodeFact['verdict'][];
  output?: string;
}

export interface ReachCliOptions {
  language?: GraphLanguage;
  format: 'text' | 'json' | 'sarif';
  rootKinds?: EntryKind[];
  base: string;
  output?: string;
}

export interface EntriesCliOptions {
  language?: GraphLanguage;
  format: 'text' | 'json';
  output?: string;
}

type Raw = Record<string, string | boolean | undefined>;

function optionalString(name: string, raw: unknown): string | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== 'string' || raw.trim() === '') throw new UsageError(`--${name} requires a value`);
  return raw;
}

export function parseDeadCodeOptions(o: Raw): DeadCodeCliOptions {
  return {
    language: parseGraphLanguage(o.language ?? o.l),
    format: parseFormat(o.format ?? o.f, ['text', 'json', 'sarif'] as const, 'text'),
    rootKinds: parseRootKinds(o['root-kinds']),
    verdicts: parseVerdicts(o.verdicts) ?? ['dead', 'may-be-live'],
    output: optionalString('output', o.output ?? o.o),
  };
}

export function parseReachOptions(o: Raw): ReachCliOptions {
  const base = o.base;
  if (base === undefined || typeof base !== 'string' || base.trim() === '') {
    throw new UsageError('reach requires --base <git-ref-or-directory>');
  }
  return {
    language: parseGraphLanguage(o.language ?? o.l),
    format: parseFormat(o.format ?? o.f, ['text', 'json', 'sarif'] as const, 'text'),
    rootKinds: parseRootKinds(o['root-kinds']),
    base,
    output: optionalString('output', o.output ?? o.o),
  };
}

export function parseEntriesOptions(o: Raw): EntriesCliOptions {
  return {
    language: parseGraphLanguage(o.language ?? o.l),
    format: parseFormat(o.format ?? o.f, ['text', 'json'] as const, 'text'),
    output: optionalString('output', o.output ?? o.o),
  };
}

// ─── Reading a tree ──────────────────────────────────────────────────────────

/**
 * Directories never read: dependencies, generated reports, build output
 * (`utils/skip-dirs.ts`, #1025). Dot-directories are skipped as well.
 */
export const SKIPPED_DIRECTORIES: readonly string[] = STRUCTURE_SKIPPED_DIRECTORIES;

const EXTENSIONS: Record<GraphLanguage, RegExp> = {
  typescript: /\.(ts|tsx|mts|cts|js|jsx|mjs|cjs)$/,
  java: /\.java$/,
  python: /\.py$/,
  go: /\.go$/,
};

const MAX_FILE_BYTES = 2 * 1024 * 1024;

/** Repository-relative paths (forward slashes) of the tree's files, in path order. */
export function walk(root: string, accept: (rel: string) => boolean, limit = Infinity): string[] {
  const skipped = new Set(SKIPPED_DIRECTORIES);
  const out: string[] = [];
  const visit = (dir: string): void => {
    if (out.length >= limit) return;
    let names: string[];
    try {
      names = readdirSync(dir).sort();
    } catch {
      return;
    }
    for (const name of names) {
      if (out.length >= limit) return;
      if (name.startsWith('.') || skipped.has(name)) continue;
      const abs = join(dir, name);
      let st;
      try {
        st = lstatSync(abs); // a symlink is never followed out of the tree
      } catch {
        continue;
      }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) visit(abs);
      else if (st.isFile()) {
        const rel = relative(root, abs).split(sep).join('/');
        if (accept(rel) && st.size <= MAX_FILE_BYTES) out.push(rel);
      }
    }
  };
  visit(root);
  return out;
}

function sources(root: string, language: GraphLanguage): TsSourceFile[] {
  return walk(root, (rel) => EXTENSIONS[language].test(rel) && !rel.endsWith('.d.ts.map'))
    .map((path) => ({ path, code: readFileSync(join(root, path), 'utf-8') }));
}

/** Every `package.json` above a source directory, for the TypeScript entry index. */
function manifests(root: string, files: readonly TsSourceFile[]): TsPackageManifest[] {
  const dirs = new Set<string>(['']);
  for (const s of files) {
    const parts = s.path.split('/');
    for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join('/'));
  }
  const out: TsPackageManifest[] = [];
  for (const d of [...dirs].sort()) {
    const file = join(root, d, 'package.json');
    if (existsSync(file)) out.push({ root: d, packageJson: readFileSync(file, 'utf-8') });
  }
  return out;
}

function consoleScripts(root: string): string[] {
  const file = join(root, 'pyproject.toml');
  if (!existsSync(file)) return [];
  const out: string[] = [];
  let inScripts = false;
  for (const raw of readFileSync(file, 'utf-8').split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith('[')) {
      inScripts = line === '[project.scripts]';
      continue;
    }
    if (!inScripts) continue;
    const m = /^[A-Za-z0-9_.-]+\s*=\s*["']([A-Za-z0-9_.]+:[A-Za-z0-9_.]+)["']/.exec(line);
    if (m) out.push(m[1]);
  }
  return out;
}

function goModulePath(root: string): string | undefined {
  const file = join(root, 'go.mod');
  if (!existsSync(file)) return undefined;
  const m = /^\s*module\s+(\S+)/m.exec(readFileSync(file, 'utf-8'));
  return m ? m[1].replace(/^"|"$/g, '') : undefined;
}

function serviceFiles(root: string): { path: string; text: string }[] {
  // `.`-prefixed directories are skipped by `walk`, but META-INF is not one.
  return walk(root, (rel) => /(^|\/)META-INF\/services\/[^/]+$/.test(rel))
    .map((path) => ({ path, text: readFileSync(join(root, path), 'utf-8') }));
}

const FAMILY_NAMES: Record<GraphLanguage, string> = {
  typescript: 'TypeScript/JavaScript', java: 'Java', python: 'Python', go: 'Go',
};

/** The language asked for, else the only family present; a mixed tree must say. */
export function pickLanguage(roots: readonly string[], asked?: GraphLanguage): GraphLanguage {
  if (asked) return asked;
  const present = new Set<GraphLanguage>();
  for (const r of roots) {
    for (const lang of ['java', 'typescript', 'python', 'go'] as const) {
      if (walk(r, (rel) => EXTENSIONS[lang].test(rel), 1).length > 0) present.add(lang);
    }
  }
  const found = (['java', 'typescript', 'python', 'go'] as const).filter((l) => present.has(l));
  if (found.length > 1) {
    throw new UsageError(`the tree has ${found.map((l) => FAMILY_NAMES[l]).join(', ')} files: pass --language`);
  }
  if (found.length === 0) throw new UsageError('no Java, TypeScript, JavaScript, Python or Go files under the path');
  return found[0];
}

/** The engine's reach input for one tree: its call graph with the entry index. */
export async function buildGraph(root: string, language: GraphLanguage): Promise<ReachInput> {
  if (language === 'java') return buildJavaGraph(sources(root, 'java'), { serviceFiles: serviceFiles(root) });
  if (language === 'python') return buildPythonGraph(sources(root, 'python'), { consoleScripts: consoleScripts(root) });
  if (language === 'go') {
    const modulePath = goModulePath(root);
    return buildGoGraph(sources(root, 'go'), modulePath ? { modulePath } : {});
  }
  const files = sources(root, 'typescript');
  return buildTsCallGraph(files, { packages: manifests(root, files) });
}

async function headIds(root: string, language: GraphLanguage): Promise<StableIdFile[]> {
  if (language !== 'typescript') return (await buildGraph(root, language)).files as StableIdFile[];
  const out: StableIdFile[] = [];
  for (const s of sources(root, 'typescript')) {
    const lang = /\.(ts|tsx|mts|cts)$/.test(s.path) ? 'typescript' : 'javascript';
    out.push(await deriveStableIds(s.code, s.path, lang));
  }
  return out;
}

/** The engine that computed an answer: `circle-ir` and its version. */
export function engineIdentity(): { package: 'circle-ir'; version: string } {
  try {
    const require = createRequire(import.meta.url);
    const pkg = JSON.parse(readFileSync(require.resolve('circle-ir/package.json'), 'utf-8')) as { version?: string };
    return { package: 'circle-ir', version: pkg.version ?? 'unknown' };
  } catch {
    return { package: 'circle-ir', version: 'unknown' };
  }
}

export function checkDirectory(path: string): string {
  const abs = resolve(path);
  if (!existsSync(abs)) throw new UsageError(`path not found: ${path}`);
  if (!statSync(abs).isDirectory()) throw new UsageError(`not a directory: ${path}`);
  return abs;
}

/**
 * `--base`: a directory is used as it is; anything else is a git ref of the
 * repository that holds `head`, exported with `git archive` into a temporary
 * directory (the working tree and the index are never touched).
 */
export function materializeBase(head: string, base: string): { dir: string; ref?: string; cleanup: () => void } {
  const asDir = resolve(base);
  if (existsSync(asDir) && statSync(asDir).isDirectory()) return { dir: asDir, cleanup: () => {} };
  let top: string;
  let prefix: string;
  try {
    top = execFileSync('git', ['-C', head, 'rev-parse', '--show-toplevel'], { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString().trim();
    prefix = execFileSync('git', ['-C', head, 'rev-parse', '--show-prefix'], { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString().trim();
  } catch {
    throw new UsageError(`--base '${base}' is not a directory, and ${head} is not inside a git repository`);
  }
  try {
    execFileSync('git', ['-C', top, 'rev-parse', '--verify', '--quiet', `${base}^{commit}`], { stdio: 'ignore' });
  } catch {
    throw new UsageError(`--base '${base}' is neither a directory nor a commit in ${top}`);
  }
  const tmp = mkdtempSync(join(tmpdir(), 'cognium-reach-'));
  const tar = execFileSync('git', ['-C', top, 'archive', '--format=tar', base], { maxBuffer: 1024 * 1024 * 1024 });
  execFileSync('tar', ['-x', '-C', tmp], { input: tar });
  const dir = prefix ? join(tmp, prefix) : tmp;
  return { dir, ref: base, cleanup: () => rmSync(tmp, { recursive: true, force: true }) };
}

// ─── Commands ────────────────────────────────────────────────────────────────

export interface DeadCodeReport {
  root: string;
  language: GraphLanguage;
  engine: { package: 'circle-ir'; version: string };
  scheme: DeadCodeResult['scheme'];
  ids: DeadCodeResult['ids'];
  rootKinds: DeadCodeResult['rootKinds'];
  entryIndexDigest: string;
  partial: string[];
  /** Each `partial` file and its first blocking parse error (file, line, node kind). */
  partialFiles: PartialFile[];
  summary: DeadCodeResult['summary'];
  verdicts: DeadCodeFact['verdict'][];
  totalFacts: number;
  facts: DeadCodeFact[];
  /** Declaration id → [line, column] (1-based line), for text and SARIF locations. */
  locations: Record<string, [number, number]>;
}

function declLocations(files: readonly StableIdFile[]): Record<string, [number, number]> {
  const out: Record<string, [number, number]> = {};
  for (const f of files) for (const d of f.decls) out[d.id] = [d.start_line, d.start_column + 1];
  return out;
}

export async function computeDeadCode(path: string, opts: DeadCodeCliOptions): Promise<DeadCodeReport> {
  const root = checkDirectory(path);
  const language = pickLanguage([root], opts.language);
  const graph = await buildGraph(root, language);
  const result = deadCode(graph, opts.rootKinds ? { rootKinds: opts.rootKinds } : {});
  const wanted = new Set(opts.verdicts);
  const facts = result.facts.filter((f) => wanted.has(f.verdict));
  return {
    root,
    language,
    engine: engineIdentity(),
    scheme: result.scheme,
    ids: result.ids,
    rootKinds: result.rootKinds,
    entryIndexDigest: entryIndexDigest(graph.entries),
    partial: result.partial,
    partialFiles: result.partialFiles,
    summary: result.summary,
    verdicts: opts.verdicts,
    totalFacts: facts.length,
    facts,
    locations: declLocations(graph.files),
  };
}

export interface ReachReport extends Omit<RemovalReachResult, never> {
  root: string;
  base: string;
  baseRef?: string;
  language: GraphLanguage;
  engine: { package: 'circle-ir'; version: string };
  /** Base declaration id → [line, column] (1-based line), for SARIF locations. Not in JSON. */
  locations: Record<string, [number, number]>;
}

export async function computeReach(path: string, opts: ReachCliOptions): Promise<ReachReport> {
  const head = checkDirectory(path);
  const base = materializeBase(head, opts.base);
  try {
    const language = pickLanguage([base.dir, head], opts.language);
    const baseGraph = await buildGraph(base.dir, language);
    const result = removalReach(baseGraph, await headIds(head, language), opts.rootKinds ? { rootKinds: opts.rootKinds } : {});
    return {
      root: head,
      base: base.ref ? base.ref : base.dir,
      ...(base.ref ? { baseRef: base.ref } : {}),
      language,
      engine: engineIdentity(),
      ...result,
      locations: declLocations(baseGraph.files),
    };
  } finally {
    base.cleanup();
  }
}

export interface EntriesReport {
  root: string;
  language: GraphLanguage;
  engine: { package: 'circle-ir'; version: string };
  entryIndexDigest: string;
  entries: ReachInput['entries'];
  unresolvedRegistrations: NonNullable<ReachInput['unresolvedRegistrations']>;
  partial: string[];
  /** Each `partial` file and its first blocking parse error. */
  partialFiles: PartialFile[];
  summary: Record<string, number>;
}

export async function computeEntries(path: string, opts: EntriesCliOptions): Promise<EntriesReport> {
  const root = checkDirectory(path);
  const language = pickLanguage([root], opts.language);
  const graph = await buildGraph(root, language);
  const summary: Record<string, number> = {};
  for (const e of graph.entries) summary[e.kind] = (summary[e.kind] ?? 0) + 1;
  return {
    root,
    language,
    engine: engineIdentity(),
    entryIndexDigest: entryIndexDigest(graph.entries),
    entries: graph.entries,
    unresolvedRegistrations: graph.unresolvedRegistrations ?? [],
    partial: [...graph.partial],
    partialFiles: partialFileDetails(graph.partial, graph.files),
    summary,
  };
}

// ─── Output ──────────────────────────────────────────────────────────────────

/** `file:line:column  ERROR in <parent>`: where a file stopped parsing. */
function partialFileLine(p: PartialFile): string {
  if (p.line === undefined) return p.file;
  return `${p.file}:${p.line}:${p.column}  ${p.nodeKind} in ${p.parent}`;
}

/** Text block naming each file that did not parse, and where. */
function partialFilesText(partial: readonly PartialFile[], heading: string): string[] {
  if (partial.length === 0) return [];
  return [`  ${partial.length} ${heading}; verdicts these files could reach are held back:`, ...partial.map(p => `    ${partialFileLine(p)}`)];
}

const PARTIAL_PARSE_RULE = {
  id: 'graph-facts/partial-parse',
  shortDescription: { text: 'This file did not parse fully; reachability answers that depend on it are held back' },
};

/** SARIF note results, one per file that did not parse, at its first blocking error. */
function partialParseResults(partial: readonly PartialFile[], scheme: string): object[] {
  return partial.map(p => ({
    ruleId: PARTIAL_PARSE_RULE.id,
    level: 'note',
    message: { text: p.line === undefined
      ? `${p.file} did not parse fully.`
      : `${p.file} did not parse fully: ${p.nodeKind} in ${p.parent} at line ${p.line}, column ${p.column}.` },
    locations: [{ physicalLocation: { artifactLocation: { uri: p.file, uriBaseId: 'SRCROOT' }, region: { startLine: p.line ?? 1, startColumn: p.column ?? 1 } } }],
    properties: { nodeKind: p.nodeKind, parent: p.parent, scheme },
  }));
}

/** JSON: the engine's scheme fields unchanged, plus the envelope; `locations` is internal. */
export function deadCodeJson(r: DeadCodeReport): string {
  const { locations: _locations, ...rest } = r;
  return JSON.stringify(rest, null, 2);
}

export function deadCodeText(r: DeadCodeReport): string {
  const lines: string[] = [];
  const s = r.summary;
  lines.push(`Dead code (${r.scheme}) — ${r.root} [${r.language}], engine circle-ir ${r.engine.version}`);
  lines.push(`  live ${s.live} · may-be-live ${s['may-be-live']} · dead ${s.dead} · reached by tests only ${s.reachedByTestOnly}`);
  lines.push(`  roots: ${r.rootKinds.join(', ')}`);
  lines.push(...partialFilesText(r.partialFiles, 'file(s) did not parse fully'));
  lines.push('');
  const order: Record<string, number> = { dead: 0, 'may-be-live': 1, live: 2 };
  const facts = [...r.facts].sort((a, b) =>
    order[a.verdict] - order[b.verdict] || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) ||
    (r.locations[a.id]?.[0] ?? 0) - (r.locations[b.id]?.[0] ?? 0));
  for (const f of facts) {
    const line = r.locations[f.id]?.[0];
    const why = f.verdict === 'may-be-live' && f.reasons.length > 0 ? ` (${f.reasons.join(', ')})` : '';
    const test = f.reachedByTest ? ' [reached by tests]' : '';
    lines.push(`  ${f.verdict.padEnd(11)} ${f.file}${line ? `:${line}` : ''}  ${f.qualified_name} (${f.kind})${why}${test}`);
  }
  if (facts.length === 0) lines.push(`  no facts with verdict ${r.verdicts.join(' or ')}`);
  lines.push('');
  lines.push('A verdict is a fact about reachability, never a removal decision.');
  return lines.join('\n');
}

/** SARIF 2.1.0: one result per listed fact; `dead` is a warning, `may-be-live` a note. */
export function deadCodeSarif(r: DeadCodeReport): string {
  const levels: Record<string, 'warning' | 'note' | 'none'> = { dead: 'warning', 'may-be-live': 'note', live: 'none' };
  const rules = [
    { id: 'dead-code/dead', shortDescription: { text: 'No path from a product entry point reaches this declaration' } },
    { id: 'dead-code/may-be-live', shortDescription: { text: 'Only a weak path, an unresolved site or an unparsed file keeps this declaration alive' } },
    { id: 'dead-code/live', shortDescription: { text: 'A product entry point reaches this declaration' } },
    PARTIAL_PARSE_RULE,
  ];
  const results = r.facts.map((f) => {
    const [line, column] = r.locations[f.id] ?? [1, 1];
    const reasons = f.reasons.length > 0 ? ` Reasons: ${f.reasons.join(', ')}.` : '';
    return {
      ruleId: `dead-code/${f.verdict}`,
      level: levels[f.verdict],
      message: { text: `${f.qualified_name} (${f.kind}) is ${f.verdict}.${reasons}${f.reachedByTest ? ' Reached by tests.' : ''}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: f.file, uriBaseId: 'SRCROOT' }, region: { startLine: line, startColumn: column } } }],
      partialFingerprints: { stableId: f.id },
      properties: { verdict: f.verdict, reasons: f.reasons, reachedByTest: f.reachedByTest, scheme: r.scheme },
    };
  });
  results.push(...(partialParseResults(r.partialFiles, r.scheme) as typeof results));
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'cognium-dev deadcode', informationUri: 'https://cognium.dev', version: r.engine.version, rules } },
      originalUriBaseIds: { SRCROOT: { uri: `file://${r.root.split(sep).join('/')}/` } },
      results,
      properties: { scheme: r.scheme, summary: r.summary, partial: r.partial, partialFiles: r.partialFiles, rootKinds: r.rootKinds },
    }],
  }, null, 2);
}

export function reachText(r: ReachReport): string {
  const lines: string[] = [];
  lines.push(`Removal reach (${r.scheme}) — base ${r.base} → head ${r.root} [${r.language}], engine circle-ir ${r.engine.version}`);
  lines.push(`  removed ${r.removed.length} · moved or renamed ${r.moved.length}`);
  lines.push(...partialFilesText(r.partialFiles, 'file(s) did not parse fully at either pin'));
  lines.push('');
  for (const d of r.removed) {
    const reach = d.strong ? `strong from ${d.strong.entry.kind}${d.strong.entry.path ? ` ${d.strong.entry.path}` : ''}`
      : d.weak ? `weak from ${d.weak.entry.kind}` : 'no path';
    const unresolved = d.unresolvedCount > 0 ? `, ${d.unresolvedCount} unresolved site(s)` : '';
    const moves = d.moveCandidates.length > 0 ? `, ${d.moveCandidates.length} move candidate(s)` : '';
    lines.push(`  removed  ${d.file}  ${d.qualified_name ?? d.id} (${d.kind}) — ${reach}${unresolved}${moves}`);
  }
  for (const m of r.moved) lines.push(`  moved    ${m.from} → ${m.to} (${m.relation})`);
  if (r.removed.length === 0 && r.moved.length === 0) lines.push('  nothing removed');
  return lines.join('\n');
}

/** JSON: the engine's scheme fields unchanged, plus the envelope; `locations` is internal. */
export function reachJson(r: ReachReport): string {
  const { locations: _locations, ...rest } = r;
  return JSON.stringify(rest, null, 2);
}

/**
 * SARIF 2.1.0: one result per removed declaration, located at the base.
 * A removal that a product entry still reaches strongly is a warning; the
 * rest are notes. Files that did not parse are notes as well.
 */
export function reachSarif(r: ReachReport): string {
  const rules = [
    { id: 'removal-reach/reached', shortDescription: { text: 'A removed declaration that a product entry point reached at the base' } },
    { id: 'removal-reach/removed', shortDescription: { text: 'A removed declaration with no strong path from a product entry point at the base' } },
    PARTIAL_PARSE_RULE,
  ];
  const results: object[] = r.removed.map((d) => {
    const [line, column] = r.locations[d.id] ?? [1, 1];
    const reached = d.strong !== undefined && d.strong !== null;
    const via = reached ? ` Reached from ${d.strong!.entry.kind} at the base.` : d.weak ? ` Only a weak path from ${d.weak.entry.kind}.` : '';
    const unresolved = d.unresolvedCount > 0 ? ` ${d.unresolvedCount} unresolved site(s) could reach it.` : '';
    return {
      ruleId: reached ? 'removal-reach/reached' : 'removal-reach/removed',
      level: reached ? 'warning' : 'note',
      message: { text: `${d.qualified_name ?? d.id} (${d.kind}) was removed.${via}${unresolved}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: d.file, uriBaseId: 'BASEROOT' }, region: { startLine: line, startColumn: column } } }],
      partialFingerprints: { stableId: d.id },
      properties: { unresolvedCount: d.unresolvedCount, moveCandidates: d.moveCandidates.length, scheme: r.scheme },
    };
  });
  results.push(...partialParseResults(r.partialFiles, r.scheme));
  const uri = (p: string) => `file://${p.split(sep).join('/')}/`;
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'cognium-dev reach', informationUri: 'https://cognium.dev', version: r.engine.version, rules } },
      originalUriBaseIds: { SRCROOT: { uri: uri(r.root) }, ...(r.baseRef ? {} : { BASEROOT: { uri: uri(r.base) } }) },
      results,
      properties: { scheme: r.scheme, entryIndexDigest: r.entryIndexDigest, partial: r.partial, partialFiles: r.partialFiles, rootKinds: r.rootKinds, base: r.base },
    }],
  }, null, 2);
}

export function entriesText(r: EntriesReport): string {
  const lines: string[] = [];
  lines.push(`Entry points — ${r.root} [${r.language}], engine circle-ir ${r.engine.version}`);
  lines.push(`  ${r.entries.length} entries: ${Object.entries(r.summary).map(([k, v]) => `${k} ${v}`).join(' · ') || 'none'}`);
  if (r.unresolvedRegistrations.length > 0) lines.push(`  ${r.unresolvedRegistrations.length} registration(s) could not be tied to a declaration`);
  lines.push(...partialFilesText(r.partialFiles, 'file(s) did not parse fully'));
  lines.push('');
  const sorted = [...r.entries].sort((a, b) =>
    (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.line - b.line);
  for (const e of sorted) {
    const route = e.method || e.path ? ` ${[e.method, e.path].filter(Boolean).join(' ')}` : '';
    lines.push(`  ${e.kind.padEnd(10)} ${e.certainty.padEnd(12)} ${e.file}:${e.line}${route}`);
  }
  return lines.join('\n');
}

