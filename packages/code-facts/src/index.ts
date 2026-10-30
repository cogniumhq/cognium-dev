/**
 * `@cognium/code-facts`: static facts about a code change between two versions
 * of a tree, read with circle-ir.
 *
 *  - `path-set-diff`: every source-to-sink path of one CWE at each version,
 *    keyed so a path is found again across the change, with its state at each
 *    version (`absent` · `sanitized` · `guarded` · `present`) and the change
 *    (`removed` · `sanitized` · `guarded` · `unchanged` · `added` · `other`),
 *    plus per version the unresolved edges met and the analysis budgets hit.
 *  - `remedy-class`: for every sink of a path the change closed (and, with
 *    `scope: 'all'`, of a path it left open), the row of a caller-supplied
 *    `safe-construct-table@0.1` the fixed code matches, or `multiple`,
 *    `unrecognized`, `abstained`, with the table's digest.
 *
 * Observations only: nothing here says a fix is adequate. Tables are inputs;
 * none ships in this package. Deterministic: no network, no model, the same
 * output for the same trees, table and versions.
 */
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import {
  analyzeProject,
  initAnalyzer,
  deriveBranchFacts,
  deriveStableIds,
  deriveTemplateFacts,
  loadSafeConstructTable,
  pathSetDiff,
  remedyClassOf,
  stableIdsSupport,
  type BranchFact,
  type PathDiffEntry,
  type PathSetDiff,
  type ProjectAnalysis,
  type RemedySinkObservation,
  type StableIdFile,
  type TemplateFact,
} from 'circle-ir';
import { readTree, sha, TEMPLATE_EXTENSIONS, type CodeLanguage, type TreeFile } from './tree.js';

export { readTree, EXTENSIONS, TEMPLATE_EXTENSIONS, DEFAULT_EXCLUDED_DIRS } from './tree.js';
export type { CodeLanguage, TreeFile } from './tree.js';

/** The version of the observation shape. A consumer pins it and refuses any other. */
export const SCHEMA_VERSION = '0.1' as const;

/** Identity of this package, carried on every result and in the environment digest. */
export const DRIVER = { id: 'code-facts', family: 'static', version: '0.1.0' } as const;

export function capabilities(): string[] {
  return ['path-set-diff', 'remedy-class'];
}

/** Two versions of one tree, checked out by the caller: the baseline and the change. */
export interface PinPair {
  before: string;
  after: string;
}

export interface CodeFactsParams {
  /** The weakness class, `CWE-89` or `89`. */
  cwe: string | number;
  language: CodeLanguage;
  /** Directory names never read; defaults to `DEFAULT_EXCLUDED_DIRS`. */
  excludedDirs?: readonly string[];
}

export interface RemedyClassParams extends CodeFactsParams {
  /** `closed` (default) or `all` (also sinks of paths still open after the change). */
  scope?: 'closed' | 'all';
  /** A `path-set-diff` result for the same pair and parameters, to avoid analysing twice. */
  pathSet?: RunResult;
  /** Observe the output context at writer sinks and hold context rows only there (off by default). */
  outputContext?: boolean;
}

export interface AnchorObservation {
  /** A path key, a closed sink (`<path key>:sink`), or `site`. */
  anchor: string;
  observation: unknown;
  /** Content hash of exactly what this anchor's observation read. */
  inputDigest: string;
}

export interface RunResult {
  driver: typeof DRIVER;
  schemaVersion: typeof SCHEMA_VERSION;
  capability: string;
  anchors: AnchorObservation[];
  environmentDigest: string;
}

/** One analysed version: files, IR, stable ids and branch facts. */
interface Pin {
  files: TreeFile[];
  digests: Map<string, string>;
  project: ProjectAnalysis;
  stableIds: Record<string, StableIdFile>;
  branches: Record<string, BranchFact[]>;
  templates: Record<string, TemplateFact[]>;
}

const require = createRequire(import.meta.url);

function circleIrVersion(): string {
  return (require('circle-ir/package.json') as { version: string }).version;
}

/** The facts run in-process; their environment is the Node runtime, this package and circle-ir. */
function environmentDigest(): string {
  return sha(`node ${process.version} ${process.platform}/${process.arch} ${DRIVER.id}@${DRIVER.version} circle-ir@${circleIrVersion()}`);
}

let ready: Promise<void> | null = null;

/** Initialise circle-ir once, from the grammars it ships in `dist/wasm`. */
function init(): Promise<void> {
  ready ??= (async () => {
    const wasm = join(dirname(require.resolve('circle-ir/package.json')), 'dist', 'wasm');
    const g = (name: string): string => join(wasm, `tree-sitter-${name}.wasm`);
    await initAnalyzer({
      wasmPath: join(wasm, 'web-tree-sitter.wasm'),
      languagePaths: { java: g('java'), javascript: g('javascript'), typescript: g('typescript'), tsx: g('tsx'), python: g('python'), html: g('html') },
    });
  })();
  return ready;
}

async function analysePin(root: string, params: CodeFactsParams): Promise<Pin> {
  await init();
  const files = readTree(root, params.language, params.excludedDirs);
  const project = await analyzeProject(files.map(f => ({ code: f.code, filePath: f.path, language: params.language })));
  const stableIds: Record<string, StableIdFile> = {};
  const branches: Record<string, BranchFact[]> = {};
  for (const f of files) {
    branches[f.path] = await deriveBranchFacts(f.code, params.language);
    if (stableIdsSupport(params.language)) stableIds[f.path] = await deriveStableIds(f.code, f.path, params.language);
  }
  const templates: Record<string, TemplateFact[]> = {};
  const templateFiles = TEMPLATE_EXTENSIONS[params.language]
    ? readTree(root, params.language, params.excludedDirs, TEMPLATE_EXTENSIONS[params.language])
    : [];
  for (const t of templateFiles) {
    const facts = await deriveTemplateFacts(t.code, t.path);
    if (facts.length > 0) templates[t.path] = facts;
  }
  const digests = new Map([...files, ...templateFiles].map(f => [f.path, f.digest]));
  return { files, digests, project, stableIds, branches, templates };
}

function filesOf(e: PathDiffEntry): string[] {
  const out = new Set<string>();
  for (const p of [e.before, e.after]) {
    if (!p) continue;
    out.add(p.source.file);
    out.add(p.sink.file);
    for (const h of p.hops) out.add(h.file);
    for (const t of p.sink.templates ?? []) out.add(t.file);
  }
  return [...out].sort();
}

/** Digest over the named files' bytes at both versions (`-` where a file is absent). */
function pairDigest(files: string[], before: Pin, after: Pin): string {
  return sha(files.map(f => `${f}\u0000${before.digests.get(f) ?? '-'}\u0000${after.digests.get(f) ?? '-'}`).join('\n'));
}

function diffOf(before: Pin, after: Pin, params: CodeFactsParams): PathSetDiff {
  return pathSetDiff(before.project, after.project, {
    cwe: params.cwe,
    stableIds: { before: before.stableIds, after: after.stableIds },
    branches: { before: before.branches, after: after.branches },
    templates: { before: before.templates, after: after.templates },
  });
}

function pathSetResult(diff: PathSetDiff, before: Pin, after: Pin): RunResult {
  const anchors: AnchorObservation[] = diff.entries.map(e => ({
    anchor: e.key,
    observation: e,
    inputDigest: pairDigest(filesOf(e), before, after),
  }));
  const all = [...new Set([...before.digests.keys(), ...after.digests.keys()])].sort();
  anchors.push({
    anchor: 'site',
    observation: { scheme: diff.scheme, cwe: diff.cwe, counts: diff.counts, pins: diff.pins },
    inputDigest: pairDigest(all, before, after),
  });
  return { driver: DRIVER, schemaVersion: SCHEMA_VERSION, capability: 'path-set-diff', anchors, environmentDigest: environmentDigest() };
}

/** Capability `path-set-diff` over a pin pair. */
export async function runPathSetDiff(root: PinPair, _views: Record<string, never> = {}, params: CodeFactsParams): Promise<RunResult> {
  const before = await analysePin(root.before, params);
  const after = await analysePin(root.after, params);
  return pathSetResult(diffOf(before, after, params), before, after);
}

/**
 * Capability `remedy-class` over a pin pair. `views.table` is the table's
 * bytes; a refused table throws circle-ir's `TableRefused`, so no observation
 * exists on it.
 */
export async function runRemedyClass(root: PinPair, views: { table: Uint8Array | string }, params: RemedyClassParams): Promise<RunResult> {
  const loaded = loadSafeConstructTable(views.table);
  const before = await analysePin(root.before, params);
  const after = await analysePin(root.after, params);
  const diff = params.pathSet ? diffFromResult(params.pathSet) : diffOf(before, after, params);
  const pathDigests = new Map(pathSetResult(diff, before, after).anchors.map(a => [a.anchor, a.inputDigest]));
  const result = remedyClassOf(diff, before.project, after.project, loaded, {
    stableIds: { before: before.stableIds, after: after.stableIds },
    branches: { after: after.branches },
    templates: { before: before.templates, after: after.templates },
    ...(params.scope ? { scope: params.scope } : {}),
    ...(params.outputContext ? { outputContext: true } : {}),
  });
  const anchors: AnchorObservation[] = result.sinks.map((s: RemedySinkObservation) => ({
    anchor: s.anchor,
    observation: s,
    inputDigest: sha(`${result.table.digest}\n${pathDigests.get(s.pathKey) ?? '-'}`),
  }));
  const byMatch: Record<string, number> = {};
  for (const s of result.sinks) {
    const k = s.match === 'multiple' || s.match === 'unrecognized' || s.match === 'abstained' ? s.match : 'row';
    byMatch[k] = (byMatch[k] ?? 0) + 1;
  }
  anchors.push({
    anchor: 'site',
    observation: { table: result.table, sinks: result.sinks.length, byMatch, scope: params.scope ?? 'closed', ...(params.outputContext ? { outputContext: true } : {}) },
    inputDigest: sha(`${result.table.digest}\n${pathDigests.get('site')}`),
  });
  return { driver: DRIVER, schemaVersion: SCHEMA_VERSION, capability: 'remedy-class', anchors, environmentDigest: environmentDigest() };
}

/** Rebuild the diff a `path-set-diff` result carries. */
function diffFromResult(r: RunResult): PathSetDiff {
  if (r.capability !== 'path-set-diff' || r.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(`code-facts: pathSet must be a path-set-diff result of schema ${SCHEMA_VERSION}`);
  }
  const site = r.anchors.find(a => a.anchor === 'site');
  if (!site) throw new Error('code-facts: pathSet has no site anchor');
  const s = site.observation as Pick<PathSetDiff, 'scheme' | 'cwe' | 'counts' | 'pins'>;
  return { ...s, entries: r.anchors.filter(a => a.anchor !== 'site').map(a => a.observation as PathDiffEntry) };
}
