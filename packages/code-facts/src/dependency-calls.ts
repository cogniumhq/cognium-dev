/**
 * Capability `dependency-calls`: for a dependency bump (E02), every call
 * site in the subject that lands on the bumped Maven artifact, the tests
 * that reach each one, and the external sites that cannot be ruled in or
 * out (circle-ir `dependency-calls@0.1`).
 *
 * The artifact's packages come from its resolved jar when one is found
 * (`views.jar`, `params.jarPath`, or the local Maven repository for
 * `groupId:artifactId:version`), else circle-ir's fallback table; an
 * artifact neither resolves throws circle-ir's `UnknownArtifact`. The jar's
 * digest is part of every anchor's input, so the same tree and jar give
 * byte-identical output.
 */
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  buildJavaGraph,
  dependencyCalls,
  mavenArtifact,
  type DependencyCall,
  type DependencyCallsResult,
  type DependencyUnattributedSite,
} from 'circle-ir';
import { readTree, sha, type TreeFile } from './tree.js';

export interface DependencyCallsParams {
  /** `groupId:artifactId[:version]`; the version finds the jar in the Maven repository. */
  artifact: string;
  /** Java only (circle-ir's `java-graph@0.1` carries the receiver types). */
  language: 'java';
  /** A resolved jar on disk; wins over the Maven repository. */
  jarPath?: string;
  /** The local Maven repository; defaults to `$MAVEN_REPO_LOCAL`, else `~/.m2/repository`. */
  mavenRepo?: string;
  /** Directory names never read; defaults to `DEFAULT_EXCLUDED_DIRS`. */
  excludedDirs?: readonly string[];
}

/** One call's row, as the evidence card lists it. */
export interface DependencyCallRow {
  state: 'covered' | 'uncovered';
  call: DependencyCall;
}

export interface DependencyCallsSite {
  scheme: DependencyCallsResult['scheme'];
  artifact: string;
  packages: string[];
  packageSource: DependencyCallsResult['packageSource'];
  /** `sha256:` of the jar the packages were read from; absent for the table. */
  jarDigest?: string;
  counts: { calls: number; covered: number; uncovered: number; unattributed: number };
  /** Every call reached strongly by a test, and no partial file. */
  covered: boolean;
  unattributed: DependencyUnattributedSite[];
  partial: string[];
  partialFiles: DependencyCallsResult['partialFiles'];
}

/** `<repo>/<group path>/<artifact>/<version>/<artifact>-<version>.jar`, when the coordinate has a version. */
export function mavenJarPath(coordinate: string, repo: string): string | null {
  const [group, artifact, version] = coordinate.trim().split(':');
  if (!group || !artifact || !version) return null;
  return join(repo, ...group.split('.'), artifact, version, `${artifact}-${version}.jar`);
}

function defaultMavenRepo(): string {
  return process.env.MAVEN_REPO_LOCAL || join(homedir(), '.m2', 'repository');
}

/** The jar's bytes: given, at `jarPath`, or in the Maven repository; null when none is found. */
export function findJar(params: DependencyCallsParams, given?: Uint8Array): Uint8Array | null {
  if (given) return given;
  if (params.jarPath) return readFileSync(params.jarPath);
  const path = mavenJarPath(params.artifact, params.mavenRepo ?? defaultMavenRepo());
  return path && existsSync(path) ? readFileSync(path) : null;
}

/** The files an anchor read: the call's file and the files of the tests that reach it. */
function callFiles(c: DependencyCall): string[] {
  return [...new Set([c.site.file, ...c.tests.map(t => t.file)])].sort();
}

function digestOf(files: string[], byPath: Map<string, string>, jarDigest: string): string {
  return sha([jarDigest, ...files.map(f => `${f}\u0000${byPath.get(f) ?? '-'}`)].join('\n'));
}

/**
 * Run `dependency-calls` over one tree (check out the version under test,
 * e.g. the fix). Anchors: one per call (`call:<file>:<line>:<col>`), with
 * `covered` (a strong test path) or `uncovered`, then `site` with the counts
 * and the unattributed sites.
 */
export async function dependencyCallsFacts(
  root: string,
  views: { jar?: Uint8Array },
  params: DependencyCallsParams,
  init: () => Promise<void>,
): Promise<{ anchors: Array<{ anchor: string; observation: unknown; inputDigest: string }> }> {
  if (params.language !== 'java') throw new Error(`code-facts: dependency-calls supports java only, not ${String(params.language)}`);
  const artifact = mavenArtifact(params.artifact);
  const jar = findJar(params, views.jar);
  await init();
  const files: TreeFile[] = readTree(root, 'java', params.excludedDirs);
  const graph = await buildJavaGraph(files.map(f => ({ path: f.path, code: f.code })));
  const result = dependencyCalls(graph, jar ? { artifact, jar } : { artifact });
  const jarDigest = jar ? sha(Buffer.from(jar)) : 'table';
  const byPath = new Map(files.map(f => [f.path, f.digest]));

  const rows: DependencyCallRow[] = result.calls.map(call => ({
    state: call.tests.some(t => t.class === 'strong') ? 'covered' : 'uncovered',
    call,
  }));
  const anchors: Array<{ anchor: string; observation: DependencyCallRow | DependencyCallsSite; inputDigest: string }> = rows.map(r => ({
    anchor: `call:${r.call.site.file}:${r.call.site.line}:${r.call.site.col}`,
    observation: r,
    inputDigest: digestOf(callFiles(r.call), byPath, jarDigest),
  }));
  const site: DependencyCallsSite = {
    scheme: result.scheme,
    artifact,
    packages: result.packages,
    packageSource: result.packageSource,
    ...(jar ? { jarDigest } : {}),
    counts: {
      calls: rows.length,
      covered: rows.filter(r => r.state === 'covered').length,
      uncovered: result.uncovered,
      unattributed: result.unattributed,
    },
    covered: result.covered,
    unattributed: result.unattributedSites,
    partial: result.partial,
    partialFiles: result.partialFiles,
  };
  anchors.push({ anchor: 'site', observation: site, inputDigest: digestOf([...byPath.keys()].sort(), byPath, jarDigest) });
  return { anchors };
}
