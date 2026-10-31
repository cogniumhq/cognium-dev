/**
 * Calls into one dependency and the tests that reach them
 * (`dependency-calls@0.1`): for a dependency bump, every call site in the
 * subject that lands on the library, and which test entry points reach the
 * method that makes it.
 *
 * - **Calls**: `external` unresolved sites whose receiver type (the
 *   constructed type, or a static import's owner) is in one of the
 *   library's packages. The caller gives the packages: an artifact's
 *   packages are not readable from the subject's sources.
 * - **Tests**: each `test` entry is walked on its own over the reach core's
 *   graph. A test reaches a call **strongly** when its path to the calling
 *   method uses only strong edges, **weakly** otherwise.
 * - **covered**: every call is reached strongly by at least one test, and no
 *   file is partial.
 * - **unattributed**: `external` sites with no receiver type, or a bare
 *   simple name no import qualifies (other than `java.lang`). They could be
 *   calls into the library; a merge rule that relies on there being no other
 *   calls reads this count too.
 *
 * Experimental and opt-in; Java only for now (`java-graph@0.1` carries the
 * receiver types).
 */

import type { UnresolvedCall } from '../navigation/ts-call-edges.js';
import { ReachGraph, partialFileDetails, walkFrom, type PartialFile, type ReachInput, type ReachSite } from './reach.js';

export const DEPENDENCY_CALLS_SCHEME = 'dependency-calls@0.1' as const;

export interface DependencyCallsOptions {
  /** The library's packages, e.g. `com.fasterxml.jackson`; a package covers its subpackages. */
  packages: readonly string[];
}

export interface DependencyCallTest {
  /** The test entry's declaration id. */
  id: string;
  file: string;
  line: number;
  class: 'strong' | 'weak';
}

export interface DependencyCall {
  /** The calling declaration's id. */
  from: string;
  site: ReachSite;
  methodName: string;
  /** The library type the call lands on. */
  receiver: string;
  /** Tests reaching `from`, strong first, then by file and line. */
  tests: DependencyCallTest[];
}

export interface DependencyCallsResult {
  scheme: typeof DEPENDENCY_CALLS_SCHEME;
  ids: 'ids@0.1';
  packages: string[];
  calls: DependencyCall[];
  /** Calls with no strong test path. */
  uncovered: number;
  /** Every call reached strongly by a test, and no partial file. */
  covered: boolean;
  /** `external` sites the library cannot be ruled in or out for: no receiver type, or an unqualified one. */
  unattributed: number;
  partial: string[];
  partialFiles: PartialFile[];
}

/** `java.lang` types, which need no import. */
const JAVA_LANG = new Set([
  'Object', 'String', 'StringBuilder', 'StringBuffer', 'Math', 'System', 'Thread', 'Class', 'Runtime', 'Character',
  'Integer', 'Long', 'Short', 'Byte', 'Double', 'Float', 'Boolean', 'Number', 'Enum', 'Iterable', 'CharSequence',
  'Throwable', 'Exception', 'RuntimeException', 'Error', 'ProcessBuilder', 'ThreadLocal', 'ClassLoader', 'Record',
]);

const inPackages = (fqn: string, packages: readonly string[]): boolean =>
  packages.some(p => fqn === p || fqn.startsWith(`${p}.`));

export function dependencyCalls(
  input: Omit<ReachInput, 'unresolved'> & { unresolved: readonly UnresolvedCall[] },
  options: DependencyCallsOptions,
): DependencyCallsResult {
  const packages = [...new Set(options.packages)].sort();
  const external = input.unresolved.filter(u => u.reason === 'external');
  const hits = external.filter(u => u.receiver !== undefined && inPackages(u.receiver, packages));
  const unattributed = external.filter(u => u.receiver === undefined || (!u.receiver.includes('.') && !JAVA_LANG.has(u.receiver))).length;

  const g = new ReachGraph(input);
  const tests = input.entries
    .filter(e => e.kind === 'test')
    .sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)));
  const callers = new Set(hits.map(h => h.from));
  const reachedBy = new Map<string, DependencyCallTest[]>();
  for (const t of tests) {
    const visits = walkFrom(g, [{ id: t.id, weak: t.certainty === 'inferred' }]);
    for (const from of callers) {
      const cls = visits.has(`0${from}`) ? 'strong' : visits.has(`1${from}`) ? 'weak' : null;
      if (!cls) continue;
      const list = reachedBy.get(from) ?? [];
      list.push({ id: t.id, file: t.file, line: t.line, class: cls });
      reachedBy.set(from, list);
    }
  }

  const calls: DependencyCall[] = hits
    .map(h => ({
      from: h.from,
      site: { file: h.site.file, line: h.site.line, col: h.site.col },
      methodName: h.methodName,
      receiver: h.receiver as string,
      tests: [...(reachedBy.get(h.from) ?? [])].sort((a, b) => (a.class === b.class ? 0 : a.class === 'strong' ? -1 : 1)),
    }))
    .sort((a, b) => (a.site.file < b.site.file ? -1 : a.site.file > b.site.file ? 1 : a.site.line - b.site.line || a.site.col - b.site.col));
  const uncovered = calls.filter(c => !c.tests.some(t => t.class === 'strong')).length;
  return {
    scheme: DEPENDENCY_CALLS_SCHEME,
    ids: 'ids@0.1',
    packages,
    calls,
    uncovered,
    covered: uncovered === 0 && input.partial.length === 0,
    unattributed,
    partial: [...input.partial],
    partialFiles: partialFileDetails(input.partial, input.files),
  };
}
