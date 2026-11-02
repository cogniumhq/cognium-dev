/**
 * `facts@1` rows from a `java-graph@0.1` graph: a post-pass over today's
 * structures (graph-store plan T2, first half). The graph is a view of the
 * same facts, so every count here equals one of the graph's: `decl` rows =
 * declarations over `files`, `call` = `edges`, `unresolved` = `unresolved`,
 * `entries` = `entries`, `files` = `files`, `imports` = the files' import
 * declarations. `flow` and `moved` are empty from one snapshot (see
 * `schemas/facts@1.json`).
 */

import type { JavaGraph } from '../navigation/java-graph.js';
import { blake3 } from '../stable-ids/hash.js';
import { canonicalRows, compareCodePoints, idBytes } from './order.js';
import { FACTS_ID_WIDTH, FACTS_RELATIONS, type FactRow, type FactRows } from './schema.js';

/** One import declaration of a Java file, as the `imports` relation records it. */
export interface JavaImportRow {
  /** The imported name without a trailing `.*` (a static import's member path for `import static`). */
  target: string;
  wildcard: boolean;
}

export interface JavaFactsInput {
  /** Repository-relative path and the source it was analysed from. */
  path: string;
  code: string;
  imports: readonly JavaImportRow[];
}

const encoder = new TextEncoder();

/** blake3 of the UTF-8 bytes, first 16. */
export function contentHash(code: string): Uint8Array {
  return blake3(encoder.encode(code)).subarray(0, FACTS_ID_WIDTH);
}

/**
 * The eight relations, each in canonical order. `inputs` must cover every
 * file of the graph (a file the graph names but the inputs do not is an
 * error, never a silent gap). File ids are the 0-based positions in the
 * code-point-sorted path list.
 */
export function javaGraphFacts(graph: JavaGraph, inputs: readonly JavaFactsInput[]): FactRows {
  if (graph.ids !== 'ids@0.1') throw new Error(`facts@1: graph ids are ${String(graph.ids)}, not ids@0.1`);
  const paths = [...new Set(inputs.map(i => i.path))].sort(compareCodePoints);
  const fileId = new Map(paths.map((p, i) => [p, i] as const));
  const byPath = new Map(inputs.map(i => [i.path, i] as const));
  const fid = (path: string): number => {
    const id = fileId.get(path);
    if (id === undefined) throw new Error(`facts@1: ${path} is in the graph but not in the inputs`);
    return id;
  };

  const files: FactRow[] = paths.map(p => [fid(p), p, contentHash((byPath.get(p) as JavaFactsInput).code), 'java']);

  const decl: FactRow[] = [];
  for (const f of graph.files) {
    const file = fid(f.file);
    for (const d of f.decls) {
      decl.push([idBytes(d.id), d.kind, d.qualified_name, d.signature, file, d.start_line, d.body_hash ? idBytes(d.body_hash) : null]);
    }
  }

  const call: FactRow[] = graph.edges.map(e => [idBytes(e.from), idBytes(e.to), e.tier, e.methodName, fid(e.site.file), e.site.line, e.site.col]);

  const unresolved: FactRow[] = graph.unresolved.map(u => [idBytes(u.from), u.reason, u.receiver ?? null, u.methodName, fid(u.site.file), u.site.line, u.site.col]);

  const imports: FactRow[] = [];
  for (const p of paths) {
    const file = fid(p);
    for (const i of (byPath.get(p) as JavaFactsInput).imports) imports.push([file, i.target, i.wildcard]);
  }

  const entries: FactRow[] = graph.entries.map(e => [idBytes(e.id), e.kind, e.evidence, e.certainty]);

  return {
    files: canonicalRows(FACTS_RELATIONS.files, files),
    decl: canonicalRows(FACTS_RELATIONS.decl, decl),
    call: canonicalRows(FACTS_RELATIONS.call, call),
    unresolved: canonicalRows(FACTS_RELATIONS.unresolved, unresolved),
    flow: [],
    imports: canonicalRows(FACTS_RELATIONS.imports, imports),
    entries: canonicalRows(FACTS_RELATIONS.entries, entries),
    moved: [],
  };
}
