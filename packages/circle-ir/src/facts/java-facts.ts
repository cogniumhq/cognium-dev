/**
 * `facts@1` rows from a `java-graph@0.1` graph: a post-pass over today's
 * structures (graph-store plan T2, first half). The graph is a view of the
 * same facts, so every count here equals one of the graph's *before* the set
 * dedupe: `decl` rows = declarations over `files`, `call` = `edges`,
 * `unresolved` = `unresolved`, `entries` = `entries`, `files` = `files`,
 * `imports` = the files' import declarations; the manifest's
 * `duplicates_dropped` is the difference. `flow` and `moved` are empty from
 * one snapshot (see `schemas/facts@1.json`).
 *
 * Built as columns, never as row objects: each relation's typed arrays are
 * filled straight from the graph, then `canonicalTable` sorts one index
 * permutation, drops duplicates and gathers.
 */

import type { JavaGraph } from '../navigation/java-graph.js';
import { blake3, digest128 } from '../stable-ids/hash.js';
import { STABLE_ID_SCHEME } from '../stable-ids/types.js';
import { compareCodePoints } from './order.js';
import {
  FACTS_ID_WIDTH,
  FACTS_RELATION_NAMES,
  FACTS_RELATIONS,
  type FactsRelation,
  type FactsRelationName,
} from './schema.js';
import { IdDecoder, allocTable, canonicalTable, dictIndex, type FactColumnData, type FactTable } from './table.js';

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

/** The eight relations in canonical form (sorted sets) with what the dedupe dropped from each. */
export interface FactSet {
  relations: Readonly<Record<FactsRelationName, FactTable>>;
  duplicatesDropped: Readonly<Record<FactsRelationName, number>>;
}

const encoder = new TextEncoder();

/** blake3 of the UTF-8 bytes, first 16. */
export function contentHash(code: string): Uint8Array {
  return blake3(encoder.encode(code)).subarray(0, FACTS_ID_WIDTH);
}

/** The engine's `entry-index@0.1` kind as the `facts@1` vocabulary writes it: `bean` is `di`. */
export function factsEntryKind(kind: string): string {
  return kind === 'bean' ? 'di' : kind;
}

function dict(relation: FactsRelation, column: string): Map<string, number> {
  return dictIndex(relation.columns.find(c => c.name === column) as FactsRelation['columns'][number]);
}

function code(d: Map<string, number>, value: string, column: string): number {
  const k = d.get(value);
  if (k === undefined) throw new Error(`facts@1: ${JSON.stringify(value)} is not in the ${column} vocabulary`);
  return k;
}

/**
 * Re-keys for declarations whose `ids@0.1` id another file already derived
 * (two `package-info.java` of one package in different bundles). The
 * stable-ids duplicate rule applied over the snapshot: the later one in file
 * order gets `#n` on its qualified name and the id derived from it, so the
 * `decl` key is unique. `(file, old id) → (new id, new qualified name)`.
 */
type Rekey = Map<string, Map<string, { id: string; qualifiedName: string }>>;

/**
 * The eight relations, each a canonical set, with the dedupe counts
 * (`FactSet`). `inputs` must cover every file of the graph (a file the graph
 * names but the inputs do not is an error, never a silent gap). File ids are
 * the 0-based positions in the code-point-sorted path list.
 */
export function javaGraphFactSet(graph: JavaGraph, inputs: readonly JavaFactsInput[]): FactSet {
  if (graph.ids !== 'ids@0.1') throw new Error(`facts@1: graph ids are ${String(graph.ids)}, not ids@0.1`);
  const paths = [...new Set(inputs.map(i => i.path))].sort(compareCodePoints);
  const fileId = new Map(paths.map((p, i) => [p, i] as const));
  const byPath = new Map(inputs.map(i => [i.path, i] as const));
  const fid = (path: string): number => {
    const id = fileId.get(path);
    if (id === undefined) throw new Error(`facts@1: ${path} is in the graph but not in the inputs`);
    return id;
  };
  const R = FACTS_RELATIONS;
  const ids = new IdDecoder();

  // files
  const files = allocTable(R.files, paths.length);
  {
    const language = code(dict(R.files, 'language'), 'java', 'language');
    for (let i = 0; i < paths.length; i++) {
      (files[0] as Uint32Array)[i] = i;
      (files[1] as string[])[i] = paths[i];
      (files[2] as Uint8Array).set(contentHash((byPath.get(paths[i]) as JavaFactsInput).code), i * FACTS_ID_WIDTH);
      (files[3] as Int8Array)[i] = language;
    }
  }

  // decl — in file order (code point), the order the duplicate rule counts in.
  const graphFiles = new Map(graph.files.map(f => [f.file, f] as const));
  const orderedFiles = paths.map(p => graphFiles.get(p)).filter((f): f is NonNullable<typeof f> => f !== undefined);
  for (const f of graph.files) if (!fileId.has(f.file)) fid(f.file);
  const declCount = orderedFiles.reduce((n, f) => n + f.decls.length, 0);
  const decl = allocTable(R.decl, declCount);
  const rekey: Rekey = new Map();
  {
    const kinds = dict(R.decl, 'kind');
    const seen = new Map<string, number>();
    let i = 0;
    for (const f of orderedFiles) {
      const file = fid(f.file);
      for (const d of f.decls) {
        let id = d.id;
        let qualifiedName = d.qualified_name;
        const n = (seen.get(d.id) ?? 0) + 1;
        seen.set(d.id, n);
        if (n > 1) {
          qualifiedName = `${d.qualified_name}#${n}`;
          id = digest128([STABLE_ID_SCHEME, f.language, d.kind, qualifiedName, d.signature]);
          let m = rekey.get(f.file);
          if (!m) rekey.set(f.file, (m = new Map()));
          m.set(d.id, { id, qualifiedName });
        }
        ids.put(id, decl[0] as Uint8Array, i * FACTS_ID_WIDTH);
        (decl[1] as Int8Array)[i] = code(kinds, d.kind, 'kind');
        (decl[2] as string[])[i] = qualifiedName;
        (decl[3] as string[])[i] = d.signature;
        (decl[4] as Uint32Array)[i] = file;
        (decl[5] as Uint32Array)[i] = d.start_line;
        // No nulls in facts@1: all-zero bytes when the engine derived no body hash (the array starts zeroed).
        if (d.body_hash) ids.put(d.body_hash, decl[6] as Uint8Array, i * FACTS_ID_WIDTH);
        i++;
      }
    }
  }
  const callerId = (file: string, id: string): string => (rekey.size > 0 ? rekey.get(file)?.get(id)?.id ?? id : id);

  // call
  const call = allocTable(R.call, graph.edges.length);
  {
    const tiers = dict(R.call, 'tier');
    for (let i = 0; i < graph.edges.length; i++) {
      const e = graph.edges[i];
      ids.put(callerId(e.site.file, e.from), call[0] as Uint8Array, i * FACTS_ID_WIDTH);
      ids.put(e.to, call[1] as Uint8Array, i * FACTS_ID_WIDTH);
      (call[2] as Int8Array)[i] = code(tiers, e.tier, 'tier');
      (call[3] as string[])[i] = e.methodName;
      (call[4] as Uint32Array)[i] = fid(e.site.file);
      (call[5] as Uint32Array)[i] = e.site.line;
      (call[6] as Uint32Array)[i] = e.site.col;
    }
  }

  // unresolved
  const unresolved = allocTable(R.unresolved, graph.unresolved.length);
  {
    const reasons = dict(R.unresolved, 'reason');
    for (let i = 0; i < graph.unresolved.length; i++) {
      const u = graph.unresolved[i];
      ids.put(callerId(u.site.file, u.from), unresolved[0] as Uint8Array, i * FACTS_ID_WIDTH);
      (unresolved[1] as Int8Array)[i] = code(reasons, u.reason, 'reason');
      // No nulls in facts@1: the empty string when the receiver is unknown.
      (unresolved[2] as string[])[i] = u.receiver ?? '';
      (unresolved[3] as string[])[i] = u.methodName;
      (unresolved[4] as Uint32Array)[i] = fid(u.site.file);
      (unresolved[5] as Uint32Array)[i] = u.site.line;
      (unresolved[6] as Uint32Array)[i] = u.site.col;
    }
  }

  // imports
  const importCount = paths.reduce((n, p) => n + (byPath.get(p) as JavaFactsInput).imports.length, 0);
  const imports = allocTable(R.imports, importCount);
  {
    let i = 0;
    for (const p of paths) {
      const file = fid(p);
      for (const imp of (byPath.get(p) as JavaFactsInput).imports) {
        (imports[0] as Uint32Array)[i] = file;
        (imports[1] as string[])[i] = imp.target;
        (imports[2] as Uint8Array)[i] = imp.wildcard ? 1 : 0;
        i++;
      }
    }
  }

  // entries
  const entries = allocTable(R.entries, graph.entries.length);
  {
    const kinds = dict(R.entries, 'kind');
    const certainties = dict(R.entries, 'certainty');
    for (let i = 0; i < graph.entries.length; i++) {
      const e = graph.entries[i];
      ids.put(e.id, entries[0] as Uint8Array, i * FACTS_ID_WIDTH);
      (entries[1] as Int8Array)[i] = code(kinds, factsEntryKind(e.kind), 'kind');
      (entries[2] as string[])[i] = e.evidence;
      (entries[3] as Int8Array)[i] = code(certainties, e.certainty, 'certainty');
    }
  }

  const raw: Record<FactsRelationName, { columns: FactColumnData[]; length: number }> = {
    files: { columns: files, length: paths.length },
    decl: { columns: decl, length: declCount },
    call: { columns: call, length: graph.edges.length },
    unresolved: { columns: unresolved, length: graph.unresolved.length },
    flow: { columns: allocTable(R.flow, 0), length: 0 },
    imports: { columns: imports, length: importCount },
    entries: { columns: entries, length: graph.entries.length },
    moved: { columns: allocTable(R.moved, 0), length: 0 },
  };
  const relations = {} as Record<FactsRelationName, FactTable>;
  const duplicatesDropped = {} as Record<FactsRelationName, number>;
  for (const name of FACTS_RELATION_NAMES) {
    const { table, duplicatesDropped: dropped } = canonicalTable(R[name], raw[name].columns, raw[name].length);
    relations[name] = table;
    duplicatesDropped[name] = dropped;
  }
  return { relations, duplicatesDropped };
}

/** The eight relations as canonical sets (`javaGraphFactSet` without the dedupe counts). */
export function javaGraphFacts(graph: JavaGraph, inputs: readonly JavaFactsInput[]): Readonly<Record<FactsRelationName, FactTable>> {
  return javaGraphFactSet(graph, inputs).relations;
}
