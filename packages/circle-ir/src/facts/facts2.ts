/**
 * `facts@2` rows from a call graph: a post-pass over the graph the engine
 * already builds (`java-graph@0.1`, or `ts-call-edges@0.1` for TypeScript and
 * JavaScript), the counterpart of `javaGraphFactSet` for the `facts@2`
 * schema. Opt-in: `facts@1` stays the default (`JavaGraphOptions.factsScheme`).
 *
 * Against the `facts@1` post-pass:
 * - every relation that names a file carries the stable file key
 *   (`fileKey(path)`), never a dense index;
 * - a site (`call`, `unresolved`, `ref`, `registration`) carries `rel_line` =
 *   its line minus the start line of the declaration whose body holds it, and
 *   its column, and no file (the file is that declaration's file);
 * - `decl` has no position (`decl_pos` holds it) and gains `name`,
 *   `parent_id`, `type_only`, the two `ids@0.1` flags, `contained` (the
 *   reach walk's `contains` rule, `containedIn`) and `loads_parent` (the
 *   graph's member-initializes-its-class `loads`);
 * - `call.declaring` marks the polymorphic row whose callee is the member the
 *   receiver's static type declares;
 * - `ref` (references), `registration` (unresolved registrations),
 *   `files.partial` and `parse_error` (the first blocking parse error, its
 *   column 0-based) are new.
 *
 * The `#n` re-key of a declaration id two files derive is the `facts@1` one,
 * and it rewrites `parent_id` and every site's declaration as it rewrites
 * `caller_id`. Built as columns, then each relation goes through
 * `canonicalTable` (sorted, duplicates dropped and counted).
 */

import { containedIn } from '../graph-facts/reach.js';
import type { JavaGraph } from '../navigation/java-graph.js';
import type { CallEdge, CallEdgeSite, ReferenceEdge, TsCallGraph, TsEntry, UnresolvedCall, UnresolvedRegistration } from '../navigation/ts-call-edges.js';
import { digest128 } from '../stable-ids/hash.js';
import { NodeIdWriter, declLocator, locateNodes } from '../stable-ids/nodes.js';
import { STABLE_ID_SCHEME, type StableDecl, type StableIdFile } from '../stable-ids/types.js';
import { compareCodePoints } from './order.js';
import { FACTS_ID_WIDTH, type FactsRelation } from './schema.js';
import { FACTS2_RELATION_NAMES, FACTS2_RELATIONS, FACTS2_SCHEME, fileKey, type Facts2RelationName } from './schema2.js';
import { IdDecoder, allocTable, canonicalTable, dictIndex, keyCollisions, type FactColumnData, type FactTable } from './table.js';
import { contentHash, factsEntryKind, type JavaFactsInput } from './java-facts.js';

/** One file's source as the post-pass reads it: path, code (for `content_hash`), its imports and, optionally, its DFG (for `flow`). */
export type Facts2Input = JavaFactsInput;

/** The twelve relations in canonical form (sorted sets) with what the dedupe dropped from each. */
export interface Fact2Set {
  relations: Readonly<Record<Facts2RelationName, FactTable>>;
  duplicatesDropped: Readonly<Record<Facts2RelationName, number>>;
}

/** What the post-pass reads from a graph; `JavaGraph` and `TsCallGraph` both have it. */
export interface Facts2Graph {
  ids: 'ids@0.1';
  files: readonly StableIdFile[];
  edges: readonly CallEdge[];
  unresolved: readonly UnresolvedCall[];
  references: readonly ReferenceEdge[];
  entries: readonly Pick<TsEntry, 'id' | 'kind' | 'certainty' | 'evidence'>[];
  unresolvedRegistrations: readonly UnresolvedRegistration[];
  typeOnly: readonly string[];
}

interface Facts2Extras {
  /** Member-initializes-its-class edges (Java `loads`): `loads_parent` is true where one runs from a declaration to its parent. */
  loads?: readonly { from: string; to: string }[];
  /** The language written for an input file the graph does not hold; absent, such a file is an error. */
  language?: string;
}

/**
 * Polymorphic call edges that are the declaring row of their site. The Java
 * graph sets `via` on the other rows only, so `buildJavaGraph` marks the
 * declaring one here; the TypeScript graph sets `via` on every row of the
 * site, the declaring one included (`via === to`). A mark, not a field, so
 * the graph's JSON is unchanged.
 */
const declaringEdges = new WeakSet<object>();

/** Mark `edge` as the declaring row of its polymorphic site (for `call.declaring`). */
export function markDeclaringEdge(edge: CallEdge): void {
  declaringEdges.add(edge);
}

function isDeclaring(e: CallEdge): boolean {
  return e.tier === 'polymorphic' && (e.via === e.to || declaringEdges.has(e));
}

function dict(relation: FactsRelation, column: string): Map<string, number> {
  return dictIndex(relation.columns.find(c => c.name === column) as FactsRelation['columns'][number]);
}

function code(d: Map<string, number>, value: string, column: string): number {
  const k = d.get(value);
  if (k === undefined) throw new Error(`${FACTS2_SCHEME}: ${JSON.stringify(value)} is not in the ${column} vocabulary`);
  return k;
}

/** `(file, old id) → (new id, new qualified name)` for the snapshot's `#n` re-key (see `javaGraphFactSet`). */
type Rekey = Map<string, Map<string, { id: string; qualifiedName: string }>>;

/**
 * The twelve `facts@2` relations of a graph, each a canonical set, with the
 * dedupe counts. `inputs` must cover every file of the graph (a file the
 * graph names but the inputs do not is an error, never a silent gap).
 */
function graphFact2Set(graph: Facts2Graph, inputs: readonly Facts2Input[], extras: Facts2Extras): Fact2Set {
  if (graph.ids !== STABLE_ID_SCHEME) throw new Error(`${FACTS2_SCHEME}: graph ids are ${String(graph.ids)}, not ${STABLE_ID_SCHEME}`);
  const R = FACTS2_RELATIONS;
  const ids = new IdDecoder();
  const paths = [...new Set(inputs.map(i => i.path))].sort(compareCodePoints);
  const byPath = new Map(inputs.map(i => [i.path, i] as const));
  const graphFiles = new Map(graph.files.map(f => [f.file, f] as const));
  for (const f of graph.files) if (!byPath.has(f.file)) throw new Error(`${FACTS2_SCHEME}: ${f.file} is in the graph but not in the inputs`);
  const keys = new Map(paths.map(p => [p, fileKey(p)] as const));
  const orderedFiles = paths.map(p => graphFiles.get(p)).filter((f): f is StableIdFile => f !== undefined);

  // Each file's declarations by their engine id, for parents, start lines and site owners.
  const declsOf = new Map(orderedFiles.map(f => [f.file, new Map(f.decls.map(d => [d.id, d] as const))] as const));
  const declIn = (file: string, id: string): StableDecl => {
    const d = declsOf.get(file)?.get(id);
    if (!d) throw new Error(`${FACTS2_SCHEME}: declaration ${id} is not in ${file}`);
    return d;
  };

  // files
  const files = allocTable(R.files, paths.length);
  let partialCount = 0;
  {
    const languages = dict(R.files, 'language');
    for (let i = 0; i < paths.length; i++) {
      const p = paths[i];
      const g = graphFiles.get(p);
      const language = g?.language ?? extras.language;
      if (language === undefined) throw new Error(`${FACTS2_SCHEME}: ${p} is in the inputs but not in the graph`);
      (files[0] as Uint8Array).set(keys.get(p) as Uint8Array, i * FACTS_ID_WIDTH);
      (files[1] as string[])[i] = p;
      (files[2] as Uint8Array).set(contentHash((byPath.get(p) as Facts2Input).code), i * FACTS_ID_WIDTH);
      (files[3] as Int8Array)[i] = code(languages, language, 'language');
      if (g?.partial) {
        (files[4] as Uint8Array)[i] = 1;
        partialCount++;
      }
    }
  }

  // parse_error — one row per partial file.
  const parseError = allocTable(R.parse_error, partialCount);
  {
    let i = 0;
    for (const f of orderedFiles) {
      if (!f.partial) continue;
      const e = f.parseError;
      if (!e) throw new Error(`${FACTS2_SCHEME}: ${f.file} is partial but has no parse error`);
      (parseError[0] as Uint8Array).set(keys.get(f.file) as Uint8Array, i * FACTS_ID_WIDTH);
      (parseError[1] as Uint32Array)[i] = e.line;
      // The engine's parse-error column is 1-based; every column in facts@2 is 0-based.
      (parseError[2] as Uint32Array)[i] = Math.max(0, e.column - 1);
      (parseError[3] as string[])[i] = e.nodeKind;
      (parseError[4] as string[])[i] = e.parent;
      i++;
    }
  }

  // decl and decl_pos — in file order (code point), the order the duplicate rule counts in.
  const declCount = orderedFiles.reduce((n, f) => n + f.decls.length, 0);
  const decl = allocTable(R.decl, declCount);
  const declPos = allocTable(R.decl_pos, declCount);
  const rekey: Rekey = new Map();
  const rekeyed = (file: string, id: string): string => (rekey.size > 0 ? rekey.get(file)?.get(id)?.id ?? id : id);
  {
    const kinds = dict(R.decl, 'kind');
    const typeOnly = new Set(graph.typeOnly);
    const loads = new Set((extras.loads ?? []).map(l => `${l.from}\n${l.to}`));
    const seen = new Map<string, number>();
    let i = 0;
    for (const f of orderedFiles) {
      const file = keys.get(f.file) as Uint8Array;
      const byId = declsOf.get(f.file) as Map<string, StableDecl>;
      const module = f.decls[0];
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
        const o = i * FACTS_ID_WIDTH;
        const parent = d.parent === null ? undefined : byId.get(d.parent);
        ids.put(id, decl[0] as Uint8Array, o);
        (decl[1] as Int8Array)[i] = code(kinds, d.kind, 'kind');
        (decl[2] as string[])[i] = d.name;
        (decl[3] as string[])[i] = qualifiedName;
        (decl[4] as string[])[i] = d.signature;
        (decl[5] as Uint8Array).set(file, o);
        // No nulls in facts@2: all-zero bytes for a module's parent and for a missing body hash (the arrays start zeroed).
        if (d.parent !== null) ids.put(rekeyed(f.file, d.parent), decl[6] as Uint8Array, o);
        if (d.body_hash) ids.put(d.body_hash, decl[7] as Uint8Array, o);
        (decl[8] as Uint8Array)[i] = typeOnly.has(d.id) ? 1 : 0;
        (decl[9] as Uint8Array)[i] = d.flags.includes('unstable:anonymous') ? 1 : 0;
        (decl[10] as Uint8Array)[i] = d.flags.includes('unstable:duplicate') || n > 1 ? 1 : 0;
        (decl[11] as Uint8Array)[i] = d !== module && parent !== undefined && containedIn(d, parent, module, f.language) ? 1 : 0;
        (decl[12] as Uint8Array)[i] = d.parent !== null && loads.has(`${d.id}\n${d.parent}`) ? 1 : 0;

        ids.put(id, declPos[0] as Uint8Array, o);
        (declPos[1] as Uint32Array)[i] = d.start_line;
        (declPos[2] as Uint32Array)[i] = d.end_line;
        (declPos[3] as Uint32Array)[i] = d.start_column;
        (declPos[4] as Uint32Array)[i] = d.end_column;
        i++;
      }
    }
  }

  /** The site's line relative to the start line of `owner`, the declaration (in the site's file) whose body holds it. */
  const relLine = (site: CallEdgeSite, owner: string): number => {
    const start = declIn(site.file, owner).start_line;
    const rel = site.line - start;
    if (rel < 0) throw new Error(`${FACTS2_SCHEME}: a site at ${site.file}:${site.line} lies above its declaration's start line ${start}`);
    return rel;
  };

  // call
  const call = allocTable(R.call, graph.edges.length);
  {
    const tiers = dict(R.call, 'tier');
    for (let i = 0; i < graph.edges.length; i++) {
      const e = graph.edges[i];
      ids.put(rekeyed(e.site.file, e.from), call[0] as Uint8Array, i * FACTS_ID_WIDTH);
      ids.put(e.to, call[1] as Uint8Array, i * FACTS_ID_WIDTH);
      (call[2] as Int8Array)[i] = code(tiers, e.tier, 'tier');
      (call[3] as string[])[i] = e.methodName;
      (call[4] as Uint32Array)[i] = relLine(e.site, e.from);
      (call[5] as Uint32Array)[i] = e.site.col;
      (call[6] as Uint8Array)[i] = isDeclaring(e) ? 1 : 0;
    }
  }

  // unresolved
  const unresolved = allocTable(R.unresolved, graph.unresolved.length);
  {
    const reasons = dict(R.unresolved, 'reason');
    for (let i = 0; i < graph.unresolved.length; i++) {
      const u = graph.unresolved[i];
      ids.put(rekeyed(u.site.file, u.from), unresolved[0] as Uint8Array, i * FACTS_ID_WIDTH);
      (unresolved[1] as Int8Array)[i] = code(reasons, u.reason, 'reason');
      // No nulls in facts@2: the empty string when the receiver is unknown.
      (unresolved[2] as string[])[i] = u.receiver ?? '';
      (unresolved[3] as string[])[i] = u.methodName;
      (unresolved[4] as Uint32Array)[i] = relLine(u.site, u.from);
      (unresolved[5] as Uint32Array)[i] = u.site.col;
    }
  }

  // ref
  const ref = allocTable(R.ref, graph.references.length);
  for (let i = 0; i < graph.references.length; i++) {
    const r = graph.references[i];
    ids.put(rekeyed(r.site.file, r.from), ref[0] as Uint8Array, i * FACTS_ID_WIDTH);
    ids.put(r.to, ref[1] as Uint8Array, i * FACTS_ID_WIDTH);
    (ref[2] as Uint32Array)[i] = relLine(r.site, r.from);
    (ref[3] as Uint32Array)[i] = r.site.col;
  }

  // registration — `from` as the engine gives it (Java), else the innermost declaration enclosing the site.
  const registration = allocTable(R.registration, graph.unresolvedRegistrations.length);
  {
    const reasons = dict(R.registration, 'reason');
    const locators = new Map<string, (line: number, column?: number) => StableDecl | null>();
    const owner = (site: CallEdgeSite): string => {
      const f = graphFiles.get(site.file);
      if (!f) throw new Error(`${FACTS2_SCHEME}: a registration in ${site.file}, which is not in the graph`);
      let at = locators.get(site.file);
      if (!at) locators.set(site.file, (at = declLocator(f)));
      return (at(site.line, site.col) ?? f.decls[0]).id;
    };
    for (let i = 0; i < graph.unresolvedRegistrations.length; i++) {
      const reg = graph.unresolvedRegistrations[i];
      const from = reg.from ?? owner(reg.site);
      ids.put(rekeyed(reg.site.file, from), registration[0] as Uint8Array, i * FACTS_ID_WIDTH);
      (registration[1] as Int8Array)[i] = code(reasons, reg.reason, 'reason');
      (registration[2] as string[])[i] = reg.evidence;
      (registration[3] as Uint32Array)[i] = relLine(reg.site, from);
      (registration[4] as Uint32Array)[i] = reg.site.col;
    }
  }

  // flow — def-use edges on fixed-width node ids, as in facts@1.
  const flowCapacity = orderedFiles.reduce((n, f) => n + ((byPath.get(f.file) as Facts2Input).dfg?.uses.length ?? 0), 0);
  const flow = allocTable(R.flow, flowCapacity);
  let flowCount = 0;
  if (flowCapacity > 0) {
    const defUse = code(dict(R.flow, 'kind'), 'def-use', 'kind');
    const writer = new NodeIdWriter();
    const from = flow[0] as Uint8Array;
    const to = flow[1] as Uint8Array;
    const kinds = flow[2] as Int8Array;
    for (const f of orderedFiles) {
      const dfg = (byPath.get(f.file) as Facts2Input).dfg;
      if (!dfg || dfg.uses.length === 0) continue;
      const fileRekey = rekey.get(f.file);
      const bodyId = (d: StableDecl): string => {
        const r = fileRekey?.get(d.id);
        return r ? `${r.id}.${d.body_hash}` : d.body_id;
      };
      const defs = locateNodes(f, dfg.defs, (d, at) => at(d.line, d.column));
      const defIds = new Uint8Array(defs.length * FACTS_ID_WIDTH);
      const defAt = new Map<number, number>();
      for (let i = 0; i < defs.length; i++) {
        const n = defs[i];
        if (n === null) continue;
        writer.forBody(bodyId(n.decl), 'def');
        writer.write(n.ordinal, defIds, i * FACTS_ID_WIDTH);
        defAt.set(dfg.defs[i].id, i * FACTS_ID_WIDTH);
      }
      const uses = locateNodes(f, dfg.uses, (u, at) => at(u.line, u.column));
      for (let i = 0; i < uses.length; i++) {
        const n = uses[i];
        const u = dfg.uses[i];
        if (n === null || u.def_id === null) continue;
        const d = defAt.get(u.def_id);
        if (d === undefined) continue;
        const o = flowCount * FACTS_ID_WIDTH;
        for (let k = 0; k < FACTS_ID_WIDTH; k++) from[o + k] = defIds[d + k];
        writer.forBody(bodyId(n.decl), 'use');
        writer.write(n.ordinal, to, o);
        kinds[flowCount] = defUse;
        flowCount++;
      }
    }
  }

  // imports
  const importCount = paths.reduce((n, p) => n + (byPath.get(p) as Facts2Input).imports.length, 0);
  const imports = allocTable(R.imports, importCount);
  {
    let i = 0;
    for (const p of paths) {
      const file = keys.get(p) as Uint8Array;
      for (const imp of (byPath.get(p) as Facts2Input).imports) {
        (imports[0] as Uint8Array).set(file, i * FACTS_ID_WIDTH);
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

  const raw: Record<Facts2RelationName, { columns: FactColumnData[]; length: number }> = {
    files: { columns: files, length: paths.length },
    decl: { columns: decl, length: declCount },
    decl_pos: { columns: declPos, length: declCount },
    call: { columns: call, length: graph.edges.length },
    unresolved: { columns: unresolved, length: graph.unresolved.length },
    ref: { columns: ref, length: graph.references.length },
    registration: { columns: registration, length: graph.unresolvedRegistrations.length },
    parse_error: { columns: parseError, length: partialCount },
    flow: { columns: flow, length: flowCount },
    imports: { columns: imports, length: importCount },
    entries: { columns: entries, length: graph.entries.length },
    moved: { columns: allocTable(R.moved, 0), length: 0 },
  };
  const relations = {} as Record<Facts2RelationName, FactTable>;
  const duplicatesDropped = {} as Record<Facts2RelationName, number>;
  for (const name of FACTS2_RELATION_NAMES) {
    const { table, duplicatesDropped: dropped } = canonicalTable(R[name], raw[name].columns, raw[name].length);
    relations[name] = table;
    duplicatesDropped[name] = dropped;
  }
  // Two paths with one key (a 128-bit collision) must fail, never merge.
  if (keyCollisions(R.files, relations.files) > 0) throw new Error(`${FACTS2_SCHEME}: two paths share a file key`);
  return { relations, duplicatesDropped };
}

/**
 * The `facts@2` relations of a `java-graph@0.1` graph. Every file the graph
 * holds must be in `inputs`; an input the graph does not hold is written as a
 * Java file with no declarations.
 */
export function javaGraphFact2Set(graph: JavaGraph, inputs: readonly Facts2Input[]): Fact2Set {
  return graphFact2Set(graph, inputs, { loads: graph.loads, language: 'java' });
}

/**
 * The `facts@2` relations of a `ts-call-edges@0.1` graph (TypeScript and
 * JavaScript). Every file the graph holds must be in `inputs`, and every
 * input must be a file of the graph. The TypeScript-only edges (field uses,
 * module imports and loads) have no relation in `facts@2`; `imports` holds
 * whatever the inputs list.
 */
export function tsGraphFact2Set(graph: TsCallGraph, inputs: readonly Facts2Input[]): Fact2Set {
  return graphFact2Set(graph, inputs, {});
}
