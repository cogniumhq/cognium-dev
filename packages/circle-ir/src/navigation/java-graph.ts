/**
 * Java graph facts keyed by stable ids (`java-graph@0.1`): the reach core's
 * input for Java.
 *
 * - **Declarations** from `deriveJavaIds` (`ids@0.1`).
 * - **Call edges** from the Java navigation index (`callSites`), each target
 *   located by file and declaration line and keyed to its declaration id,
 *   with the index's tiers. A target the ids do not hold is an unresolved
 *   site, never dropped.
 * - **References**: method references (`Type::m`, `this::m`, `Type::new`).
 * - **Loads**: a member initializes its class (static initializer, fields).
 * - **Entries** (`entry-index@0.1`): Spring and JAX-RS routes with class
 *   prefixes, servlets and filters, Spring beans, lifecycle, scheduled and
 *   listener methods, `main`, JUnit/TestNG tests and test files,
 *   `Class.forName` literals and `META-INF/services` files.
 * - **typeOnly**: interfaces, annotation types and body-less methods.
 *
 * Library code: no file access; the caller passes the sources (and may pass
 * each file's IR, which must come from `analyze` with `navigationTypes`).
 */

import { analyze } from '../analyzer.js';
import { disposeTree, parse, type Node, type Tree } from '../core/parser.js';
import { deriveJavaIds } from '../stable-ids/java.js';
import { declLocator } from '../stable-ids/nodes.js';
import { namedChildren } from '../stable-ids/normalize.js';
import type { StableDecl, StableIdFile } from '../stable-ids/types.js';
import type { CircleIR } from '../types/index.js';
import { buildNavigationIndex, type IndexedTarget } from './navigation-index.js';
import { DEFAULT_JAVA_ENTRY_TABLES, type JavaEntryTables } from './java-entry-tables.js';
import type { EntryCertainty, EntryKind } from './ts-entry-tables.js';
import type { CallEdge, CallEdgeSite, ReferenceEdge, TsEntry, UnresolvedCall, UnresolvedRegistration } from './ts-call-edges.js';
import { joinRoutePath } from './ts-call-edges.js';

export const JAVA_GRAPH_SCHEME = 'java-graph@0.1' as const;

export interface JavaSourceFile {
  /** Repository-relative path, `/`-separated. */
  path: string;
  code: string;
  /** The file's IR from `analyze(code, path, 'java', { navigationTypes: true })`; computed when absent. */
  ir?: CircleIR;
}

export interface JavaGraphOptions {
  /** `META-INF/services/<interface>` files: each listed class is a `reflection` entry. */
  serviceFiles?: readonly { path: string; text: string }[];
  /** Files run as programs, in addition to `main` methods. */
  mainFiles?: readonly string[];
  entryTables?: JavaEntryTables;
}

export interface JavaGraph {
  scheme: typeof JAVA_GRAPH_SCHEME;
  ids: 'ids@0.1';
  files: StableIdFile[];
  edges: CallEdge[];
  unresolved: UnresolvedCall[];
  references: ReferenceEdge[];
  loads: { from: string; to: string }[];
  entryScheme: 'entry-index@0.1';
  entries: TsEntry[];
  unresolvedRegistrations: UnresolvedRegistration[];
  partial: string[];
  typeOnly: string[];
  /** Call sites from the navigation index; equals the distinct sites over `edges` and `unresolved`. */
  sites: number;
}

// ---------------------------------------------------------------------------
// Annotations

interface Annotation {
  name: string;
  /** The package the annotation resolves to, `null` when the file gives no way to tell. */
  pkg: string | null;
  /** Wildcard-imported packages that could hold it. */
  wildcards: string[];
  args: Map<string, Node>;
}

interface Imports {
  pkg: string;
  explicit: Map<string, string>;
  wildcards: string[];
}

function importsOf(root: Node): Imports {
  const out: Imports = { pkg: '', explicit: new Map(), wildcards: [] };
  for (const c of namedChildren(root)) {
    if (c.type === 'package_declaration') {
      out.pkg = namedChildren(c).find(x => x.type === 'scoped_identifier' || x.type === 'identifier')?.text ?? '';
    } else if (c.type === 'import_declaration') {
      const text = c.text.replace(/^import\s+/, '').replace(/;$/, '').replace(/\s+/g, '');
      if (text.startsWith('static')) continue;
      if (text.endsWith('.*')) out.wildcards.push(text.slice(0, -2));
      else out.explicit.set(text.slice(text.lastIndexOf('.') + 1), text.slice(0, text.lastIndexOf('.')));
    }
  }
  return out;
}

function annotationsOf(node: Node, imports: Imports): Annotation[] {
  const mods = namedChildren(node).find(c => c.type === 'modifiers');
  const out: Annotation[] = [];
  for (const a of mods ? namedChildren(mods) : []) {
    if (a.type !== 'annotation' && a.type !== 'marker_annotation') continue;
    const nameNode = a.childForFieldName('name');
    if (!nameNode) continue;
    const written = nameNode.text;
    const dot = written.lastIndexOf('.');
    const name = dot >= 0 ? written.slice(dot + 1) : written;
    const pkg = dot >= 0 ? written.slice(0, dot) : imports.explicit.get(name) ?? null;
    const args = new Map<string, Node>();
    const list = a.childForFieldName('arguments');
    for (const arg of list ? namedChildren(list) : []) {
      if (arg.type === 'element_value_pair') {
        const k = arg.childForFieldName('key')?.text;
        const v = arg.childForFieldName('value');
        if (k && v) args.set(k, v);
      } else args.set('value', arg);
    }
    out.push({ name, pkg, wildcards: pkg === null ? imports.wildcards : [], args });
  }
  return out;
}

/** How sure the annotation is the one a table row names. */
function certaintyOf(a: Annotation, packages: readonly string[]): EntryCertainty | null {
  if (a.pkg !== null) return packages.includes(a.pkg) ? 'declared' : null;
  if (a.wildcards.some(w => packages.includes(w))) return 'declared';
  return 'inferred';
}

function stringsOf(node: Node | undefined): string[] {
  if (!node) return [];
  if (node.type === 'string_literal') return [namedChildren(node).map(c => c.text).join('')];
  if (node.type === 'element_value_array_initializer') return namedChildren(node).flatMap(c => stringsOf(c));
  return [];
}

function namesOf(node: Node | undefined): string[] {
  if (!node) return [];
  if (node.type === 'element_value_array_initializer') return namedChildren(node).flatMap(c => namesOf(c));
  return [node.text.slice(node.text.lastIndexOf('.') + 1)];
}

function pathsOf(a: Annotation | undefined, keys: readonly string[] = ['value', 'path']): string[] {
  if (!a) return [''];
  for (const k of keys) {
    const v = stringsOf(a.args.get(k));
    if (v.length > 0) return v;
  }
  return [''];
}

// ---------------------------------------------------------------------------

interface FileCtx {
  path: string;
  tree: Tree;
  ids: StableIdFile;
  imports: Imports;
  locate: (line: number, column?: number) => StableDecl | null;
  /** Declarations by `line:name` (start line of their node). */
  byLine: Map<string, StableDecl[]>;
}

function declAt(ctx: FileCtx, node: Node, kind: StableDecl['kind']): StableDecl | undefined {
  return (ctx.byLine.get(String(node.startPosition.row + 1)) ?? []).find(d => d.kind === kind && d.start_column === node.startPosition.column);
}

class JavaGraphBuilder {
  readonly entries: TsEntry[] = [];
  readonly references: ReferenceEdge[] = [];
  readonly unresolved: UnresolvedCall[] = [];
  readonly unresolvedRegistrations: UnresolvedRegistration[] = [];
  readonly typeOnly = new Set<string>();
  private readonly typesBySimple = new Map<string, StableDecl[]>();
  private readonly typesByQname = new Map<string, StableDecl>();

  constructor(private readonly files: FileCtx[], private readonly tables: JavaEntryTables) {
    for (const f of files) {
      for (const d of f.ids.decls) {
        if (d.kind !== 'type' || d.flags.includes('unstable:anonymous')) continue;
        const list = this.typesBySimple.get(d.name) ?? [];
        list.push(d);
        this.typesBySimple.set(d.name, list);
        this.typesByQname.set(d.qualified_name, d);
      }
    }
  }

  private entry(d: StableDecl, kind: EntryKind, certainty: EntryCertainty, file: string, evidence: string, extra: Partial<TsEntry> = {}): void {
    this.entries.push({ id: d.id, kind, certainty, file, line: d.start_line, evidence, ...extra });
  }

  private members(type: StableDecl, ctx: FileCtx): StableDecl[] {
    return ctx.ids.decls.filter(d => d.parent === type.id);
  }

  scan(ctx: FileCtx): void {
    const isTestFile = this.tables.testFile.test(ctx.path);
    if (isTestFile) this.entry(ctx.ids.decls[0], 'test', 'conventional', ctx.path, 'test source file');
    const visit = (node: Node): void => {
      const t = node.type;
      if (t === 'class_declaration' || t === 'interface_declaration' || t === 'enum_declaration' || t === 'record_declaration' || t === 'annotation_type_declaration') {
        this.typeDeclaration(ctx, node);
      } else if (t === 'method_reference') {
        this.methodReference(ctx, node);
      } else if (t === 'method_invocation') {
        this.forName(ctx, node);
      }
      for (const c of namedChildren(node)) visit(c);
    };
    visit(ctx.tree.rootNode);
  }

  private typeDeclaration(ctx: FileCtx, node: Node): void {
    const type = declAt(ctx, node, 'type');
    if (!type) return;
    if (node.type === 'interface_declaration' || node.type === 'annotation_type_declaration') this.typeOnly.add(type.id);
    const classAnns = annotationsOf(node, ctx.imports);
    // Class-level entries (beans).
    for (const row of this.tables.annotations) {
      if (row.on !== 'class') continue;
      for (const a of classAnns) {
        if (!row.names.includes(a.name)) continue;
        const c = certaintyOf(a, row.packages);
        if (!c) continue;
        const ctors = this.members(type, ctx).filter(d => d.kind === 'method' && d.name === 'constructor');
        for (const target of ctors.length > 0 ? ctors : [type]) this.entry(target, row.kind, c, ctx.path, `@${a.name}`, { framework: a.pkg ?? row.packages[0] });
      }
    }
    // Servlets and filters, by supertype.
    const supers = [
      node.childForFieldName('superclass'),
      node.childForFieldName('interfaces'),
    ].flatMap(n => (n ? n.text.replace(/^(extends|implements)\s+/, '').split(',') : [])).map(s => s.replace(/<.*$/s, '').trim());
    const servlets = this.tables.servlets.filter(row => supers.some(s => {
      const simple = s.slice(s.lastIndexOf('.') + 1);
      if (simple !== row.supertype) return false;
      const pkg = s.includes('.') ? s.slice(0, s.lastIndexOf('.')) : ctx.imports.explicit.get(simple) ?? null;
      return pkg === null ? ctx.imports.wildcards.some(w => row.packages.includes(w)) : row.packages.includes(pkg);
    }));
    const body = node.childForFieldName('body');
    const methodNodes = body ? namedChildren(body).filter(m => m.type === 'method_declaration' || m.type === 'annotation_type_element_declaration') : [];
    for (const row of servlets) {
      const ann = classAnns.find(a => a.name === row.pathAnnotation);
      const paths = ann ? pathsOf(ann, ['value', 'urlPatterns']) : [];
      for (const m of methodNodes) {
        const name = m.childForFieldName('name')?.text ?? '';
        const verb = row.methods[name];
        const d = declAt(ctx, m, 'method');
        if (!verb || !d) continue;
        if (verb === 'lifecycle') {
          this.entry(d, 'lifecycle', 'declared', ctx.path, `${row.supertype}.${name}`, { framework: row.framework });
          continue;
        }
        for (const p of paths.length > 0 ? paths : [undefined]) {
          const extra: Partial<TsEntry> = { framework: row.framework, method: verb };
          if (p !== undefined) extra.path = joinRoutePath([p]);
          if (row.surface) extra.surface = row.surface;
          this.entry(d, 'route', 'declared', ctx.path, `${row.supertype}.${name}`, extra);
        }
      }
    }
    // Method-level entries.
    for (const m of methodNodes) {
      const d = declAt(ctx, m, 'method');
      if (!d) continue;
      if (!m.childForFieldName('body')) this.typeOnly.add(d.id);
      if (node.type === 'annotation_type_declaration') this.typeOnly.add(d.id);
      const anns = annotationsOf(m, ctx.imports);
      this.routes(ctx, d, anns, classAnns);
      for (const row of this.tables.annotations) {
        if (row.on !== 'method') continue;
        for (const a of anns) {
          if (!row.names.includes(a.name)) continue;
          const c = certaintyOf(a, row.packages);
          if (c) this.entry(d, row.kind, c, ctx.path, `@${a.name}`, { framework: a.pkg ?? row.packages[0] });
        }
      }
      if (this.isMain(m)) this.entry(d, 'main', 'declared', ctx.path, 'public static void main(String[])');
    }
  }

  private isMain(m: Node): boolean {
    if (m.childForFieldName('name')?.text !== 'main') return false;
    const mods = namedChildren(m).find(c => c.type === 'modifiers')?.text ?? '';
    if (!/\bstatic\b/.test(mods) || !/\bpublic\b/.test(mods) || m.childForFieldName('type')?.text !== 'void') return false;
    const params = m.childForFieldName('parameters');
    const ps = params ? namedChildren(params) : [];
    return ps.length === 1 && /^(?:final\s+)?(?:java\.lang\.)?String\s*(?:\[\s*\]|\.\.\.)/.test(ps[0].text.replace(/@\w+\s*/g, ''));
  }

  private routes(ctx: FileCtx, d: StableDecl, anns: Annotation[], classAnns: Annotation[]): void {
    for (const row of this.tables.routes) {
      for (const a of anns) {
        if (!(a.name in row.verbs)) continue;
        const c = certaintyOf(a, row.packages);
        if (!c) continue;
        let methods: string[];
        const verb = row.verbs[a.name];
        if (verb === null) {
          methods = namesOf(a.args.get('method'));
          if (methods.length === 0) methods = ['ANY'];
        } else methods = [verb];
        // JAX-RS carries the path on a separate annotation; Spring on the verb annotation.
        const own = verb !== null && row.pathAnnotation && !a.args.size ? anns.find(x => x.name === row.pathAnnotation) : a;
        const ownPaths = own === a ? pathsOf(a) : own ? pathsOf(own) : [''];
        const prefixAnn = row.pathAnnotation ? classAnns.find(x => x.name === row.pathAnnotation) : undefined;
        const prefixes = pathsOf(prefixAnn);
        for (const prefix of prefixes) {
          for (const p of ownPaths) {
            for (const method of methods) {
              this.entry(d, 'route', c, ctx.path, `@${a.name}`, { framework: row.framework, method: method.toUpperCase(), path: joinRoutePath([prefix, p]) });
            }
          }
        }
      }
    }
  }

  private methodReference(ctx: FileCtx, node: Node): void {
    const parts = namedChildren(node);
    const target = parts[0];
    const last = parts[parts.length - 1];
    const isNew = node.text.trimEnd().endsWith('::new');
    const name = isNew ? 'constructor' : last?.text ?? '';
    const site: CallEdgeSite = { file: ctx.path, line: node.startPosition.row + 1, col: node.startPosition.column };
    const from = (ctx.locate(site.line, site.col) ?? ctx.ids.decls[0]).id;
    let types: StableDecl[] = [];
    if (target?.type === 'this' || target?.type === 'super') {
      // The enclosing class's own methods (an inherited one is reached through the call graph's types).
      let enclosing = ctx.locate(site.line, site.col);
      while (enclosing && enclosing.kind !== 'type') enclosing = ctx.ids.decls.find(d => d.id === enclosing?.parent) ?? null;
      if (enclosing) types = [enclosing];
    } else if (target && (target.type === 'identifier' || target.type === 'type_identifier' || target.type === 'scoped_type_identifier' || target.type === 'generic_type')) {
      const simple = target.text.replace(/<.*$/s, '').split('.').pop() ?? '';
      const fqnPkg = ctx.imports.explicit.get(simple);
      const all = this.typesBySimple.get(simple) ?? [];
      const exact = fqnPkg ? all.filter(t => t.qualified_name === `${fqnPkg}:${simple}`) : all.filter(t => t.qualified_name.startsWith(`${ctx.imports.pkg || '<default>'}:`));
      types = exact.length > 0 ? exact : all;
    }
    const targets = types.flatMap(t => this.files.flatMap(f => f.ids.decls.filter(d => d.parent === t.id && d.kind === 'method' && d.name === name)));
    if (isNew && targets.length === 0) targets.push(...types);
    if (targets.length === 0) {
      this.unresolved.push({ from, methodName: name, site, reason: 'dynamic', evidence: 'method reference not tied to a declaration' });
      return;
    }
    for (const d of targets) if (d.id !== from) this.references.push({ from, to: d.id, site });
  }

  private forName(ctx: FileCtx, node: Node): void {
    if (node.childForFieldName('name')?.text !== 'forName' || node.childForFieldName('object')?.text.replace(/^java\.lang\./, '') !== 'Class') return;
    const args = node.childForFieldName('arguments');
    const first = args ? namedChildren(args)[0] : undefined;
    const site: CallEdgeSite = { file: ctx.path, line: node.startPosition.row + 1, col: node.startPosition.column };
    if (first?.type !== 'string_literal') {
      this.unresolvedRegistrations.push({ site, reason: 'handler-unresolved', evidence: 'Class.forName with a computed name' });
      return;
    }
    this.reflect(stringsOf(first)[0] ?? '', ctx.path, 'Class.forName');
  }

  reflect(fqn: string, file: string, evidence: string): void {
    const clean = fqn.trim().replace(/\$/g, '.');
    // `a.b.Outer.Inner`: try each split point between package and type path.
    const segs = clean.split('.');
    for (let i = segs.length - 1; i >= 0; i--) {
      const t = this.typesByQname.get(`${segs.slice(0, i).join('.') || '<default>'}:${segs.slice(i).join('.')}`);
      if (t) {
        this.entry(t, 'reflection', 'declared', file, evidence);
        return;
      }
    }
  }
}

/** Java graph facts for a set of files. Deterministic: the same files give the same graph. */
export async function buildJavaGraph(files: readonly JavaSourceFile[], options: JavaGraphOptions = {}): Promise<JavaGraph> {
  const tables = options.entryTables ?? DEFAULT_JAVA_ENTRY_TABLES;
  const sorted = [...files].filter(f => f.path.endsWith('.java')).sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const ctxs: FileCtx[] = [];
  const irs: { path: string; ir: CircleIR; code: string }[] = [];
  const trees: Tree[] = [];
  try {
    for (const f of sorted) {
      const tree = await parse(f.code, 'java');
      trees.push(tree);
      const ids = deriveJavaIds(tree, f.path);
      const byLine = new Map<string, StableDecl[]>();
      for (const d of ids.decls) {
        const list = byLine.get(String(d.start_line)) ?? [];
        list.push(d);
        byLine.set(String(d.start_line), list);
      }
      ctxs.push({ path: f.path, tree, ids, imports: importsOf(tree.rootNode), locate: declLocator(ids), byLine });
      irs.push({ path: f.path, code: f.code, ir: f.ir ?? await analyze(f.code, f.path, 'java', { navigationTypes: true }) });
    }
    const b = new JavaGraphBuilder(ctxs, tables);
    for (const ctx of ctxs) b.scan(ctx);
    for (const s of options.serviceFiles ?? []) {
      for (const line of s.text.split('\n')) {
        const fqn = line.replace(/#.*$/, '').trim();
        if (fqn) b.reflect(fqn, s.path, 'META-INF/services');
      }
    }
    for (const m of options.mainFiles ?? []) {
      const ctx = ctxs.find(c => c.path === m);
      if (ctx) b.entries.push({ id: ctx.ids.decls[0].id, kind: 'main', certainty: 'declared', file: ctx.path, line: 1, evidence: 'program file given by the caller' });
    }

    // Call edges from the navigation index, keyed to declaration ids.
    const index = buildNavigationIndex(irs.map(f => ({ path: f.path, language: 'java' as const, ir: f.ir, source: f.code })));
    const byPath = new Map(ctxs.map(c => [c.path, c]));
    const keyOf = (t: IndexedTarget): StableDecl | undefined => {
      const ctx = byPath.get(t.file);
      const at = ctx?.byLine.get(String(t.line)) ?? [];
      if (t.type) return at.find(d => d.kind === 'type' && d.name === t.name);
      const name = t.name === '<init>' ? 'constructor' : t.name;
      return at.find(d => d.kind === 'method' && d.name === name);
    };
    const edges: CallEdge[] = [];
    const sites = index.callSites();
    for (const s of sites) {
      const ctx = byPath.get(s.site.file);
      if (!ctx) continue;
      const site: CallEdgeSite = s.site;
      const from = (ctx.locate(site.line, site.col) ?? ctx.ids.decls[0]).id;
      if (s.kind === 'unresolved') {
        b.unresolved.push({ from, methodName: s.methodName, site, reason: s.reason, evidence: 'navigation index', ...(s.receiver ? { receiver: s.receiver } : {}) });
        continue;
      }
      const declaring = keyOf(s.declaring);
      const targets = s.tier === 'polymorphic'
        ? [...new Map([...(declaring ? [declaring] : []), ...s.bodies.map(keyOf).filter((d): d is StableDecl => d !== undefined)].map(d => [d.id, d])).values()]
        : declaring ? [declaring] : [];
      if (targets.length === 0) {
        b.unresolved.push({ from, methodName: s.methodName, site, reason: 'unknown', evidence: `${s.declaring.fqn} not tied to a declaration` });
        continue;
      }
      for (const t of targets) {
        const e: CallEdge = { from, to: t.id, tier: s.tier, methodName: s.methodName, site, evidence: 'navigation index' };
        if (s.tier === 'polymorphic' && declaring && t.id !== declaring.id) e.via = declaring.id;
        edges.push(e);
      }
    }

    // A member initializes its class.
    const loads: { from: string; to: string }[] = [];
    for (const ctx of ctxs) {
      const types = new Set(ctx.ids.decls.filter(d => d.kind === 'type').map(d => d.id));
      for (const d of ctx.ids.decls) if (d.parent !== null && types.has(d.parent) && d.kind !== 'type') loads.push({ from: d.id, to: d.parent });
    }

    const cmp = (a: string, c: string): number => (a < c ? -1 : a > c ? 1 : 0);
    const bySite = (x: { site: CallEdgeSite }, y: { site: CallEdgeSite }): number =>
      cmp(x.site.file, y.site.file) || x.site.line - y.site.line || x.site.col - y.site.col;
    const seen = new Set<string>();
    const entries = [...b.entries]
      .sort((x, y) => cmp(x.file, y.file) || x.line - y.line || cmp(x.id, y.id) || cmp(x.kind, y.kind) || cmp(x.path ?? '', y.path ?? '') || cmp(x.method ?? '', y.method ?? ''))
      .filter(e => {
        const k = `${e.id}|${e.kind}|${e.method ?? ''}|${e.path ?? ''}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });
    return {
      scheme: JAVA_GRAPH_SCHEME,
      ids: 'ids@0.1',
      files: ctxs.map(c => c.ids),
      edges: edges.sort((x, y) => bySite(x, y) || cmp(x.to, y.to)),
      unresolved: [...b.unresolved].sort(bySite),
      references: [...b.references].sort((x, y) => bySite(x, y) || cmp(x.to, y.to)),
      loads,
      entryScheme: 'entry-index@0.1',
      entries,
      unresolvedRegistrations: [...b.unresolvedRegistrations].sort(bySite),
      partial: ctxs.filter(c => c.ids.partial).map(c => c.path),
      typeOnly: [...b.typeOnly].sort(),
      sites: sites.filter(s => byPath.has(s.site.file)).length,
    };
  } finally {
    for (const t of trees) disposeTree(t);
  }
}
