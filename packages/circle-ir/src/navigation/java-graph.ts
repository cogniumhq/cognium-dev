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
 *   `Class.forName` literals and `META-INF/services` files; and the classes
 *   and methods registering files name (OSGi DS component descriptions,
 *   `MANIFEST.MF`, Eclipse `plugin.xml`, servlet `web.xml`; see
 *   `java-registrations.ts`).
 * - **typeOnly**: interfaces, annotation types and body-less methods.
 *
 * Library code: no file access; the caller passes the sources (and may pass
 * each file's IR, which must come from `analyze` with `navigationTypes`) and
 * any registering files as text.
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
import { scanRegistrations, type RegistrationFile, type RegistrationScan } from './java-registrations.js';
import type { EntryCertainty, EntryKind } from './ts-entry-tables.js';
import type { CallEdge, CallEdgeSite, ReferenceEdge, TsEntry, UnresolvedCall, UnresolvedRegistration } from './ts-call-edges.js';
import { joinRoutePath } from './ts-call-edges.js';
import { facts2ToArrow, factsToArrow, type Facts2Arrow, type FactsArrow, type FactsArrowOptions } from '../facts/arrow.js';
import { javaGraphFactSet, type JavaImportRow } from '../facts/java-facts.js';
import { javaGraphFact2Set, markDeclaringEdge } from '../facts/facts2.js';

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
  /**
   * Registering files, as text: OSGi DS component descriptions
   * (`OSGI-INF/*.xml`), `META-INF/MANIFEST.MF`, Eclipse `plugin.xml` /
   * `fragment.xml` and servlet `web.xml` / `web-fragment.xml`, recognised by
   * path (`registrationFileKind`); other files are ignored. Each class they
   * name is an entry on its type (`osgi-ds`, `lifecycle`, `extension-point`,
   * `route`), each method on that method (found in the class or an in-tree
   * superclass); a name the tree does not declare is a `manifest-unresolved`
   * registration.
   */
  registrationFiles?: readonly RegistrationFile[];
  /**
   * The public top-level types of every `Export-Package` package in the
   * registering files' manifests are `export` entries: a library's surface,
   * so roots only in a library's reach. Off by default.
   */
  exportedPackages?: boolean;
  entryTables?: JavaEntryTables;
  /**
   * `'arrow'`: also emit the `facts@2` relations (graph-store plan T2/T5a;
   * `facts@1` under `factsScheme: 'facts@1'`) as
   * Arrow IPC file bytes in `JavaGraph.facts`, derived from the finished
   * graph as a post-pass (relations are sets: exact duplicates of the graph's
   * rows collapse, counted in the manifest); `flow` comes from each file's
   * DFG on fixed-width `ids@0.1` node ids. Off by default, and when off the graph is
   * exactly what it was: no `facts` key, same JSON. Needs the optional
   * dependency `apache-arrow`.
   */
  emitFacts?: 'arrow';
  /**
   * The fact schema `emitFacts` writes: `facts@2` (the default since
   * graph-store T5a.1b: stable file keys, site lines relative to their
   * declaration, `decl_pos`, `ref`, `registration`, `parse_error`; see
   * `schemas/facts@2.json`) or `facts@1`. Only read with `emitFacts`.
   */
  factsScheme?: 'facts@1' | 'facts@2';
  /** Metadata written with the facts (`engine`, `parser`); only read with `emitFacts`. */
  facts?: FactsArrowOptions;
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
  /** The fact relations as Arrow IPC bytes (`facts@2`, or `facts@1` under `factsScheme`); present only under `emitFacts: 'arrow'`. */
  facts?: FactsArrow | Facts2Arrow;
}

/** Every `import` of a file, as the `imports` relation records it (static imports included). */
function importRows(root: Node): JavaImportRow[] {
  const out: JavaImportRow[] = [];
  for (const c of namedChildren(root)) {
    if (c.type !== 'import_declaration') continue;
    const text = c.text.replace(/^import\s+/, '').replace(/;\s*$/, '').replace(/^static\s+/, '').replace(/\s+/g, '');
    if (text.endsWith('.*')) out.push({ target: text.slice(0, -2), wildcard: true });
    else out.push({ target: text, wildcard: false });
  }
  return out;
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
  /** Registrations with a `bound`, filled with `boundTypes` once the type hierarchy is known (#1092). */
  readonly pendingBounds: UnresolvedRegistration[] = [];
  readonly typeOnly = new Set<string>();
  private readonly typesBySimple = new Map<string, StableDecl[]>();
  private readonly typesByQname = new Map<string, StableDecl>();
  /** A class's superclass as written, with the file that wrote it (registered members may be inherited). */
  private readonly superclassOf = new Map<string, { written: string; ctx: FileCtx }>();
  /** Public top-level types by package (`Export-Package`). */
  private readonly publicTypesByPkg = new Map<string, StableDecl[]>();
  /** Declared constructors with a `public` modifier. */
  private readonly publicCtors = new Set<string>();
  private childrenByParent: Map<string, StableDecl[]> | null = null;

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
    const superclass = node.childForFieldName('superclass');
    if (superclass) {
      const written = superclass.text.replace(/^extends\s+/, '').replace(/<.*$/s, '').replace(/\s+/g, '');
      if (written) this.superclassOf.set(type.id, { written, ctx });
    }
    if (node.parent?.type === 'program' && namedChildren(node).find(c => c.type === 'modifiers')?.children.some(c => c.type === 'public')) {
      const pkg = ctx.imports.pkg;
      const list = this.publicTypesByPkg.get(pkg) ?? [];
      list.push(type);
      this.publicTypesByPkg.set(pkg, list);
    }
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
    for (const c of body ? namedChildren(body) : []) {
      if (c.type !== 'constructor_declaration') continue;
      if (!namedChildren(c).find(x => x.type === 'modifiers')?.children.some(x => x.type === 'public')) continue;
      const d = declAt(ctx, c, 'method');
      if (d) this.publicCtors.add(d.id);
    }
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
    // #1093: `T[]::new` creates an array; it calls no declared constructor.
    if (isNew && target?.type === 'array_type') return;
    const name = isNew ? 'constructor' : last?.text ?? '';
    const site: CallEdgeSite = { file: ctx.path, line: node.startPosition.row + 1, col: node.startPosition.column };
    const from = (ctx.locate(site.line, site.col) ?? ctx.ids.decls[0]).id;
    let types: StableDecl[] = [];
    let typeName: string | null = null;
    if (target?.type === 'this' || target?.type === 'super') {
      // The enclosing class's own methods (an inherited one is reached through the call graph's types).
      let enclosing = ctx.locate(site.line, site.col);
      while (enclosing && enclosing.kind !== 'type') enclosing = ctx.ids.decls.find(d => d.id === enclosing?.parent) ?? null;
      if (enclosing) types = [enclosing];
    } else if (target && (target.type === 'identifier' || target.type === 'type_identifier' || target.type === 'scoped_type_identifier' || target.type === 'generic_type'
      // #1093: a qualified type before `::new` (`java.util.LinkedList::new`) parses as an expression
      || (isNew && (target.type === 'field_access' || target.type === 'scoped_identifier')))) {
      const written = target.text.replace(/<.*$/s, '');
      const simple = written.split('.').pop() ?? '';
      const fqnPkg = ctx.imports.explicit.get(simple);
      typeName = written.includes('.') ? written : fqnPkg ? `${fqnPkg}.${simple}` : simple;
      const all = this.typesBySimple.get(simple) ?? [];
      const exact = fqnPkg ? all.filter(t => t.qualified_name === `${fqnPkg}:${simple}`) : all.filter(t => t.qualified_name.startsWith(`${ctx.imports.pkg || '<default>'}:`));
      types = exact.length > 0 ? exact : all;
    }
    const targets = types.flatMap(t => this.files.flatMap(f => f.ids.decls.filter(d => d.parent === t.id && d.kind === 'method' && d.name === name)));
    if (isNew && targets.length === 0) targets.push(...types);
    if (targets.length === 0) {
      // #1093: `Ext::new` on a type that is not declared in the tree is a call into a
      // library, like `new Ext()`: external, naming its receiver, not every constructor.
      if (isNew && types.length === 0 && typeName) {
        this.unresolved.push({ from, methodName: name, site, reason: 'external', evidence: 'constructor reference to a type outside the tree', receiver: typeName });
        return;
      }
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
    if (first?.type === 'string_literal') {
      this.reflect(stringsOf(first)[0] ?? '', ctx.path, 'Class.forName');
      return;
    }
    // #1092: a local (or static final field) whose every assignment is a string literal
    // is the literal case: each name is a reflection entry, a name outside the tree nothing.
    const method = enclosingBody(node);
    if (first?.type === 'identifier' && method) {
      const names = constantStrings(method, first.text, node);
      if (names) {
        for (const n of names) this.reflect(n, ctx.path, 'Class.forName (local constant)');
        return;
      }
    }
    const from = (ctx.locate(site.line, site.col) ?? ctx.ids.decls[0]).id;
    const bound = method ? boundTypeNames(method.text) : [];
    const reg: UnresolvedRegistration = { site, reason: 'handler-unresolved', evidence: 'Class.forName with a computed name', from };
    if (bound.length > 0) {
      reg.bound = bound.map(b => resolveTypeName(b, ctx));
      this.pendingBounds.push(reg);
    }
    this.unresolvedRegistrations.push(reg);
  }

  /** `instantiated`: the loader also constructs the class (`ServiceLoader`), not only loads it (`Class.forName`). */
  reflect(fqn: string, file: string, evidence: string, instantiated = false): void {
    const t = this.typeByName(fqn);
    if (!t) return;
    const constructors = instantiated ? this.instantiationConstructors(t) : [];
    this.entry(t, 'reflection', 'declared', file, evidence, constructors.length > 0 ? { constructors } : {});
  }

  /**
   * The constructors a runtime that instantiates the class by reflection runs:
   * its public no-arg constructor; when it declares none, its public
   * constructors (constructor injection). Empty when it declares no
   * constructor at all (the implicit one has no declaration).
   */
  private instantiationConstructors(type: StableDecl): string[] {
    const pub = this.childrenOf(type.id).filter(d => d.kind === 'method' && d.name === 'constructor' && this.publicCtors.has(d.id));
    const noArg = pub.filter(d => d.signature === '()');
    return (noArg.length > 0 ? noArg : pub).map(d => d.id);
  }

  /** The tree's type for a binary (`a.B$C`) or canonical (`a.B.C`) name. */
  private typeByName(fqn: string): StableDecl | undefined {
    const clean = fqn.trim().replace(/\$/g, '.');
    // `a.b.Outer.Inner`: try each split point between package and type path.
    const segs = clean.split('.');
    for (let i = segs.length - 1; i >= 0; i--) {
      const t = this.typesByQname.get(`${segs.slice(0, i).join('.') || '<default>'}:${segs.slice(i).join('.')}`);
      if (t) return t;
    }
    return undefined;
  }

  private childrenOf(id: string): StableDecl[] {
    if (!this.childrenByParent) {
      this.childrenByParent = new Map();
      for (const f of this.files) {
        for (const d of f.ids.decls) {
          if (d.parent === null) continue;
          const list = this.childrenByParent.get(d.parent) ?? [];
          list.push(d);
          this.childrenByParent.set(d.parent, list);
        }
      }
    }
    return this.childrenByParent.get(id) ?? [];
  }

  /** The in-tree superclass of a class, from its `extends` clause, the file's imports and its package. */
  private superclass(type: StableDecl): StableDecl | undefined {
    const s = this.superclassOf.get(type.id);
    if (!s) return undefined;
    const { written, ctx } = s;
    const pkg = ctx.imports.pkg || '<default>';
    const first = written.split('.')[0];
    const imported = ctx.imports.explicit.get(first);
    // `import p.Outer;` + `extends Outer.Inner`, or `import p.Outer.Inner;` + `extends Inner`.
    if (imported) return this.typeByName(`${imported}.${written}`);
    // A type nested in an enclosing type or the package, nearest first.
    const path = type.qualified_name.slice(type.qualified_name.indexOf(':') + 1).split('.');
    for (let i = path.length - 1; i >= 0; i--) {
      const t = this.typesByQname.get(`${pkg}:${[...path.slice(0, i), written].join('.')}`);
      if (t) return t;
    }
    if (written.includes('.')) {
      const t = this.typeByName(written);
      if (t) return t;
    }
    for (const w of ctx.imports.wildcards) {
      const t = this.typesByQname.get(`${w}:${written}`);
      if (t) return t;
    }
    return undefined;
  }

  /** The methods named `name` the type declares, else those of its nearest in-tree superclass that does. */
  private methodsNamed(type: StableDecl, name: string): StableDecl[] {
    const seen = new Set<string>();
    for (let t: StableDecl | undefined = type; t && !seen.has(t.id); t = this.superclass(t)) {
      seen.add(t.id);
      const ms = this.childrenOf(t.id).filter(d => d.kind === 'method' && d.name === name);
      if (ms.length > 0) return ms;
    }
    return [];
  }

  /**
   * Entries for what registering files name: a class's type, a member's
   * method. A name the tree does not declare is a `manifest-unresolved`
   * registration (an optional member, the DS default lifecycle names, is
   * nothing). Exported packages' public types only with `exportedPackages`.
   */
  register(scan: RegistrationScan, exportedPackages: boolean): void {
    for (const r of scan.registrations) {
      const site: CallEdgeSite = { file: r.file, line: r.line, col: r.col };
      const type = this.typeByName(r.className);
      const targets = !type ? [] : r.member ? this.methodsNamed(type, r.member) : [type];
      if (targets.length === 0) {
        if (!r.optional) {
          const what = type ? `${r.className}#${r.member ?? ''} is not a method of the class or an in-tree superclass` : `${r.className} is not a type in the tree`;
          this.unresolvedRegistrations.push({ site, reason: 'manifest-unresolved', evidence: `${r.source}: ${what}` });
        }
        continue;
      }
      const extra: Partial<TsEntry> = { framework: r.framework };
      if (r.method) extra.method = r.method;
      if (r.path !== undefined) extra.path = r.path;
      if (r.surface) extra.surface = r.surface;
      // A class a registering file names is instantiated by its runtime: the entry carries the constructors that runs.
      if (!r.member && type) {
        const constructors = this.instantiationConstructors(type);
        if (constructors.length > 0) extra.constructors = constructors;
      }
      for (const d of targets) this.entries.push({ id: d.id, kind: r.kind, certainty: r.certainty, file: r.file, line: r.line, evidence: r.source, ...extra });
    }
    if (!exportedPackages) return;
    for (const p of scan.exportedPackages) {
      const types = this.publicTypesByPkg.get(p.name) ?? [];
      if (types.length === 0) {
        this.unresolvedRegistrations.push({ site: { file: p.file, line: p.line, col: 0 }, reason: 'manifest-unresolved', evidence: `Export-Package: ${p.name} has no public type in the tree` });
      }
      for (const t of types) this.entries.push({ id: t.id, kind: 'export', certainty: 'declared', file: p.file, line: p.line, evidence: 'Export-Package', framework: 'osgi' });
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
        if (fqn) b.reflect(fqn, s.path, 'META-INF/services', true);
      }
    }
    for (const m of options.mainFiles ?? []) {
      const ctx = ctxs.find(c => c.path === m);
      if (ctx) b.entries.push({ id: ctx.ids.decls[0].id, kind: 'main', certainty: 'declared', file: ctx.path, line: 1, evidence: 'program file given by the caller' });
    }
    if (options.registrationFiles && options.registrationFiles.length > 0) {
      const regs = [...options.registrationFiles].sort((x, y) => (x.path < y.path ? -1 : x.path > y.path ? 1 : 0));
      b.register(scanRegistrations(regs), options.exportedPackages === true);
    }

    // Call edges from the navigation index, keyed to declaration ids.
    const index = buildNavigationIndex(irs.map(f => ({ path: f.path, language: 'java' as const, ir: f.ir, source: f.code })));
    // #1092: a bound names the in-tree types that are it or extend / implement it.
    if (b.pendingBounds.length > 0) {
      const typeIdByFqn = new Map<string, string>();
      for (const c of ctxs) for (const d of c.ids.decls) {
        if (d.kind !== 'type') continue;
        const [pkg, path] = d.qualified_name.split(':');
        typeIdByFqn.set(pkg && pkg !== '<default>' ? `${pkg}.${path}` : path, d.id);
      }
      const pkgByFile = new Map(ctxs.map(c => [c.path, c.imports.pkg]));
      for (const reg of b.pendingBounds) {
        const ids = new Set<string>();
        for (const name of reg.bound ?? []) {
          const pkg = pkgByFile.get(reg.site.file) ?? '';
          const cands = name.includes('.') ? [name] : [pkg ? `${pkg}.${name}` : name, `java.lang.${name}`, name];
          for (const c of cands) {
            for (const fqn of [c, ...index.subtypesOf(c)]) {
              const id = typeIdByFqn.get(fqn) ?? typeIdByFqn.get(fqn.replace(/\$/g, '.'));
              if (id) ids.add(id);
            }
          }
        }
        reg.boundTypes = [...ids].sort();
      }
    }
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
        if (s.tier === 'polymorphic' && declaring) {
          if (t.id !== declaring.id) e.via = declaring.id;
          else markDeclaringEdge(e);
        }
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
    const seen = new Map<string, TsEntry>();
    const entries = [...b.entries]
      .sort((x, y) => cmp(x.file, y.file) || x.line - y.line || cmp(x.id, y.id) || cmp(x.kind, y.kind) || cmp(x.path ?? '', y.path ?? '') || cmp(x.method ?? '', y.method ?? ''))
      .filter(e => {
        const k = `${e.id}|${e.kind}|${e.method ?? ''}|${e.path ?? ''}`;
        const kept = seen.get(k);
        if (kept) {
          // A duplicate that instantiates the class (a service file) keeps its constructors on the entry kept.
          if (e.constructors && !kept.constructors) kept.constructors = e.constructors;
          return false;
        }
        seen.set(k, e);
        return true;
      });
    const graph: JavaGraph = {
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
    if (options.emitFacts === 'arrow') {
      const inputs = sorted.map((f, i) => ({ path: f.path, code: f.code, imports: importRows(ctxs[i].tree.rootNode), dfg: irs[i].ir.dfg }));
      const scheme = options.factsScheme ?? 'facts@2';
      const factsOptions = { source: JAVA_GRAPH_SCHEME, ...options.facts };
      if (scheme === 'facts@2') graph.facts = await facts2ToArrow(javaGraphFact2Set(graph, inputs), factsOptions);
      else if (scheme === 'facts@1') graph.facts = await factsToArrow(javaGraphFactSet(graph, inputs), factsOptions);
      else throw new Error(`unknown fact scheme ${JSON.stringify(scheme)} (expected facts@1 or facts@2)`);
    }
    return graph;
  } finally {
    for (const t of trees) disposeTree(t);
  }
}

/** The method, constructor, initializer or lambda body enclosing `node` (#1092). */
function enclosingBody(node: Node): Node | null {
  let n: Node | null = node.parent;
  while (n && !['method_declaration', 'constructor_declaration', 'static_initializer', 'lambda_expression', 'class_body'].includes(n.type)) n = n.parent;
  return n && n.type !== 'class_body' ? n : null;
}

/** Whether `n` directly declares the local `name` (a `local_variable_declaration` child). */
function declaresLocal(n: Node, name: string): boolean {
  return namedChildren(n).some(c => c.type === 'local_variable_declaration'
    && namedChildren(c).some(d => d.type === 'variable_declarator' && d.childForFieldName('name')?.text === name));
}

/** The innermost node between `at` and `body` that declares the local `name`, if any. */
function declaringBlock(at: Node, body: Node, name: string): Node | null {
  for (let n: Node | null = at.parent; n && n !== body; n = n.parent) if (declaresLocal(n, name)) return n;
  return null;
}

/**
 * The string literals `name` can hold at a `Class.forName(name)` in `body` (#1092): every
 * local declaration and assignment of it in the body is a string literal, or it is a
 * `static final String` field of the enclosing class with a literal value. A `null`
 * value names no class (`Class.forName(null)` throws) and adds nothing. Null when any
 * assignment is not a literal, or nothing assigns it. Only the local in scope at `at` is
 * read: a same-named local declared in a sibling block is another variable.
 */
function constantStrings(body: Node, name: string, at: Node): string[] | null {
  const values: string[] = [];
  const scope = declaringBlock(at, body, name) ?? body;
  let other = false;
  const visit = (n: Node): void => {
    // another block declaring `name` holds a different variable (a sibling scope)
    if (n !== scope && declaresLocal(n, name)) return;
    if (n.type === 'variable_declarator' && n.childForFieldName('name')?.text === name) {
      const v = n.childForFieldName('value');
      if (v?.type === 'string_literal') values.push(...stringsOf(v)); else if (v && v.type !== 'null_literal') other = true;
    } else if (n.type === 'assignment_expression' && n.childForFieldName('left')?.text === name) {
      const v = n.childForFieldName('right');
      if (v?.type === 'string_literal') values.push(...stringsOf(v)); else if (v?.type !== 'null_literal') other = true;
    } else if ((n.type === 'formal_parameter' || n.type === 'catch_formal_parameter') && n.childForFieldName('name')?.text === name) {
      other = true;
    }
    for (const c of namedChildren(n)) visit(c);
  };
  visit(scope);
  if (other) return null;
  if (values.length > 0) return values;
  // a static final String field of the enclosing class
  let cls: Node | null = body.parent;
  while (cls && cls.type !== 'class_body') cls = cls.parent;
  for (const f of cls ? namedChildren(cls).filter(m => m.type === 'field_declaration') : []) {
    const mods = f.children.find(ch => ch.type === 'modifiers')?.text ?? '';
    if (!/\bstatic\b/.test(mods) || !/\bfinal\b/.test(mods)) continue;
    for (const d of namedChildren(f).filter(x => x.type === 'variable_declarator')) {
      if (d.childForFieldName('name')?.text !== name) continue;
      const v = d.childForFieldName('value');
      return v?.type === 'string_literal' ? stringsOf(v) : null;
    }
  }
  return null;
}

/** A type as written: a capitalised simple name, optionally package-qualified (`java.security.Provider`). */
const TYPE = String.raw`(?:[a-z_$][\w$]*\.)*[A-Z][\w$.]*`;
const CAST_NEW_INSTANCE = new RegExp(String.raw`\(\s*(${TYPE}(?:<[^()]*>)?)\s*\)\s*[\w$.\s]*?(?:\.\s*getDeclaredConstructor\s*\([^)]*\)|\.\s*getConstructor\s*\([^)]*\))?\s*\.\s*newInstance\s*\(`, 'g');
const CAST_FORNAME_NEW_INSTANCE = new RegExp(String.raw`\(\s*(${TYPE}(?:<[^()]*>)?)\s*\)\s*Class\s*\.\s*forName\s*\([^)]*\)\s*\.\s*(?:getDeclaredConstructor|getConstructor)\s*\([^)]*\)\s*\.\s*newInstance\s*\(`, 'g');
const INSTANCEOF = new RegExp(String.raw`\binstanceof\s+(${TYPE})`, 'g');

/**
 * The type a reflectively loaded class must be, from how the method uses it (#1092): a cast
 * of `newInstance()` (directly or through `getDeclaredConstructor` / `getConstructor`),
 * `asSubclass(T.class)`, `instanceof T` (also with a pattern variable), `T.class.isAssignableFrom(…)`,
 * or a `getSuperclass()` walk compared with `== T.class`, directly or through a variable the
 * walk assigns (`s = c.getSuperclass(); … if (s == T.class)`). Names as written, simple or package-qualified,
 * generics stripped.
 */
function boundTypeNames(text: string): string[] {
  const out = new Set<string>();
  const add = (t: string | undefined) => { const c = (t ?? '').replace(/<.*$/s, '').trim(); if (/^[A-Za-z_$][\w$.]*$/.test(c) && c !== 'Object' && !c.endsWith('.class')) out.add(c); };
  for (const m of text.matchAll(CAST_NEW_INSTANCE)) add(m[1]);
  for (const m of text.matchAll(CAST_FORNAME_NEW_INSTANCE)) add(m[1]);
  for (const m of text.matchAll(/\.\s*asSubclass\s*\(\s*([\w$.]+)\s*\.\s*class\s*\)/g)) add(m[1]);
  for (const m of text.matchAll(INSTANCEOF)) add(m[1]);
  for (const m of text.matchAll(/\b([\w$.]+)\s*\.\s*class\s*\.\s*isAssignableFrom\s*\(/g)) add(m[1]);
  for (const m of text.matchAll(/getSuperclass\s*\(\s*\)\s*==\s*([\w$.]+)\s*\.\s*class/g)) add(m[1]);
  // a walk through a variable: `s = c.getSuperclass(); while (s != null) { if (s == T.class) … }`
  for (const w of text.matchAll(/\b([A-Za-z_$][\w$]*)\s*=\s*[\w$.]+\s*\.\s*getSuperclass\s*\(\s*\)/g)) {
    const v = w[1].replace(/[$]/g, '\\$&');
    for (const m of text.matchAll(new RegExp(String.raw`\b${v}\s*==\s*([\w$.]+)\s*\.\s*class\b`, 'g'))) add(m[1]);
  }
  return [...out].sort();
}

/** A type name as written, qualified through the file's explicit imports when it is simple. */
function resolveTypeName(name: string, ctx: FileCtx): string {
  if (name.includes('.')) return name;
  return ctx.imports.explicit.get(name) ? `${ctx.imports.explicit.get(name)}.${name}` : name;
}

