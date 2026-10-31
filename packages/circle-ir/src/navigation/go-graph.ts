/**
 * Go graph facts keyed by stable ids (`go-graph@0.1`): the reach core's
 * input for Go.
 *
 * - **Declarations** from `deriveGoIds` (`ids@0.1`); a package is a directory.
 * - **Call edges**, resolved from the syntax tree:
 *   - `exact`: a function of the same package, `pkg.F` through an import of
 *     a project package, `recv.M` on the method's own receiver, `T.M` method
 *     expressions, and `T{}` / `&T{}` composite literals (a reference to `T`).
 *   - `inferred`: `x.M` on a value of unknown type reaches every project
 *     method named `M`, up to `maxInferred`; beyond it the site is unresolved.
 *   A target outside the project (the standard library, modules) is an
 *   unresolved `external` site, never dropped.
 * - **References**: a project function or method used as a value (a handler
 *   passed to a router, a callback).
 * - **Imports**: a file loads the project packages it imports; a package's
 *   files load each other.
 * - **Entries** (`entry-index@0.1`): `main` in package `main`, `init`,
 *   net/http (`HandleFunc`, `Handle`, Go 1.22 method patterns), gin, echo and
 *   chi routes with group and route prefixes composed, `_test.go` tests,
 *   benchmarks, examples and fuzz targets, and the exported API of packages
 *   the caller names as libraries.
 * - **typeOnly**: interface types.
 *
 * Library code: no file access; the caller passes the sources.
 */

import { disposeTree, parse, type Node } from '../core/parser.js';
import { deriveGoIds, goPackageDir, goReceiverType } from '../stable-ids/go.js';
import { declLocator } from '../stable-ids/nodes.js';
import { namedChildren } from '../stable-ids/normalize.js';
import type { StableDecl, StableIdFile } from '../stable-ids/types.js';
import type { EntryCertainty } from './ts-entry-tables.js';
import type {
  CallEdge,
  CallEdgeSite,
  ImportEdge,
  ReferenceEdge,
  TsEntry,
  UnresolvedCall,
  UnresolvedRegistration,
} from './ts-call-edges.js';
import { joinRoutePath } from './ts-call-edges.js';

export const GO_GRAPH_SCHEME = 'go-graph@0.1' as const;

export interface GoSourceFile {
  /** Repository-relative path, `/`-separated. */
  path: string;
  code: string;
}

export interface GoGraphOptions {
  /** The module path from `go.mod` (`example.com/app`); imports under it map to directories. Without it, imports map by directory suffix. */
  modulePath?: string;
  /** Package directories whose exported functions, types and methods are `export` entries (a library's API). */
  libraryPackages?: readonly string[];
  /** Most `inferred` edges one site may carry; beyond it the site is unresolved. Default 16. */
  maxInferred?: number;
}

export interface GoGraph {
  scheme: typeof GO_GRAPH_SCHEME;
  ids: 'ids@0.1';
  files: StableIdFile[];
  edges: CallEdge[];
  unresolved: UnresolvedCall[];
  references: ReferenceEdge[];
  imports: ImportEdge[];
  loads: { from: string; to: string }[];
  entryScheme: 'entry-index@0.1';
  entries: TsEntry[];
  unresolvedRegistrations: UnresolvedRegistration[];
  partial: string[];
  typeOnly: string[];
  /** Call sites walked; equals the distinct sites over `edges` and `unresolved`. */
  sites: number;
}

// ---------------------------------------------------------------------------
// Tables

/** Router packages: import path prefix → framework. */
const ROUTERS: Record<string, string> = {
  'net/http': 'net/http',
  'github.com/gin-gonic/gin': 'gin',
  'github.com/labstack/echo': 'echo',
  'github.com/go-chi/chi': 'chi',
  'github.com/gorilla/mux': 'gorilla',
};
const UPPER_VERBS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'Any', 'Match'];
const CHI_VERBS = ['Get', 'Post', 'Put', 'Patch', 'Delete', 'Head', 'Options', 'Connect', 'Trace', 'Method', 'MethodFunc', 'Handle', 'HandleFunc'];
const HTTP_FUNCS = ['HandleFunc', 'Handle'];
const BUILTINS = new Set(['append', 'cap', 'clear', 'close', 'complex', 'copy', 'delete', 'imag', 'len', 'make', 'max', 'min', 'new', 'panic', 'print', 'println', 'real', 'recover']);
const TEST_FUNC = /^(Test|Benchmark|Example|Fuzz)([A-Z_]|$)/;

// ---------------------------------------------------------------------------

interface FileCtx {
  path: string;
  pkg: string;
  pkgName: string;
  ids: StableIdFile;
  root: Node;
  /** Import name → import path. */
  imports: Map<string, string>;
  locate: (line: number, column?: number) => StableDecl | null;
}

interface PkgInfo {
  dir: string;
  files: FileCtx[];
  /** Package-level names: functions, types, vars, consts. */
  top: Map<string, StableDecl>;
  /** Type name → method name → decl. */
  methods: Map<string, Map<string, StableDecl>>;
  /** Interface name → its method names. */
  interfaces: Map<string, Set<string>>;
  /** Struct name → field name → the field's named type. */
  fields: Map<string, Map<string, TypeRef | null>>;
  /** Function or `Type.method` → its single named result type. */
  results: Map<string, TypeRef | null>;
}

/** A named type in a project package. */
interface TypeRef {
  pkg: string;
  name: string;
}

const stringValue = (n: Node | null | undefined): string | null => {
  if (!n) return null;
  if (n.type === 'interpreted_string_literal') return namedChildren(n).map(c => c.text).join('');
  if (n.type === 'raw_string_literal') return n.text.slice(1, -1);
  return null;
};

function walk(node: Node, visit: (n: Node) => boolean | void): void {
  if (visit(node) === false) return;
  for (const c of namedChildren(node)) walk(c, visit);
}

function importsOf(root: Node): Map<string, string> {
  const out = new Map<string, string>();
  for (const decl of namedChildren(root).filter(c => c.type === 'import_declaration')) {
    const specs = namedChildren(decl).flatMap(c => (c.type === 'import_spec_list' ? namedChildren(c) : [c])).filter(c => c.type === 'import_spec');
    for (const spec of specs) {
      const path = stringValue(spec.childForFieldName('path'));
      if (!path) continue;
      const alias = spec.childForFieldName('name')?.text;
      if (alias === '_') continue;
      // The package name is conventionally the last element (ignoring a `/vN` major suffix).
      const parts = path.split('/');
      let name = parts[parts.length - 1];
      if (/^v\d+$/.test(name) && parts.length > 1) name = parts[parts.length - 2];
      name = name.replace(/^go-/, '').replace(/[.-].*$/, '');
      out.set(alias && alias !== '.' ? alias : name, path);
    }
  }
  return out;
}

class GoGraphBuilder {
  readonly ctxs: FileCtx[] = [];
  readonly pkgs = new Map<string, PkgInfo>();
  readonly methodsByName = new Map<string, StableDecl[]>();
  readonly edges: CallEdge[] = [];
  readonly unresolved: UnresolvedCall[] = [];
  readonly references: ReferenceEdge[] = [];
  readonly imports: ImportEdge[] = [];
  readonly loads: { from: string; to: string }[] = [];
  readonly entries: TsEntry[] = [];
  readonly unresolvedRegistrations: UnresolvedRegistration[] = [];
  readonly typeOnly = new Set<string>();
  private readonly siteKeys = new Set<string>();
  private readonly edgeKeys = new Set<string>();

  constructor(private readonly options: GoGraphOptions) {}

  add(ctx: FileCtx): void {
    this.ctxs.push(ctx);
    let p = this.pkgs.get(ctx.pkg);
    if (!p) {
      p = { dir: ctx.pkg, files: [], top: new Map(), methods: new Map(), interfaces: new Map(), fields: new Map(), results: new Map() };
      this.pkgs.set(ctx.pkg, p);
    }
    p.files.push(ctx);
    const module = ctx.ids.decls[0];
    for (const d of ctx.ids.decls) {
      if (d.flags.includes('unstable:anonymous') || d === module) continue;
      if (d.kind === 'method') {
        const recv = d.qualified_name.slice(d.qualified_name.indexOf(':') + 1).split('.')[0];
        const m = p.methods.get(recv) ?? new Map<string, StableDecl>();
        m.set(d.name, d);
        p.methods.set(recv, m);
        const list = this.methodsByName.get(d.name) ?? [];
        list.push(d);
        this.methodsByName.set(d.name, list);
      } else if (d.parent === module.id && d.name !== 'init') p.top.set(d.name, d);
    }
    for (const td of namedChildren(ctx.root).filter(c => c.type === 'type_declaration')) {
      for (const spec of namedChildren(td)) {
        const name = spec.childForFieldName('name')?.text;
        if (!name || spec.childForFieldName('type')?.type !== 'interface_type') continue;
        const iface = spec.childForFieldName('type')!;
        p.interfaces.set(name, new Set(namedChildren(iface).filter(c => c.type === 'method_elem').map(c => c.childForFieldName('name')?.text ?? '')));
        const d = p.top.get(name);
        if (d) this.typeOnly.add(d.id);
      }
    }
  }

  /** The project package directory an import path names, if any. */
  pkgFor(importPath: string): PkgInfo | undefined {
    const mod = this.options.modulePath;
    if (mod) {
      if (importPath === mod) return this.pkgs.get('.');
      if (importPath.startsWith(mod + '/')) return this.pkgs.get(importPath.slice(mod.length + 1));
      return undefined;
    }
    // By directory suffix: the longest project directory the import path ends with.
    let best: PkgInfo | undefined;
    for (const p of this.pkgs.values()) {
      if (p.dir === '.') continue;
      if ((importPath === p.dir || importPath.endsWith('/' + p.dir)) && (!best || p.dir.length > best.dir.length)) best = p;
    }
    return best;
  }

  // -- recording -----------------------------------------------------------

  private site(ctx: FileCtx, n: Node): CallEdgeSite {
    return { file: ctx.path, line: n.startPosition.row + 1, col: n.startPosition.column };
  }

  private edge(from: StableDecl, to: StableDecl, tier: CallEdge['tier'], methodName: string, site: CallEdgeSite, evidence: string): void {
    const key = `${from.id}>${to.id}@${site.file}:${site.line}:${site.col}`;
    if (this.edgeKeys.has(key)) return;
    this.edgeKeys.add(key);
    this.siteKeys.add(`${site.file}:${site.line}:${site.col}:${methodName}`);
    this.edges.push({ from: from.id, to: to.id, tier, methodName, site, evidence });
  }

  private unresolvedSite(from: StableDecl, methodName: string, site: CallEdgeSite, reason: UnresolvedCall['reason'], evidence: string): void {
    this.siteKeys.add(`${site.file}:${site.line}:${site.col}:${methodName}`);
    this.unresolved.push({ from: from.id, methodName, site, reason, evidence });
  }

  get sites(): number {
    return this.siteKeys.size;
  }

  private entry(e: TsEntry): void {
    if (this.entries.some(x => x.id === e.id && x.kind === e.kind && x.method === e.method && x.path === e.path)) return;
    this.entries.push(e);
  }

  private enclosing(ctx: FileCtx, n: Node): StableDecl {
    return ctx.locate(n.startPosition.row + 1, n.startPosition.column) ?? ctx.ids.decls[0];
  }

  /** The receiver name and type of the method enclosing a node. */
  private receiverOf(ctx: FileCtx, n: Node): { name: string; type: string } | null {
    let p: Node | null = n;
    while (p && p.type !== 'method_declaration') p = p.parent;
    if (!p) return null;
    const recv = p.childForFieldName('receiver');
    const decl = recv ? namedChildren(recv).find(c => c.type === 'parameter_declaration') : undefined;
    const name = decl?.childForFieldName('name')?.text;
    return name ? { name, type: goReceiverType(p) } : null;
  }

  // -- resolution ----------------------------------------------------------

  // -- types ---------------------------------------------------------------

  /** Index struct fields and function results; called after every file is added. */
  indexTypes(): void {
    for (const p of this.pkgs.values()) {
      for (const ctx of p.files) {
        for (const td of namedChildren(ctx.root).filter(c => c.type === 'type_declaration')) {
          for (const spec of namedChildren(td)) {
            const name = spec.childForFieldName('name')?.text;
            const st = spec.childForFieldName('type');
            if (!name || st?.type !== 'struct_type') continue;
            const fields = new Map<string, TypeRef | null>();
            for (const list of namedChildren(st)) {
              for (const fd of namedChildren(list).filter(c => c.type === 'field_declaration')) {
                const ref = this.typeRef(ctx, fd.childForFieldName('type'));
                const names = namedChildren(fd).filter(c => c.type === 'field_identifier');
                if (names.length === 0 && ref) fields.set(ref.name, ref); // embedded
                for (const n of names) fields.set(n.text, ref);
              }
            }
            p.fields.set(name, fields);
          }
        }
        for (const fn of namedChildren(ctx.root)) {
          if (fn.type !== 'function_declaration' && fn.type !== 'method_declaration') continue;
          const name = fn.childForFieldName('name')?.text;
          if (!name) continue;
          const key = fn.type === 'method_declaration' ? `${goReceiverType(fn)}.${name}` : name;
          const result = fn.childForFieldName('result');
          const first = result?.type === 'parameter_list' ? namedChildren(result)[0]?.childForFieldName('type') : result;
          p.results.set(key, this.typeRef(ctx, first ?? null));
        }
      }
    }
  }

  /** The project type a type node names (`T`, `*T`, `pkg.T`), or null. */
  private typeRef(ctx: FileCtx, t: Node | null | undefined): TypeRef | null {
    if (!t) return null;
    if (t.type === 'pointer_type' || t.type === 'parenthesized_type') return this.typeRef(ctx, namedChildren(t)[0]);
    if (t.type === 'generic_type') return this.typeRef(ctx, t.childForFieldName('type'));
    if (t.type === 'type_identifier') return this.pkgs.get(ctx.pkg)!.top.get(t.text)?.kind === 'type' ? { pkg: ctx.pkg, name: t.text } : null;
    if (t.type === 'qualified_type') {
      const path = ctx.imports.get(t.childForFieldName('package')?.text ?? '');
      const p = path !== undefined ? this.pkgFor(path) : undefined;
      const name = t.childForFieldName('name')?.text ?? '';
      return p && p.top.get(name)?.kind === 'type' ? { pkg: p.dir, name } : null;
    }
    return null;
  }

  private readonly envs = new Map<number, Map<string, TypeRef>>();

  /** Local names with a known project type in the function enclosing `n`: receiver, parameters, `x := T{}` / `x := NewT()`. */
  private env(ctx: FileCtx, n: Node): Map<string, TypeRef> {
    let fn: Node | null = n;
    while (fn && fn.type !== 'function_declaration' && fn.type !== 'method_declaration' && fn.type !== 'func_literal') fn = fn.parent;
    if (!fn) return new Map();
    const cached = this.envs.get(fn.id);
    if (cached) return cached;
    const env = new Map<string, TypeRef>(fn.type === 'func_literal' ? this.env(ctx, fn.parent ?? fn) : []);
    this.envs.set(fn.id, env);
    for (const listName of ['receiver', 'parameters']) {
      const list = fn.childForFieldName(listName);
      for (const p of list ? namedChildren(list) : []) {
        const ref = this.typeRef(ctx, p.childForFieldName('type'));
        if (ref) for (const id of namedChildren(p).filter(c => c.type === 'identifier')) env.set(id.text, ref);
      }
    }
    walk(fn.childForFieldName('body') ?? fn, m => {
      if (m.type === 'func_literal') return false;
      if (m.type === 'short_var_declaration' || m.type === 'var_spec') {
        const left = m.type === 'var_spec' ? namedChildren(m).filter(c => c.type === 'identifier') : namedChildren(m.childForFieldName('left') ?? m);
        const declared = m.type === 'var_spec' ? this.typeRef(ctx, m.childForFieldName('type')) : null;
        const right = namedChildren(m.type === 'var_spec' ? m.childForFieldName('value') ?? m : m.childForFieldName('right') ?? m);
        left.forEach((l, i) => {
          const ref = declared ?? (right[i] ? this.typeOf(ctx, right[i], env) : null) ?? (i === 0 && right.length === 1 ? this.typeOf(ctx, right[0], env) : null);
          if (ref && l.type === 'identifier') env.set(l.text, ref);
        });
      }
      return undefined;
    });
    return env;
  }

  /** The project type of an expression, when the tree says it. */
  private typeOf(ctx: FileCtx, e: Node, env?: Map<string, TypeRef>): TypeRef | null {
    const scope = env ?? this.env(ctx, e);
    switch (e.type) {
      case 'identifier':
        return scope.get(e.text) ?? null;
      case 'unary_expression':
      case 'parenthesized_expression':
        return this.typeOf(ctx, namedChildren(e)[0], scope);
      case 'composite_literal':
        return this.typeRef(ctx, e.childForFieldName('type'));
      case 'selector_expression': {
        const op = e.childForFieldName('operand');
        const field = e.childForFieldName('field')?.text ?? '';
        const t = op ? this.typeOf(ctx, op, scope) : null;
        return t ? this.pkgs.get(t.pkg)?.fields.get(t.name)?.get(field) ?? null : null;
      }
      case 'call_expression': {
        const fn = e.childForFieldName('function');
        if (!fn) return null;
        if (fn.type === 'identifier') return this.pkgs.get(ctx.pkg)!.results.get(fn.text) ?? null;
        if (fn.type === 'selector_expression') {
          const op = fn.childForFieldName('operand');
          const name = fn.childForFieldName('field')?.text ?? '';
          const path = op?.type === 'identifier' ? ctx.imports.get(op.text) : undefined;
          if (path !== undefined) return this.pkgFor(path)?.results.get(name) ?? null;
          const t = op ? this.typeOf(ctx, op, scope) : null;
          return t ? this.pkgs.get(t.pkg)?.results.get(`${t.name}.${name}`) ?? null : null;
        }
        return null;
      }
      default:
        return null;
    }
  }

  /** A method on a project type, through embedded fields. */
  private methodOn(t: TypeRef, name: string, depth = 0): StableDecl | null {
    const p = this.pkgs.get(t.pkg);
    const m = p?.methods.get(t.name)?.get(name);
    if (m || depth > 3) return m ?? null;
    for (const [fname, ref] of p?.fields.get(t.name) ?? []) {
      if (ref && fname === ref.name) {
        const em = this.methodOn(ref, name, depth + 1);
        if (em) return em;
      }
    }
    return null;
  }

  /** Project types whose method set covers an interface's. */
  private implementers(t: TypeRef, name: string): StableDecl[] {
    const need = this.pkgs.get(t.pkg)?.interfaces.get(t.name);
    if (!need) return [];
    const out: StableDecl[] = [];
    for (const p of this.pkgs.values()) {
      for (const [type, ms] of p.methods) {
        if ([...need].every(x => ms.has(x)) && ms.has(name)) out.push(ms.get(name)!);
        void type;
      }
    }
    return out;
  }

  /** What an operand names: a project declaration, an external package, or nothing known. */
  private resolve(ctx: FileCtx, n: Node): { decl?: StableDecl; polymorphic?: StableDecl[]; candidates?: StableDecl[]; external?: string; name: string } | null {
    const pkg = this.pkgs.get(ctx.pkg)!;
    if (n.type === 'identifier') {
      if (BUILTINS.has(n.text)) return null;
      const d = pkg.top.get(n.text);
      return d ? { decl: d, name: n.text } : null;
    }
    if (n.type === 'selector_expression') {
      const operand = n.childForFieldName('operand');
      const field = n.childForFieldName('field')?.text ?? '';
      if (!operand) return null;
      if (operand.type === 'identifier') {
        // pkg.F
        const path = ctx.imports.get(operand.text);
        if (path !== undefined) {
          const target = this.pkgFor(path);
          if (!target) return { external: path, name: field };
          const d = target.top.get(field);
          return d ? { decl: d, name: field } : { name: field };
        }
        // recv.M on the enclosing method's receiver
        const recv = this.receiverOf(ctx, n);
        if (recv && recv.name === operand.text) {
          const m = pkg.methods.get(recv.type)?.get(field);
          if (m) return { decl: m, name: field };
        }
        // T.M method expression
        const typeDecl = pkg.top.get(operand.text);
        if (typeDecl?.kind === 'type') {
          const m = pkg.methods.get(operand.text)?.get(field);
          if (m) return { decl: m, name: field };
        }
      }
      // x.M on a value of known project type: the type's method, or an interface's implementers.
      const t = this.typeOf(ctx, operand);
      if (t) {
        if (this.pkgs.get(t.pkg)?.interfaces.has(t.name)) {
          const impls = this.implementers(t, field);
          if (impls.length > 0) return { polymorphic: impls, name: field };
        } else {
          const m = this.methodOn(t, field);
          if (m) return { decl: m, name: field };
          if (this.pkgs.get(t.pkg)?.fields.get(t.name)?.has(field)) return { name: field }; // a func-typed field
        }
      }
      // x.M on a value of unknown type
      const candidates = this.methodsByName.get(field) ?? [];
      return { candidates, name: field };
    }
    return null;
  }

  calls(ctx: FileCtx): void {
    walk(ctx.root, n => {
      if (n.type === 'call_expression') {
        this.callOne(ctx, n);
        return false;
      }
      return this.visit(ctx, n);
    });
  }

  /** Values: function and method references, composite literals. */
  private visit(ctx: FileCtx, n: Node): boolean | void {
    if (n.type === 'call_expression') {
      this.callOne(ctx, n);
      return false;
    }
    if (n.type === 'composite_literal') {
      const t = n.childForFieldName('type');
      const name = t?.type === 'type_identifier' ? t.text : t?.type === 'qualified_type' ? t.text : null;
      if (name) {
        const pkg = this.pkgs.get(ctx.pkg)!;
        let d: StableDecl | undefined;
        if (name.includes('.')) {
          const [p, tn] = name.split('.');
          const path = ctx.imports.get(p);
          d = path !== undefined ? this.pkgFor(path)?.top.get(tn) : undefined;
        } else d = pkg.top.get(name);
        if (d) this.loads.push({ from: this.enclosing(ctx, n).id, to: d.id }); // constructs a value of the type
      }
      return undefined;
    }
    if (n.type === 'identifier' || n.type === 'selector_expression') {
      const parent = n.parent;
      if (!parent) return undefined;
      if (['function_declaration', 'method_declaration', 'parameter_declaration', 'var_spec', 'const_spec', 'import_spec', 'field_declaration', 'type_spec', 'labeled_statement'].includes(parent.type)) return false;
      if (parent.type === 'selector_expression' && parent.childForFieldName('field') === n) return undefined;
      const r = this.resolve(ctx, n);
      const enc = this.enclosing(ctx, n);
      if (r?.decl && (r.decl.kind === 'function' || r.decl.kind === 'method') && r.decl.id !== enc.id) {
        this.references.push({ from: enc.id, to: r.decl.id, site: this.site(ctx, n) });
      } else if (n.type === 'selector_expression' && r?.candidates && r.candidates.length > 0 && r.candidates.length <= (this.options.maxInferred ?? 16)) {
        // A method value on a value of unknown type (`s.handle`): a reference to each method of that name.
        for (const c of r.candidates) if (c.id !== enc.id) this.references.push({ from: enc.id, to: c.id, site: this.site(ctx, n) });
      }
      return n.type === 'selector_expression' ? false : undefined;
    }
    return undefined;
  }

  private callOne(ctx: FileCtx, n: Node): void {
    const fn = n.childForFieldName('function');
    if (!fn) return;
    const from = this.enclosing(ctx, n);
    const site = this.site(ctx, fn);
    const r = this.resolve(ctx, fn);
    if (r?.decl) {
      if (r.decl.kind === 'type') this.loads.push({ from: from.id, to: r.decl.id }); // a conversion `T(x)`
      else if (r.decl.kind !== 'field') this.edge(from, r.decl, 'exact', r.name, site, 'resolved by package scope, import or receiver');
    } else if (r?.polymorphic) {
      for (const m of r.polymorphic) this.edge(from, m, 'polymorphic', r.name, site, `.${r.name}() on an interface; an implementing type's method`);
    } else if (r?.external !== undefined) this.unresolvedSite(from, r.name, site, 'external', `${r.external}.${r.name}`);
    else if (r?.candidates) {
      if (r.candidates.length === 0) this.unresolvedSite(from, r.name, site, 'external', `.${r.name}(): no project method of that name`);
      else if (r.candidates.length > (this.options.maxInferred ?? 16)) this.unresolvedSite(from, r.name, site, 'unknown', `.${r.name}(): ${r.candidates.length} project methods of that name`);
      else for (const m of r.candidates) this.edge(from, m, 'inferred', r.name, site, `.${r.name}() on a value of unknown type`);
    } else if (fn.type === 'parenthesized_expression' || fn.type === 'index_expression' || fn.type === 'call_expression') {
      this.unresolvedSite(from, '<computed>', site, 'dynamic', 'computed callee');
    }
    if (fn.type === 'selector_expression') {
      const op = fn.childForFieldName('operand');
      if (op && op.type !== 'identifier') walk(op, m => this.visit(ctx, m));
    } else if (fn.type !== 'identifier') walk(fn, m => this.visit(ctx, m));
    const args = n.childForFieldName('arguments');
    if (args) for (const a of namedChildren(args)) walk(a, m => this.visit(ctx, m));
  }

  // -- imports -------------------------------------------------------------

  importsOf(ctx: FileCtx): void {
    const self = ctx.ids.decls[0];
    const seen = new Set<string>();
    for (const path of ctx.imports.values()) {
      const p = this.pkgFor(path);
      if (!p || p.dir === ctx.pkg) continue;
      for (const f of p.files) {
        if (seen.has(f.path)) continue;
        seen.add(f.path);
        this.imports.push({ from: self.id, to: f.ids.decls[0].id });
      }
    }
    // A package is compiled whole: its files load each other.
    for (const f of this.pkgs.get(ctx.pkg)!.files) {
      if (f !== ctx && !f.path.endsWith('_test.go')) this.loads.push({ from: self.id, to: f.ids.decls[0].id });
    }
  }

  // -- entries -------------------------------------------------------------

  entriesOf(ctx: FileCtx): void {
    const module = ctx.ids.decls[0];
    const isTest = ctx.path.endsWith('_test.go');
    const frameworkOf = (alias: string): string | null => {
      const path = ctx.imports.get(alias);
      if (path === undefined) return null;
      for (const [prefix, fw] of Object.entries(ROUTERS)) if (path === prefix || path.startsWith(prefix + '/')) return fw;
      return null;
    };
    const routerImports = [...ctx.imports.keys()].map(frameworkOf).filter((x): x is string => x !== null);
    for (const d of ctx.ids.decls) {
      if (d.flags.includes('unstable:anonymous') || d === module) continue;
      if (d.kind === 'function' && d.name === 'main' && ctx.pkgName === 'main') {
        this.entry({ id: d.id, kind: 'main', certainty: 'declared', file: ctx.path, line: d.start_line, evidence: 'func main in package main' });
      }
      if (d.kind === 'function' && d.name === 'init') {
        this.entry({ id: d.id, kind: 'lifecycle', certainty: 'declared', file: ctx.path, line: d.start_line, evidence: 'func init runs when the package loads' });
      }
      if (isTest && d.kind === 'function' && TEST_FUNC.test(d.name)) {
        this.entry({ id: d.id, kind: 'test', certainty: 'declared', framework: 'testing', file: ctx.path, line: d.start_line, evidence: `go test: ${d.name}` });
      }
      if (isTest && d.kind === 'function' && d.name === 'TestMain') {
        this.entry({ id: d.id, kind: 'test', certainty: 'declared', framework: 'testing', file: ctx.path, line: d.start_line, evidence: 'TestMain' });
      }
      if ((this.options.libraryPackages ?? []).includes(ctx.pkg) && /^[A-Z]/.test(d.name) && !isTest && d.kind !== 'field') {
        this.entry({ id: d.id, kind: 'export', certainty: 'conventional', file: ctx.path, line: d.start_line, evidence: 'exported from a library package' });
      }
    }
    if (isTest) this.entry({ id: module.id, kind: 'test', certainty: 'conventional', framework: 'testing', file: ctx.path, line: 1, evidence: 'test file' });
    if (routerImports.length > 0) this.routes(ctx, frameworkOf);
  }

  /** Router registrations, with group and route prefixes composed per function body. */
  private routes(ctx: FileCtx, frameworkOf: (alias: string) => string | null): void {
    const prefixes = new Map<string, string>(); // variable → prefix (function-local, flow-insensitive)
    const register = (call: Node, framework: string, method: string, path: string, handler: Node | undefined, prefix: string, certainty: EntryCertainty): void => {
      const site = this.site(ctx, call);
      const full = joinRoutePath([prefix, path]);
      if (!handler) return;
      const targets: StableDecl[] = [];
      const h = handler.type === 'unary_expression' ? namedChildren(handler)[0] ?? handler : handler;
      if (h.type === 'func_literal') {
        const d = ctx.locate(h.startPosition.row + 1, h.startPosition.column);
        if (d) targets.push(d);
      } else if (h.type === 'call_expression') {
        // http.HandlerFunc(f), handlerFactory(dep): the wrapped function, or the factory itself.
        const inner = namedChildren(h.childForFieldName('arguments') ?? h)[0];
        const r = inner ? this.resolve(ctx, inner) : null;
        if (r?.decl) targets.push(r.decl);
        else {
          const f = this.resolve(ctx, h.childForFieldName('function') ?? h);
          if (f?.decl) targets.push(f.decl);
        }
      } else {
        const r = this.resolve(ctx, h);
        if (r?.decl) targets.push(r.decl);
        else if (r?.polymorphic) targets.push(...r.polymorphic);
        else if (r?.candidates && r.candidates.length > 0 && r.candidates.length <= (this.options.maxInferred ?? 16)) {
          targets.push(...r.candidates);
          certainty = 'inferred';
        }
      }
      if (targets.length === 0) {
        this.unresolvedRegistrations.push({ site, reason: 'handler-unresolved', evidence: `${framework} ${method} ${full}: ${handler.text}` });
        return;
      }
      for (const t of targets) {
        const e: TsEntry = { id: t.id, kind: 'route', certainty, framework, method, path: full, surface: 'api', file: ctx.path, line: site.line, evidence: `${framework} ${method} ${path}` };
        if (prefix) { e.registeredPath = path; e.mounts = [prefix]; }
        this.entry(e);
      }
    };
    walk(ctx.root, n => {
      if (n.type === 'function_declaration' || n.type === 'method_declaration') prefixes.clear();
      // g := r.Group("/api") / e.Group("/api")
      if (n.type === 'short_var_declaration' || n.type === 'assignment_statement') {
        const left = namedChildren(n.childForFieldName('left') ?? n)[0];
        const right = namedChildren(n.childForFieldName('right') ?? n)[0];
        if (left?.type === 'identifier' && right?.type === 'call_expression') {
          const fn = right.childForFieldName('function');
          if (fn?.type === 'selector_expression' && ['Group', 'PathPrefix', 'Subrouter'].includes(fn.childForFieldName('field')?.text ?? '')) {
            const base = fn.childForFieldName('operand');
            const arg = stringValue(namedChildren(right.childForFieldName('arguments') ?? right)[0]);
            let p = base?.type === 'identifier' ? prefixes.get(base.text) ?? '' : '';
            // r.PathPrefix("/x").Subrouter()
            if (base?.type === 'call_expression') {
              const inner = base.childForFieldName('function');
              if (inner?.type === 'selector_expression' && inner.childForFieldName('field')?.text === 'PathPrefix') {
                const ib = inner.childForFieldName('operand');
                p = (ib?.type === 'identifier' ? prefixes.get(ib.text) ?? '' : '') + (stringValue(namedChildren(base.childForFieldName('arguments') ?? base)[0]) ?? '');
              }
            }
            prefixes.set(left.text, joinRoutePath([p, arg ?? '']).replace(/^\/$/, ''));
          }
        }
      }
      if (n.type !== 'call_expression') return undefined;
      const fn = n.childForFieldName('function');
      if (fn?.type !== 'selector_expression') return undefined;
      const recv = fn.childForFieldName('operand');
      const verb = fn.childForFieldName('field')?.text ?? '';
      const args = namedChildren(n.childForFieldName('arguments') ?? n);
      const recvName = recv?.type === 'identifier' ? recv.text : '';
      const prefix = prefixes.get(recvName) ?? '';
      const pkgFw = recv?.type === 'identifier' ? frameworkOf(recv.text) : null;
      // net/http: http.HandleFunc("/x", h), mux.HandleFunc("GET /x", h)
      if (HTTP_FUNCS.includes(verb)) {
        const pattern = stringValue(args[0]);
        if (pattern === null) return undefined;
        const m = /^([A-Z]+)\s+(.*)$/.exec(pattern);
        const fw = pkgFw ?? 'net/http';
        register(n, fw === 'chi' || fw === 'gorilla' ? fw : 'net/http', m ? m[1] : 'ANY', m ? m[2] : pattern, args[1], prefix, pkgFw || [...ctx.imports.values()].includes('net/http') ? 'declared' : 'inferred');
        return undefined;
      }
      // chi: r.Route("/x", func(r chi.Router) { ... }) — prefix the inner router.
      if (verb === 'Route' && args.length >= 2 && args[1].type === 'func_literal') {
        const p = stringValue(args[0]) ?? '';
        const params = args[1].childForFieldName('parameters');
        const inner = params ? namedChildren(params)[0]?.childForFieldName('name')?.text : undefined;
        if (inner) prefixes.set(inner, joinRoutePath([prefix, p]));
        return undefined;
      }
      if (pkgFw) return undefined; // gin.Default(), echo.New(): not a registration
      const path = stringValue(args[0]);
      if (path === null) return undefined;
      if (UPPER_VERBS.includes(verb)) {
        const handlers = args.slice(1);
        register(n, 'gin/echo', verb === 'Any' || verb === 'Match' ? 'ANY' : verb, path, handlers[handlers.length - 1], prefix, 'declared');
      } else if (CHI_VERBS.includes(verb)) {
        register(n, 'chi', ['Handle', 'HandleFunc', 'Method', 'MethodFunc'].includes(verb) ? 'ANY' : verb.toUpperCase(), path, args[args.length - 1], prefix, 'declared');
      }
      return undefined;
    });
  }
}

/**
 * Build the Go graph facts for a set of files. Each file is parsed once;
 * nothing is read from disk.
 */
export async function buildGoGraph(files: readonly GoSourceFile[], options: GoGraphOptions = {}): Promise<GoGraph> {
  const b = new GoGraphBuilder(options);
  const trees: { tree: Awaited<ReturnType<typeof parse>>; ctx: FileCtx }[] = [];
  const partial: string[] = [];
  const sorted = [...files].sort((x, y) => (x.path < y.path ? -1 : x.path > y.path ? 1 : 0));
  try {
    for (const f of sorted) {
      const tree = await parse(f.code, 'go');
      const ids = deriveGoIds(tree, f.path);
      if (ids.partial) partial.push(f.path);
      const pkgName = namedChildren(namedChildren(tree.rootNode).find(c => c.type === 'package_clause') ?? tree.rootNode)[0]?.text ?? '';
      const ctx: FileCtx = { path: f.path, pkg: goPackageDir(f.path), pkgName, ids, root: tree.rootNode, imports: importsOf(tree.rootNode), locate: declLocator(ids) };
      b.add(ctx);
      trees.push({ tree, ctx });
    }
    b.indexTypes();
    for (const t of trees) {
      b.calls(t.ctx);
      b.importsOf(t.ctx);
      b.entriesOf(t.ctx);
    }
  } finally {
    for (const t of trees) disposeTree(t.tree);
  }
  return {
    scheme: GO_GRAPH_SCHEME,
    ids: 'ids@0.1',
    files: trees.map(t => t.ctx.ids),
    edges: b.edges,
    unresolved: b.unresolved,
    references: b.references,
    imports: b.imports,
    loads: b.loads,
    entryScheme: 'entry-index@0.1',
    entries: b.entries,
    unresolvedRegistrations: b.unresolvedRegistrations,
    partial,
    typeOnly: [...b.typeOnly],
    sites: b.sites,
  };
}
