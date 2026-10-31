/**
 * Python graph facts keyed by stable ids (`python-graph@0.1`): the reach
 * core's input for Python.
 *
 * - **Declarations** from `derivePythonIds` (`ids@0.1`).
 * - **Call edges**, resolved from the syntax tree:
 *   - `exact`: a name bound in the module or imported from a project module,
 *     `module.f` through an import alias, `Class.m`, `self.m` / `cls.m` in a
 *     method (the class's own or an inherited member), `super().m`, and
 *     `Class(...)` (the class and its `__init__`).
 *   - `polymorphic`: `self.m` also reaches the overrides in project subclasses.
 *   - `inferred`: `obj.m` on a receiver of unknown type reaches every project
 *     method named `m`, up to `maxInferred`; beyond it the site is unresolved.
 *   A target outside the project is an unresolved site (`external`), never
 *   dropped; `getattr` and friends are `dynamic`.
 * - **References**: a project function or class used as a value.
 * - **Imports**: a module loads the project modules it imports.
 * - **Loads**: a class reaches its dunder methods (`__str__`, `__enter__`, …),
 *   which the runtime calls without a call site.
 * - **Entries** (`entry-index@0.1`): Flask and FastAPI routes (blueprint and
 *   router prefixes composed), Django `urls.py` routes, click commands,
 *   `if __name__ == "__main__"` blocks and `main` files, console scripts,
 *   Celery tasks, Django management commands, pytest and unittest tests.
 * - **typeOnly**: `Protocol` classes, `@overload` stubs and `.pyi` files.
 *
 * Library code: no file access; the caller passes the sources.
 */

import { disposeTree, parse, type Node } from '../core/parser.js';
import { derivePythonIds, pythonModuleName } from '../stable-ids/python.js';
import { declLocator } from '../stable-ids/nodes.js';
import { namedChildren } from '../stable-ids/normalize.js';
import type { StableDecl, StableIdFile } from '../stable-ids/types.js';
import type { EntryCertainty, EntryKind } from './ts-entry-tables.js';
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

export const PYTHON_GRAPH_SCHEME = 'python-graph@0.1' as const;

export interface PythonSourceFile {
  /** Repository-relative path, `/`-separated. */
  path: string;
  code: string;
  /** The module's dotted name; derived from the path when absent. */
  module?: string;
}

export interface PythonGraphOptions {
  /** Files run as programs (`main` entries on the module), in addition to `__main__` blocks. */
  mainFiles?: readonly string[];
  /** Console scripts as `pkg.mod:func` (from `pyproject.toml` / `setup.cfg`); each is a `main` entry. */
  consoleScripts?: readonly string[];
  /** Most `inferred` edges one site may carry; beyond it the site is unresolved. Default 16. */
  maxInferred?: number;
}

export interface PythonGraph {
  scheme: typeof PYTHON_GRAPH_SCHEME;
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

const HTTP_VERBS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];
const DYNAMIC_CALLS = new Set(['getattr', 'setattr', 'eval', 'exec', '__import__', 'import_module']);
/** Called by the runtime, never through a call site. */
const DUNDER = /^__[a-z0-9_]+__$/;
const TEST_FILE = /(^|\/)(test_[^/]*|[^/]*_test)\.py$|(^|\/)tests?\/.*\.py$|(^|\/)conftest\.py$/;
const TEST_CASE_BASES = new Set(['TestCase', 'unittest.TestCase', 'IsolatedAsyncioTestCase', 'TransactionTestCase', 'SimpleTestCase', 'APITestCase', 'LiveServerTestCase']);
const TEST_LIFECYCLE = new Set(['setUp', 'tearDown', 'setUpClass', 'tearDownClass', 'asyncSetUp', 'asyncTearDown', 'setup_method', 'teardown_method', 'setup_class', 'teardown_class']);
const DJANGO_CBV_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'dispatch', 'get_queryset', 'get_context_data', 'get_object', 'form_valid', 'form_invalid', 'perform_create', 'perform_update', 'perform_destroy', 'list', 'create', 'retrieve', 'update', 'partial_update', 'destroy']);

// ---------------------------------------------------------------------------
// Per-file context

/** What a name bound at module level by an import points at. */
type Binding =
  | { kind: 'module'; module: string }
  | { kind: 'member'; module: string; name: string };

interface FileCtx {
  path: string;
  module: string;
  ids: StableIdFile;
  root: Node;
  /** Top-level names in this module: functions, classes, fields. */
  top: Map<string, StableDecl>;
  imports: Map<string, Binding>;
  /** Module-level names bound to a value from outside the project (`app = Flask(...)`). */
  external: Set<string>;
  locate: (line: number, column?: number) => StableDecl | null;
  byLine: Map<string, StableDecl>;
}

interface ClassInfo {
  decl: StableDecl;
  ctx: FileCtx;
  members: Map<string, StableDecl>;
  /** Base classes as written (`Base`, `mod.Base`). */
  bases: string[];
  /** Resolved project bases. */
  parents: ClassInfo[];
  children: ClassInfo[];
}

const posKey = (line: number, col: number): string => `${line}:${col}`;

function text(n: Node | null | undefined): string {
  return n?.text ?? '';
}

function stringValue(n: Node | null | undefined): string | null {
  if (!n || n.type !== 'string') return null;
  const parts = namedChildren(n).filter(c => c.type === 'string_content');
  if (namedChildren(n).some(c => c.type === 'interpolation')) return null;
  return parts.map(c => c.text).join('');
}

function walk(node: Node, visit: (n: Node) => boolean | void): void {
  if (visit(node) === false) return;
  for (const c of namedChildren(node)) walk(c, visit);
}

/** Resolve a relative module (`.`, `..pkg`) against a module's package. */
function resolveRelative(current: string, isPackage: boolean, written: string): string {
  const dots = written.length - written.replace(/^\.+/, '').length;
  const rest = written.slice(dots);
  const parts = current.split('.');
  // A module's package is its name minus the last part; a package (`__init__`) is its own package.
  let base = isPackage ? parts : parts.slice(0, -1);
  base = base.slice(0, Math.max(0, base.length - (dots - 1)));
  return [...base, ...(rest ? rest.split('.') : [])].filter(x => x !== '').join('.');
}

function importsOf(root: Node, module: string, isPackage: boolean): { bindings: Map<string, Binding>; modules: string[] } {
  const bindings = new Map<string, Binding>();
  const modules: string[] = [];
  walk(root, n => {
    if (n.type === 'function_definition' || n.type === 'class_definition') return; // module-level imports only bind names here; nested ones handled loosely below
    if (n.type === 'import_statement') {
      for (const c of namedChildren(n)) {
        if (c.type === 'dotted_name') {
          const full = c.text;
          modules.push(full);
          bindings.set(full.split('.')[0], { kind: 'module', module: full.split('.')[0] });
          // `import a.b` also makes `a.b` reachable through attribute access.
          bindings.set(full, { kind: 'module', module: full });
        } else if (c.type === 'aliased_import') {
          const name = text(c.childForFieldName('name'));
          const alias = text(c.childForFieldName('alias'));
          modules.push(name);
          bindings.set(alias, { kind: 'module', module: name });
        }
      }
      return false;
    }
    if (n.type === 'import_from_statement') {
      const modNode = n.childForFieldName('module_name');
      const written = text(modNode);
      const from = written.startsWith('.') ? resolveRelative(module, isPackage, written) : written;
      modules.push(from);
      for (const c of namedChildren(n)) {
        if (c === modNode) continue;
        if (c.type === 'dotted_name') {
          bindings.set(c.text, { kind: 'member', module: from, name: c.text });
        } else if (c.type === 'aliased_import') {
          const name = text(c.childForFieldName('name'));
          bindings.set(text(c.childForFieldName('alias')), { kind: 'member', module: from, name });
        }
      }
      return false;
    }
    return undefined;
  });
  return { bindings, modules };
}

// ---------------------------------------------------------------------------
// Builder

class PyGraphBuilder {
  readonly ctxs: FileCtx[] = [];
  readonly byModule = new Map<string, FileCtx>();
  readonly classes = new Map<string, ClassInfo>(); // by decl id
  readonly methodsByName = new Map<string, StableDecl[]>();
  readonly declFile = new Map<string, FileCtx>();

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

  constructor(private readonly maxInferred: number) {}

  add(ctx: FileCtx): void {
    this.ctxs.push(ctx);
    this.byModule.set(ctx.module, ctx);
    for (const d of ctx.ids.decls) this.declFile.set(d.id, ctx);
  }

  // -- indexes -------------------------------------------------------------

  index(): void {
    for (const ctx of this.ctxs) {
      for (const d of ctx.ids.decls) {
        if (d.kind === 'type' && !d.flags.includes('unstable:anonymous')) {
          this.classes.set(d.id, { decl: d, ctx, members: new Map(), bases: [], parents: [], children: [] });
        }
      }
      for (const d of ctx.ids.decls) {
        const parentClass = d.parent ? this.classes.get(d.parent) : undefined;
        if (parentClass && !d.flags.includes('unstable:anonymous')) parentClass.members.set(d.name, d);
        if (d.kind === 'method' && !d.flags.includes('unstable:anonymous')) {
          const list = this.methodsByName.get(d.name) ?? [];
          list.push(d);
          this.methodsByName.set(d.name, list);
        }
      }
    }
    // Bases from the class definitions.
    for (const ctx of this.ctxs) {
      walk(ctx.root, n => {
        if (n.type !== 'class_definition') return;
        const decl = this.declAt(ctx, n);
        const info = decl ? this.classes.get(decl.id) : undefined;
        const supers = n.childForFieldName('superclasses');
        if (info && supers) {
          info.bases = namedChildren(supers).filter(c => c.type === 'identifier' || c.type === 'attribute').map(c => c.text);
        }
      });
    }
    for (const ctx of this.ctxs) {
      for (const st of namedChildren(ctx.root)) {
        if (st.type !== 'expression_statement') continue;
        const a = namedChildren(st)[0];
        const left = a?.type === 'assignment' ? a.childForFieldName('left') : null;
        const right = a?.childForFieldName('right');
        if (left?.type !== 'identifier' || !right) continue;
        const callee = (right.type === 'call' ? text(right.childForFieldName('function')) : right.text).replace(/\s+/g, '');
        if (/^[A-Za-z_][\w.]*$/.test(callee) && !this.resolveName(ctx, callee) && this.isExternal(ctx, callee)) ctx.external.add(left.text);
      }
    }
    for (const info of this.classes.values()) {
      for (const b of info.bases) {
        const target = this.resolveName(info.ctx, b);
        const parent = target ? this.classes.get(target.id) : undefined;
        if (parent) {
          info.parents.push(parent);
          parent.children.push(info);
          // Defining a class evaluates its bases.
          this.loads.push({ from: info.decl.id, to: parent.decl.id });
        }
      }
    }
  }

  /** The declaration a definition node (or its decorated wrapper) declares. */
  declAt(ctx: FileCtx, def: Node): StableDecl | undefined {
    const holder = def.parent?.type === 'decorated_definition' ? def.parent : def;
    return ctx.byLine.get(posKey(holder.startPosition.row + 1, holder.startPosition.column));
  }

  /** Resolve a dotted name as written in a file to a project declaration. */
  resolveName(ctx: FileCtx, written: string): StableDecl | null {
    const parts = written.split('.');
    // Local top-level name.
    const local = ctx.top.get(parts[0]);
    if (local && parts.length === 1) return local;
    if (local && local.kind === 'type') return this.member(this.classes.get(local.id), parts.slice(1));
    // Imported.
    for (let i = parts.length; i >= 1; i--) {
      const head = parts.slice(0, i).join('.');
      const b = ctx.imports.get(head);
      if (!b) continue;
      const rest = parts.slice(i);
      if (b.kind === 'module') return this.inModule(b.module, rest);
      const target = this.byModule.get(b.module);
      if (target) {
        const d = target.top.get(b.name);
        if (d) return rest.length === 0 ? d : d.kind === 'type' ? this.member(this.classes.get(d.id), rest) : null;
      }
      // `from pkg import submodule`
      return this.inModule(`${b.module}.${b.name}`, rest);
    }
    return null;
  }

  private inModule(module: string, rest: string[]): StableDecl | null {
    // Longest module prefix.
    for (let i = rest.length; i >= 0; i--) {
      const m = [module, ...rest.slice(0, i)].join('.');
      const ctx = this.byModule.get(m);
      if (!ctx) continue;
      const tail = rest.slice(i);
      if (tail.length === 0) return ctx.ids.decls[0] ?? null;
      const d = ctx.top.get(tail[0]);
      if (!d) return null;
      if (tail.length === 1) return d;
      return d.kind === 'type' ? this.member(this.classes.get(d.id), tail.slice(1)) : null;
    }
    return null;
  }

  /** A member of a class, looking through project bases. */
  member(info: ClassInfo | undefined, path: string[]): StableDecl | null {
    if (!info || path.length !== 1) return null;
    const seen = new Set<string>();
    const queue = [info];
    while (queue.length > 0) {
      const c = queue.shift()!;
      if (seen.has(c.decl.id)) continue;
      seen.add(c.decl.id);
      const m = c.members.get(path[0]);
      if (m) return m;
      queue.push(...c.parents);
    }
    return null;
  }

  isExternal(ctx: FileCtx, written: string): boolean {
    const head = written.split('.')[0];
    const b = ctx.imports.get(head);
    if (!b) return false;
    return !this.byModule.has(b.module) && ![...this.byModule.keys()].some(m => m.startsWith(b.module + '.') || b.module.startsWith(m + '.'));
  }

  // -- recording -----------------------------------------------------------

  private site(ctx: FileCtx, n: Node): CallEdgeSite {
    return { file: ctx.path, line: n.startPosition.row + 1, col: n.startPosition.column };
  }

  private edge(from: StableDecl, to: StableDecl, tier: CallEdge['tier'], methodName: string, site: CallEdgeSite, evidence: string, via?: string): void {
    if (from.id === to.id && tier !== 'exact') return;
    const key = `${from.id}>${to.id}@${site.file}:${site.line}:${site.col}`;
    if (this.edgeKeys.has(key)) return;
    this.edgeKeys.add(key);
    this.siteKeys.add(`${site.file}:${site.line}:${site.col}:${methodName}`);
    const e: CallEdge = { from: from.id, to: to.id, tier, methodName, site, evidence };
    if (via) e.via = via;
    this.edges.push(e);
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

  // -- calls ---------------------------------------------------------------

  /** The enclosing declaration of a node: the innermost decl whose range holds it. */
  private enclosing(ctx: FileCtx, n: Node): StableDecl {
    return ctx.locate(n.startPosition.row + 1, n.startPosition.column) ?? ctx.ids.decls[0];
  }

  /** The class whose method encloses `from`. */
  private classOf(from: StableDecl): ClassInfo | undefined {
    let d: StableDecl | undefined = from;
    const ctx = this.declFile.get(from.id);
    while (d) {
      const c = this.classes.get(d.id);
      if (c) return c;
      d = d.parent ? ctx?.ids.decls.find(x => x.id === d!.parent) : undefined;
    }
    return undefined;
  }

  private overrides(info: ClassInfo, name: string): StableDecl[] {
    const out: StableDecl[] = [];
    const queue = [...info.children];
    const seen = new Set<string>();
    while (queue.length > 0) {
      const c = queue.shift()!;
      if (seen.has(c.decl.id)) continue;
      seen.add(c.decl.id);
      const m = c.members.get(name);
      if (m) out.push(m);
      queue.push(...c.children);
    }
    return out;
  }

  private callTarget(ctx: FileCtx, from: StableDecl, call: Node, isDecorator: boolean): void {
    const fn = call.type === 'call' ? call.childForFieldName('function') : call;
    if (!fn) return;
    const site = this.site(ctx, fn);
    if (fn.type === 'identifier') {
      const name = fn.text;
      if (DYNAMIC_CALLS.has(name)) {
        this.unresolvedSite(from, `<${name}>`, site, 'dynamic', `${name}(): runtime-determined target`);
        return;
      }
      const d = this.resolveName(ctx, name);
      if (d) {
        this.callDecl(from, d, name, site, isDecorator ? 'decorator' : 'name bound in the module or imported');
        return;
      }
      if (this.isExternal(ctx, name)) this.unresolvedSite(from, name, site, 'external', `${name}: imported from outside the project`);
      // Builtins and locals (parameters, nested scopes) are not project calls.
      return;
    }
    if (fn.type === 'attribute') {
      const obj = fn.childForFieldName('object');
      const attr = text(fn.childForFieldName('attribute'));
      if (!obj || !attr) return;
      // super().m
      if (obj.type === 'call' && text(obj.childForFieldName('function')) === 'super') {
        const cls = this.classOf(from);
        const target = cls ? cls.parents.map(p => this.member(p, [attr])).find(Boolean) : null;
        if (target) this.edge(from, target, 'exact', attr, site, 'super() member');
        else this.unresolvedSite(from, attr, site, cls && cls.bases.length > cls.parents.length ? 'external' : 'unknown', 'super() member not in the project');
        return;
      }
      // self.m / cls.m inside a class
      if (obj.type === 'identifier' && (obj.text === 'self' || obj.text === 'cls')) {
        const cls = this.classOf(from);
        if (cls) {
          const own = this.member(cls, [attr]);
          if (own && own.kind !== 'field') {
            this.edge(from, own, 'exact', attr, site, `${obj.text}.${attr} on ${cls.decl.name}`);
            for (const o of this.overrides(cls, attr)) {
              if (o.id !== own.id) this.edge(from, o, 'polymorphic', attr, site, `override in a subclass of ${cls.decl.name}`, own.id);
            }
            return;
          }
          if (own) return; // a field read through a call: a stored callable
          const subs = this.overrides(cls, attr);
          for (const o of subs) this.edge(from, o, 'polymorphic', attr, site, `defined only in subclasses of ${cls.decl.name}`);
          if (subs.length > 0) return;
          if (cls.bases.length > cls.parents.length) {
            this.unresolvedSite(from, attr, site, 'external', `${obj.text}.${attr}: inherited from a base outside the project`);
            return;
          }
        }
      }
      // A receiver bound to an object from outside the project.
      const root = fn.text.split('.')[0];
      if (ctx.external.has(root)) {
        this.unresolvedSite(from, attr, site, 'external', `${root}.${attr}: ${root} comes from outside the project`);
        return;
      }
      // Dotted name: module.f, Class.m, alias.sub.f
      const dotted = fn.text.replace(/\s+/g, '');
      if (/^[A-Za-z_][\w.]*$/.test(dotted)) {
        const d = this.resolveName(ctx, dotted);
        if (d) {
          this.callDecl(from, d, attr, site, isDecorator ? 'decorator' : 'dotted name through a module or class');
          return;
        }
        if (this.isExternal(ctx, dotted)) {
          this.unresolvedSite(from, attr, site, 'external', `${dotted}: imported from outside the project`);
          return;
        }
      }
      // Receiver of unknown type: every project method of that name.
      const candidates = (this.methodsByName.get(attr) ?? []).filter(m => !DUNDER.test(m.name) || attr === m.name);
      if (candidates.length === 0) {
        this.unresolvedSite(from, attr, site, 'external', `.${attr}(): no project method of that name`);
        return;
      }
      if (candidates.length > this.maxInferred) {
        this.unresolvedSite(from, attr, site, 'unknown', `.${attr}(): ${candidates.length} project methods of that name`);
        return;
      }
      for (const m of candidates) this.edge(from, m, 'inferred', attr, site, `.${attr}() on a receiver of unknown type`);
    }
  }

  /** A call that resolved to `d`: a class runs its `__init__`. */
  private callDecl(from: StableDecl, d: StableDecl, name: string, site: CallEdgeSite, evidence: string): void {
    if (d.kind === 'module') return;
    this.edge(from, d, 'exact', name, site, evidence);
    if (d.kind === 'type') {
      const init = this.member(this.classes.get(d.id), ['__init__']);
      if (init) this.edge(from, init, 'exact', '__init__', site, `${d.name}() runs __init__`);
      const nw = this.member(this.classes.get(d.id), ['__new__']);
      if (nw) this.edge(from, nw, 'exact', '__new__', site, `${d.name}() runs __new__`);
    }
  }

  /** Walk calls and value references in a file. */
  calls(ctx: FileCtx): void {
    walk(ctx.root, n => {
      if (n.type === 'decorator') {
        // A decorator runs where the definition is evaluated: in the enclosing scope.
        const holder = n.parent;
        const def = holder?.childForFieldName('definition');
        const decl = def ? this.declAt(ctx, def) : undefined;
        const scope = decl?.parent ? ctx.ids.decls.find(d => d.id === decl.parent) ?? ctx.ids.decls[0] : ctx.ids.decls[0];
        const expr = namedChildren(n)[0];
        if (expr) {
          const target = expr.type === 'call' ? expr : expr;
          this.callTarget(ctx, scope, target, true);
          if (expr.type === 'call') {
            const args = expr.childForFieldName('arguments');
            if (args) walk(args, m => this.visitExpr(ctx, scope, m));
          }
        }
        return false;
      }
      return this.visitExpr(ctx, this.enclosing(ctx, n), n);
    });
  }

  private visitExpr(ctx: FileCtx, from: StableDecl, n: Node): boolean | void {
    if (n.type === 'call') {
      this.callTarget(ctx, this.enclosing(ctx, n), n, false);
      // Walk the receiver and arguments, not the function name itself.
      const fn = n.childForFieldName('function');
      if (fn?.type === 'attribute') {
        const obj = fn.childForFieldName('object');
        if (obj) walk(obj, m => this.visitExpr(ctx, from, m));
      } else if (fn && fn.type !== 'identifier') {
        // `getattr(o, n)()`, `handlers[k]()`: the callee is itself computed.
        walk(fn, m => this.visitExpr(ctx, from, m));
      }
      const args = n.childForFieldName('arguments');
      if (args) walk(args, m => this.visitExpr(ctx, this.enclosing(ctx, m), m));
      return false;
    }
    if (n.type === 'identifier' || n.type === 'attribute') {
      const parent = n.parent;
      // Skip definitions' own names, parameters, import lists and assignment targets.
      if (!parent || ['function_definition', 'class_definition', 'parameters', 'default_parameter', 'typed_parameter', 'keyword_argument_name', 'dotted_name', 'aliased_import', 'import_statement', 'import_from_statement'].includes(parent.type)) {
        return n.type === 'attribute' ? false : undefined;
      }
      if (parent.type === 'keyword_argument' && parent.childForFieldName('name') === n) return undefined;
      if (parent.type === 'argument_list' && parent.parent?.type === 'class_definition') return n.type === 'attribute' ? false : undefined;
      if (parent.type === 'assignment' && parent.childForFieldName('left') === n) return n.type === 'attribute' ? false : undefined;
      if (parent.type === 'attribute' && parent.childForFieldName('attribute') === n) return undefined;
      const written = n.text.replace(/\s+/g, '');
      if (!/^[A-Za-z_][\w.]*$/.test(written)) return undefined;
      let d = this.resolveName(ctx, written);
      const selfRef = /^(self|cls)\.([A-Za-z_]\w*)$/.exec(written);
      if (!d && selfRef) d = this.member(this.classOf(this.enclosing(ctx, n)), [selfRef[2]]);
      if (d && (d.kind === 'function' || d.kind === 'method' || d.kind === 'type')) {
        const enc = this.enclosing(ctx, n);
        if (enc.id !== d.id) this.references.push({ from: enc.id, to: d.id, site: this.site(ctx, n) });
      }
      return n.type === 'attribute' ? false : undefined;
    }
    return undefined;
  }

  // -- imports and loads ---------------------------------------------------

  importsAndLoads(ctx: FileCtx, modules: string[]): void {
    const self = ctx.ids.decls[0];
    const seen = new Set<string>();
    for (const m of modules) {
      // `import a.b.c` loads a, a.b and a.b.c.
      const parts = m.split('.');
      for (let i = 1; i <= parts.length; i++) {
        const target = this.byModule.get(parts.slice(0, i).join('.'));
        if (!target || target === ctx || seen.has(target.module)) continue;
        seen.add(target.module);
        this.imports.push({ from: self.id, to: target.ids.decls[0].id });
      }
    }
    for (const info of this.classes.values()) {
      if (info.ctx !== ctx) continue;
      for (const m of info.members.values()) {
        if (m.kind === 'method' && DUNDER.test(m.name) && m.name !== '__init__' && m.name !== '__new__') {
          this.loads.push({ from: info.decl.id, to: m.id });
        }
      }
    }
  }

  // -- entries -------------------------------------------------------------

  /** Module-level names assigned from a call to one of `factories` (e.g. `app = Flask(__name__)`). */
  private factoryVars(ctx: FileCtx, factories: Record<string, string>): Map<string, { framework: string; prefix: string; certainty: EntryCertainty }> {
    const out = new Map<string, { framework: string; prefix: string; certainty: EntryCertainty }>();
    for (const s of namedChildren(ctx.root)) {
      if (s.type !== 'expression_statement') continue;
      const a = namedChildren(s)[0];
      if (a?.type !== 'assignment') continue;
      const left = a.childForFieldName('left');
      const right = a.childForFieldName('right');
      if (left?.type !== 'identifier' || right?.type !== 'call') continue;
      const callee = text(right.childForFieldName('function'));
      const short = callee.split('.').pop() ?? callee;
      const framework = factories[short];
      if (!framework) continue;
      const b = ctx.imports.get(callee.split('.')[0]);
      const fromPkg = b ? (b.kind === 'module' ? b.module : b.module).split('.')[0] : '';
      const certainty: EntryCertainty = fromPkg === framework ? 'declared' : 'inferred';
      let prefix = '';
      for (const arg of namedChildren(right.childForFieldName('arguments') ?? right)) {
        if (arg.type === 'keyword_argument' && ['url_prefix', 'prefix'].includes(text(arg.childForFieldName('name')))) {
          prefix = stringValue(arg.childForFieldName('value')) ?? '';
        }
      }
      out.set(left.text, { framework, prefix, certainty });
    }
    return out;
  }

  entriesOf(ctx: FileCtx, options: PythonGraphOptions): void {
    const module = ctx.ids.decls[0];
    const isTestFile = TEST_FILE.test(ctx.path);
    const apps = this.factoryVars(ctx, { Flask: 'flask', Blueprint: 'flask', FastAPI: 'fastapi', APIRouter: 'fastapi', Celery: 'celery' });

    // Decorated definitions.
    walk(ctx.root, n => {
      if (n.type !== 'decorated_definition') return;
      const def = n.childForFieldName('definition');
      const decl = def ? this.declAt(ctx, def) : undefined;
      if (!def || !decl) return;
      const line = n.startPosition.row + 1;
      for (const dec of namedChildren(n).filter(c => c.type === 'decorator')) {
        const expr = namedChildren(dec)[0];
        if (!expr) continue;
        const call = expr.type === 'call' ? expr : null;
        const callee = text(call ? call.childForFieldName('function') : expr).replace(/\s+/g, '');
        const args = call ? namedChildren(call.childForFieldName('arguments') ?? call) : [];
        const recv = callee.includes('.') ? callee.slice(0, callee.lastIndexOf('.')) : '';
        const verb = callee.split('.').pop() ?? '';
        const app = apps.get(recv);
        // Flask / FastAPI routes
        if ((verb === 'route' || HTTP_VERBS.includes(verb) || verb === 'api_route' || verb === 'websocket') && recv) {
          const path = stringValue(args.find(a => a.type === 'string')) ?? stringValue(args.find(a => a.type === 'keyword_argument' && text(a.childForFieldName('name')) === 'path')?.childForFieldName('value'));
          if (path === null || path === undefined) continue;
          const certainty: EntryCertainty = app?.certainty ?? 'inferred';
          const framework = app?.framework ?? (verb === 'route' ? 'flask' : 'fastapi');
          let methods: string[];
          if (verb === 'route' || verb === 'api_route') {
            const m = args.find(a => a.type === 'keyword_argument' && text(a.childForFieldName('name')) === 'methods');
            const list = m?.childForFieldName('value');
            methods = list ? namedChildren(list).map(x => (stringValue(x) ?? '').toUpperCase()).filter(Boolean) : [];
            if (methods.length === 0) methods = [verb === 'route' ? 'GET' : 'ANY'];
          } else methods = [verb === 'websocket' ? 'WS' : verb.toUpperCase()];
          const prefix = app?.prefix ?? '';
          for (const method of methods) {
            const e: TsEntry = { id: decl.id, kind: 'route', certainty, framework, method, path: joinRoutePath([prefix, path]), surface: 'api', file: ctx.path, line, evidence: `@${callee}(${JSON.stringify(path)})` };
            if (prefix) { e.registeredPath = path; e.mounts = [prefix]; }
            this.entry(e);
          }
          continue;
        }
        // FastAPI / Flask lifecycle hooks
        if (recv && ['on_event', 'middleware', 'exception_handler', 'before_request', 'after_request', 'errorhandler', 'teardown_request', 'teardown_appcontext', 'context_processor', 'before_app_request'].includes(verb)) {
          this.entry({ id: decl.id, kind: 'lifecycle', certainty: app?.certainty ?? 'inferred', framework: app?.framework, file: ctx.path, line, evidence: `@${callee}` });
          continue;
        }
        // click
        if (['command', 'group'].includes(verb) && (recv === 'click' || recv !== '' )) {
          const b = ctx.imports.get('click');
          const declared = recv === 'click' ? (b ? 'declared' : 'inferred') : 'inferred';
          this.entry({ id: decl.id, kind: 'main', certainty: declared as EntryCertainty, framework: 'click', file: ctx.path, line, evidence: `@${callee}` });
          continue;
        }
        // Celery tasks
        if (verb === 'task' || callee === 'shared_task' || callee === 'celery.shared_task') {
          this.entry({ id: decl.id, kind: 'listener', certainty: app?.framework === 'celery' || callee.endsWith('shared_task') ? 'declared' : 'inferred', framework: 'celery', file: ctx.path, line, evidence: `@${callee}` });
          continue;
        }
        // pytest fixtures
        if (callee === 'pytest.fixture' || callee === 'fixture') {
          this.entry({ id: decl.id, kind: 'test', certainty: 'declared', framework: 'pytest', file: ctx.path, line, evidence: `@${callee}` });
          continue;
        }
        // typing.overload stubs
        if (callee === 'overload' || callee === 'typing.overload') this.typeOnly.add(decl.id);
      }
      return undefined;
    });

    // `if __name__ == "__main__":` — the module is a program.
    for (const s of namedChildren(ctx.root)) {
      if (s.type !== 'if_statement') continue;
      const cond = s.childForFieldName('condition')?.text.replace(/\s+/g, '').replace(/'/g, '"') ?? '';
      if (cond === '__name__=="__main__"' || cond === '"__main__"==__name__') {
        this.entry({ id: module.id, kind: 'main', certainty: 'conventional', file: ctx.path, line: s.startPosition.row + 1, evidence: 'if __name__ == "__main__"' });
      }
    }
    if ((options.mainFiles ?? []).includes(ctx.path) || /(^|\/)__main__\.py$/.test(ctx.path)) {
      this.entry({ id: module.id, kind: 'main', certainty: 'conventional', file: ctx.path, line: 1, evidence: 'program file' });
    }

    // Classes: tests, Django management commands and class-based views, Protocols.
    for (const info of this.classes.values()) {
      if (info.ctx !== ctx) continue;
      const bases = new Set(info.bases.map(b => b.split('.').pop() ?? b));
      const allBases = this.allBaseNames(info);
      if (bases.has('Protocol')) {
        this.typeOnly.add(info.decl.id);
        for (const m of info.members.values()) this.typeOnly.add(m.id);
      }
      const isTestCase = [...allBases].some(b => TEST_CASE_BASES.has(b));
      const isPytestClass = isTestFile && /^Test/.test(info.decl.name);
      if (isTestCase || isPytestClass) {
        for (const m of info.members.values()) {
          if (m.kind === 'method' && (/^test/.test(m.name) || TEST_LIFECYCLE.has(m.name))) {
            this.entry({ id: m.id, kind: 'test', certainty: isTestCase ? 'declared' : 'conventional', framework: isTestCase ? 'unittest' : 'pytest', file: ctx.path, line: m.start_line, evidence: `${info.decl.name}.${m.name}` });
          }
        }
      }
      if (allBases.has('BaseCommand') && /(^|\/)management\/commands\/[^/]+\.py$/.test(ctx.path)) {
        const handle = info.members.get('handle');
        this.entry({ id: info.decl.id, kind: 'reflection', certainty: 'declared', framework: 'django', file: ctx.path, line: info.decl.start_line, evidence: 'management command class' });
        this.entry({ id: (handle ?? info.decl).id, kind: 'main', certainty: 'declared', framework: 'django', file: ctx.path, line: (handle ?? info.decl).start_line, evidence: 'management command' });
        const args = info.members.get('add_arguments');
        if (args) this.entry({ id: args.id, kind: 'lifecycle', certainty: 'declared', framework: 'django', file: ctx.path, line: args.start_line, evidence: 'management command add_arguments' });
      }
    }

    // pytest functions in test files.
    if (isTestFile) {
      this.entry({ id: module.id, kind: 'test', certainty: 'conventional', framework: 'pytest', file: ctx.path, line: 1, evidence: 'test file' });
      for (const d of ctx.top.values()) {
        if (d.kind === 'function' && /^test/.test(d.name)) {
          this.entry({ id: d.id, kind: 'test', certainty: 'conventional', framework: 'pytest', file: ctx.path, line: d.start_line, evidence: `test function ${d.name}` });
        }
      }
    }

    // Django urls.py, and the modules Django loads by convention.
    if (/(^|\/)urls\.py$/.test(ctx.path)) this.djangoUrls(ctx);
    const usesDjango = [...ctx.imports.values()].some(b => b.module === 'django' || b.module.startsWith('django.'));
    const conventional = /(^|\/)(urls|admin|apps|models|signals|settings|wsgi|asgi|tasks)\.py$/.exec(ctx.path);
    if (usesDjango && conventional) {
      this.entry({ id: module.id, kind: 'reflection', certainty: 'conventional', framework: 'django', file: ctx.path, line: 1, evidence: `${conventional[2]}.py loaded by Django` });
    }

    // .pyi stubs are type-only.
    if (ctx.path.endsWith('.pyi')) for (const d of ctx.ids.decls.slice(1)) this.typeOnly.add(d.id);
  }

  private allBaseNames(info: ClassInfo): Set<string> {
    const out = new Set<string>();
    const queue = [info];
    const seen = new Set<string>();
    while (queue.length > 0) {
      const c = queue.shift()!;
      if (seen.has(c.decl.id)) continue;
      seen.add(c.decl.id);
      for (const b of c.bases) {
        out.add(b);
        out.add(b.split('.').pop() ?? b);
      }
      queue.push(...c.parents);
    }
    return out;
  }

  private djangoUrls(ctx: FileCtx): void {
    walk(ctx.root, n => {
      if (n.type !== 'call') return;
      const callee = text(n.childForFieldName('function'));
      if (!['path', 're_path', 'url', 'django.urls.path', 'django.urls.re_path'].includes(callee)) return;
      const args = namedChildren(n.childForFieldName('arguments') ?? n).filter(a => a.type !== 'comment');
      const route = stringValue(args[0]);
      const view = args[1];
      if (route === null || route === undefined || !view) return false;
      const site = this.site(ctx, n);
      const path = '/' + route.replace(/^\^/, '').replace(/\$$/, '');
      if (view.type === 'call' && text(view.childForFieldName('function')) === 'include') return false;
      let target = view;
      let cbv = false;
      if (view.type === 'call') {
        const fn = view.childForFieldName('function');
        if (fn?.type === 'attribute' && text(fn.childForFieldName('attribute')) === 'as_view') {
          target = fn.childForFieldName('object') ?? view;
          cbv = true;
        }
      }
      const written = target.text.replace(/\s+/g, '');
      const d = /^[A-Za-z_][\w.]*$/.test(written) ? this.resolveName(ctx, written) : null;
      if (!d) {
        this.unresolvedRegistrations.push({ site, reason: 'handler-unresolved', evidence: `${callee}(${JSON.stringify(route)}, ${written})` });
        return false;
      }
      this.entry({ id: d.id, kind: 'route', certainty: 'declared', framework: 'django', method: 'ANY', path, surface: 'api', file: ctx.path, line: site.line, evidence: `${callee}(${JSON.stringify(route)}, ${written})` });
      if (cbv || d.kind === 'type') {
        const info = this.classes.get(d.id);
        const seen = new Set<string>();
        const queue = info ? [info] : [];
        while (queue.length > 0) {
          const c = queue.shift()!;
          if (seen.has(c.decl.id)) continue;
          seen.add(c.decl.id);
          for (const m of c.members.values()) {
            if (m.kind === 'method' && DJANGO_CBV_METHODS.has(m.name)) {
              this.entry({ id: m.id, kind: 'route', certainty: 'declared', framework: 'django', method: HTTP_VERBS.includes(m.name) ? m.name.toUpperCase() : 'ANY', path, surface: 'api', file: ctx.path, line: site.line, evidence: `${written}.as_view() → ${m.name}` });
            }
          }
          queue.push(...c.parents);
        }
      }
      return false;
    });
  }

  consoleScripts(scripts: readonly string[]): void {
    for (const s of scripts) {
      const [mod, fn] = s.split(':');
      const ctx = mod ? this.byModule.get(mod.trim()) : undefined;
      const d = ctx && fn ? ctx.top.get(fn.trim()) : ctx?.ids.decls[0];
      if (!ctx || !d) {
        this.unresolvedRegistrations.push({ site: { file: '', line: 0, col: 0 }, reason: 'manifest-unresolved', evidence: `console script ${s}` });
        continue;
      }
      this.entry({ id: d.id, kind: 'main', certainty: 'declared', framework: 'console_scripts', file: ctx.path, line: d.start_line, evidence: `console script ${s}` });
    }
  }
}

/**
 * Build the Python graph facts for a set of files. Each file is parsed once;
 * nothing is read from disk.
 */
export async function buildPythonGraph(files: readonly PythonSourceFile[], options: PythonGraphOptions = {}): Promise<PythonGraph> {
  const b = new PyGraphBuilder(options.maxInferred ?? 16);
  const trees: { tree: Awaited<ReturnType<typeof parse>>; modules: string[]; ctx: FileCtx }[] = [];
  const partial: string[] = [];
  const sorted = [...files].sort((x, y) => (x.path < y.path ? -1 : x.path > y.path ? 1 : 0));
  try {
    for (const f of sorted) {
      const tree = await parse(f.code, 'python');
      const module = f.module ?? pythonModuleName(f.path);
      const ids = derivePythonIds(tree, f.path, { module });
      if (ids.partial) partial.push(f.path);
      const isPackage = /(^|\/)__init__\.pyi?$/.test(f.path);
      const { bindings, modules } = importsOf(tree.rootNode, module, isPackage);
      const top = new Map<string, StableDecl>();
      const moduleDecl = ids.decls[0];
      for (const d of ids.decls) if (d.parent === moduleDecl?.id && !d.flags.includes('unstable:anonymous')) top.set(d.name, d);
      const byLine = new Map<string, StableDecl>();
      for (const d of ids.decls) byLine.set(posKey(d.start_line, d.start_column), d);
      const ctx: FileCtx = { path: f.path, module, ids, root: tree.rootNode, top, imports: bindings, external: new Set(), locate: declLocator(ids), byLine };
      b.add(ctx);
      trees.push({ tree, modules, ctx });
    }
    b.index();
    for (const t of trees) {
      b.calls(t.ctx);
      b.importsAndLoads(t.ctx, t.modules);
      b.entriesOf(t.ctx, options);
    }
    b.consoleScripts(options.consoleScripts ?? []);
  } finally {
    for (const t of trees) disposeTree(t.tree);
  }
  return {
    scheme: PYTHON_GRAPH_SCHEME,
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

export type { EntryKind };
