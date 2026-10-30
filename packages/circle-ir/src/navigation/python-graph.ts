/**
 * Python graph facts keyed by stable ids (`python-graph@0.1`): the reach
 * core's input for Python.
 *
 * Every `call` becomes an edge from the enclosing declaration to what can
 * run, with the navigation tiers, or an unresolved site with a reason:
 *
 * - `exact` — bound through function scope, a module-level name, an import
 *   (absolute or relative, followed through re-exports in `__init__`), a
 *   module alias, a class name, `super()`, or a receiver whose class is
 *   known (`self`/`cls`, a parameter annotation, `x = C(...)`, an attribute
 *   assigned or annotated on the class) with no override in the tree. A
 *   class called is its `__init__` (or the class, when it declares none).
 * - `polymorphic` — the receiver's class is known and a subclass overrides
 *   the method; one edge per body.
 * - `inferred` — a method call on a receiver of unknown class, bound by name
 *   alone (bounded).
 *
 * Also: value references (a function or class passed, stored or returned),
 * class-to-property `loads` (an attribute access runs a property), entries
 * (`entry-index@0.1`: Flask and FastAPI routes with blueprint/router
 * prefixes and mounts, Django `path()` views, Click/Typer commands, Celery
 * tasks, pytest and unittest tests and fixtures, `if __name__ ==
 * "__main__"`, `pyproject.toml` scripts, caller-given export roots), and
 * `partial[]`. Dunder methods run implicitly; the reach core treats them as
 * part of their class.
 */

import { disposeTree, parse, type Node, type Tree } from '../core/parser.js';
import { declLocator } from '../stable-ids/nodes.js';
import { namedChildren } from '../stable-ids/normalize.js';
import { derivePythonIds, pythonModuleName } from '../stable-ids/python.js';
import type { StableDecl, StableIdFile } from '../stable-ids/types.js';
import { DEFAULT_PYTHON_ENTRY_TABLES, type PythonEntryTables, type PythonRouterRow } from './python-entry-tables.js';
import type { EntryCertainty, EntryKind } from './ts-entry-tables.js';
import { joinRoutePath, type CallEdge, type CallEdgeSite, type ReferenceEdge, type TsEntry, type UnresolvedCall, type UnresolvedRegistration } from './ts-call-edges.js';
import type { Tier, UnresolvedReason } from './types.js';

export const PYTHON_GRAPH_SCHEME = 'python-graph@0.1' as const;

export interface PythonSourceFile {
  path: string;
  code: string;
  /** The dotted module name; derived from the path when absent. */
  module?: string;
}

export interface PythonGraphOptions {
  /** `pyproject.toml` text: `[project.scripts]` / `[tool.poetry.scripts]` targets are `main` entries. */
  pyprojectToml?: string;
  /** Files whose public names (or `__all__`) are `export` entries. */
  exportRoots?: readonly string[];
  /** Most `inferred` edges one site may carry. Default 16. */
  maxInferred?: number;
  entryTables?: PythonEntryTables;
}

export interface PythonGraph {
  scheme: typeof PYTHON_GRAPH_SCHEME;
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
  sites: number;
}

type Binding =
  | { kind: 'module'; module: string; external: boolean }
  | { kind: 'name'; module: string; name: string; external: boolean };

interface FileCtx {
  path: string;
  module: string;
  /** The package relative imports resolve against. */
  pkg: string;
  ids: StableIdFile;
  root: Node;
  top: Map<string, StableDecl[]>;
  /** Module-level assignments by name (their `assignment` node). */
  topVars: Map<string, Node>;
  imports: Map<string, Binding>;
  locate: (line: number, column?: number) => StableDecl | null;
  byStart: Map<string, StableDecl>;
}

type Target =
  | { kind: 'decls'; decls: StableDecl[]; ctx: FileCtx }
  | { kind: 'module'; ctx: FileCtx }
  | { kind: 'external' }
  | { kind: 'none' };

const DEF_NODES = new Set(['function_definition', 'lambda']);

function str(node: Node | null | undefined): string | null {
  if (!node || node.type !== 'string') return null;
  return namedChildren(node).filter(c => c.type === 'string_content').map(c => c.text).join('');
}

function posKey(node: Node): string {
  return `${node.startPosition.row + 1}:${node.startPosition.column}`;
}

function holderOf(def: Node): Node {
  return def.parent?.type === 'decorated_definition' ? def.parent : def;
}

/** Names bound by a parameter or target pattern. */
function patternNames(node: Node | null, out: string[] = []): string[] {
  if (!node) return out;
  if (node.type === 'identifier') {
    out.push(node.text);
    return out;
  }
  if (node.type === 'typed_parameter') {
    patternNames(namedChildren(node)[0] ?? null, out);
    return out;
  }
  if (node.type === 'default_parameter' || node.type === 'typed_default_parameter') return patternNames(node.childForFieldName('name'), out);
  if (node.type === 'attribute' || node.type === 'subscript') return out;
  for (const c of namedChildren(node)) patternNames(c, out);
  return out;
}

interface Scope {
  params: Map<string, Node>;
  vars: Map<string, Node[]>;
  defs: Map<string, Node>;
}

class PythonGraphBuilder {
  readonly edges: CallEdge[] = [];
  readonly unresolved: UnresolvedCall[] = [];
  readonly references: ReferenceEdge[] = [];
  readonly loads: { from: string; to: string }[] = [];
  readonly entries: TsEntry[] = [];
  readonly unresolvedRegistrations: UnresolvedRegistration[] = [];
  readonly typeOnly = new Set<string>();
  private sites = 0;
  private readonly modules = new Map<string, FileCtx>();
  private readonly classNodes = new Map<string, { node: Node; ctx: FileCtx }>();
  private readonly bases = new Map<string, (StableDecl | 'external')[]>();
  private readonly subs = new Map<string, StableDecl[]>();
  private readonly methodsByName = new Map<string, StableDecl[]>();
  private readonly scopes = new Map<number, Scope>();
  private readonly routes: { decl: StableDecl; certainty: EntryCertainty; framework?: string; method: string; path: string; file: string; line: number; router?: string }[] = [];
  private readonly routers = new Map<string, { prefix: string }>();
  private readonly mounts: { parent: string; child: string; prefix: string }[] = [];

  constructor(readonly files: FileCtx[], private readonly tables: PythonEntryTables, private readonly options: PythonGraphOptions) {
    for (const f of files) this.modules.set(f.module, f);
  }

  get siteCount(): number {
    return this.sites;
  }

  // -- loading ---------------------------------------------------------------

  link(): void {
    for (const ctx of this.files) this.scanModule(ctx);
    for (const ctx of this.files) this.scanClasses(ctx);
    // A member's class exists before the member runs.
    for (const f of this.files) {
      const types = new Set(f.ids.decls.filter(d => d.kind === 'type').map(d => d.id));
      for (const d of f.ids.decls) if (d.parent !== null && types.has(d.parent) && d.kind !== 'type') this.loads.push({ from: d.id, to: d.parent });
    }
    for (const [id, bases] of this.bases) {
      const self = this.declById(id);
      if (!self) continue;
      for (const b of bases) if (b !== 'external') this.subs.set(b.id, [...(this.subs.get(b.id) ?? []), self]);
    }
  }

  private readonly idIndex = new Map<string, StableDecl>();
  private declById(id: string): StableDecl | undefined {
    if (this.idIndex.size === 0) for (const f of this.files) for (const d of f.ids.decls) this.idIndex.set(d.id, d);
    return this.idIndex.get(id);
  }

  private resolveModuleName(ctx: FileCtx, dotted: string, relative: number): string {
    if (relative === 0) return dotted;
    const parts = ctx.pkg === '' ? [] : ctx.pkg.split('.');
    const base = parts.slice(0, Math.max(0, parts.length - (relative - 1)));
    return [...base, ...(dotted ? [dotted] : [])].join('.');
  }

  private scanModule(ctx: FileCtx): void {
    for (const d of ctx.ids.decls) {
      ctx.byStart.set(`${d.start_line}:${d.start_column}`, d);
      if (d.parent === ctx.ids.decls[0].id) ctx.top.set(d.name, [...(ctx.top.get(d.name) ?? []), d]);
      if (d.kind === 'method') this.methodsByName.set(d.name, [...(this.methodsByName.get(d.name) ?? []), d]);
    }
    for (const stmt of namedChildren(ctx.root)) {
      if (stmt.type === 'import_statement') {
        for (const n of namedChildren(stmt)) {
          const dotted = n.type === 'aliased_import' ? n.childForFieldName('name')?.text ?? '' : n.text;
          const alias = n.type === 'aliased_import' ? n.childForFieldName('alias')?.text : dotted.split('.')[0];
          if (!alias) continue;
          const module = n.type === 'aliased_import' ? dotted : dotted.split('.')[0];
          ctx.imports.set(alias, { kind: 'module', module, external: !this.knownModule(module) });
        }
      } else if (stmt.type === 'import_from_statement') {
        const mod = stmt.childForFieldName('module_name');
        let relative = 0;
        let dotted = mod?.text ?? '';
        if (mod?.type === 'relative_import') {
          relative = (namedChildren(mod).find(c => c.type === 'import_prefix')?.text ?? '').length;
          dotted = namedChildren(mod).find(c => c.type === 'dotted_name')?.text ?? '';
        }
        const module = this.resolveModuleName(ctx, dotted, relative);
        for (const n of namedChildren(stmt)) {
          if (n === mod || n.type === 'wildcard_import') continue;
          const name = n.type === 'aliased_import' ? n.childForFieldName('name')?.text : n.text;
          const alias = n.type === 'aliased_import' ? n.childForFieldName('alias')?.text : name;
          if (!name || !alias) continue;
          const sub = `${module}.${name}`;
          if (this.modules.has(sub)) ctx.imports.set(alias, { kind: 'module', module: sub, external: false });
          else ctx.imports.set(alias, { kind: 'name', module, name, external: !this.knownModule(module) });
        }
      } else if (stmt.type === 'expression_statement') {
        const a = namedChildren(stmt)[0];
        const left = a?.type === 'assignment' ? a.childForFieldName('left') : null;
        if (left?.type === 'identifier' && a) ctx.topVars.set(left.text, a);
      }
    }
  }

  private knownModule(module: string): boolean {
    return this.modules.has(module);
  }

  private scanClasses(ctx: FileCtx): void {
    const visit = (node: Node): void => {
      if (node.type === 'class_definition') {
        const decl = ctx.byStart.get(posKey(holderOf(node)));
        if (decl?.kind === 'type') {
          this.classNodes.set(decl.id, { node, ctx });
          const supers = node.childForFieldName('superclasses');
          const bases: (StableDecl | 'external')[] = [];
          for (const s of supers ? namedChildren(supers) : []) {
            if (s.type === 'keyword_argument') continue;
            const t = this.resolveExpr(ctx, s);
            const type = t.kind === 'decls' ? t.decls.find(d => d.kind === 'type') : undefined;
            if (type) bases.push(type);
            else if (s.text !== 'object') bases.push('external');
            if (/(^|\.)Protocol$/.test(s.text)) this.typeOnly.add(decl.id);
          }
          this.bases.set(decl.id, bases);
          // An attribute access runs a property.
          const body = node.childForFieldName('body');
          for (const s of body ? namedChildren(body) : []) {
            if (s.type !== 'decorated_definition') continue;
            const isProperty = namedChildren(s).some(d => d.type === 'decorator' && /^@?\s*(?:\w+\.)*(?:property|cached_property|setter|getter|deleter)\b/.test(d.text.replace(/^@/, '')));
            const m = ctx.byStart.get(posKey(s));
            if (isProperty && m) this.loads.push({ from: decl.id, to: m.id });
          }
        }
      }
      for (const c of namedChildren(node)) visit(c);
    };
    visit(ctx.root);
  }

  // -- names -----------------------------------------------------------------

  private resolveName(ctx: FileCtx, name: string, depth = 0): Target {
    if (depth > 8) return { kind: 'none' };
    const decls = ctx.top.get(name);
    if (decls) return { kind: 'decls', decls, ctx };
    const imp = ctx.imports.get(name);
    if (!imp) return { kind: 'none' };
    if (imp.external) return { kind: 'external' };
    const target = this.modules.get(imp.module);
    if (!target) return { kind: 'external' };
    if (imp.kind === 'module') return { kind: 'module', ctx: target };
    return this.resolveName(target, imp.name, depth + 1);
  }

  /** An identifier or dotted attribute chain that names something at module level. */
  private resolveExpr(ctx: FileCtx, node: Node): Target {
    if (node.type === 'identifier') return this.localScopeHas(node, node.text) ? { kind: 'none' } : this.resolveName(ctx, node.text);
    if (node.type === 'attribute') {
      const object = node.childForFieldName('object');
      const attr = node.childForFieldName('attribute')?.text;
      if (!object || !attr) return { kind: 'none' };
      const base = this.resolveExpr(ctx, object);
      if (base.kind === 'module') {
        const sub = this.modules.get(`${base.ctx.module}.${attr}`);
        return sub ? { kind: 'module', ctx: sub } : this.resolveName(base.ctx, attr);
      }
      if (base.kind === 'external') return base;
      return { kind: 'none' };
    }
    return { kind: 'none' };
  }

  // -- function scope --------------------------------------------------------

  private scopeOf(fn: Node): Scope {
    const cached = this.scopes.get(fn.id);
    if (cached) return cached;
    const scope: Scope = { params: new Map(), vars: new Map(), defs: new Map() };
    const params = fn.childForFieldName('parameters');
    for (const p of params ? namedChildren(params) : []) for (const n of patternNames(p)) scope.params.set(n, p);
    const walk = (node: Node): void => {
      for (const c of namedChildren(node)) {
        if (c.type === 'function_definition' || c.type === 'class_definition') {
          const n = c.childForFieldName('name')?.text;
          if (n) scope.defs.set(n, c);
          continue;
        }
        if (c.type === 'lambda') continue;
        if (c.type === 'assignment' || c.type === 'augmented_assignment') {
          for (const n of patternNames(c.childForFieldName('left'))) scope.vars.set(n, [...(scope.vars.get(n) ?? []), c]);
        } else if (c.type === 'for_statement' || c.type === 'for_in_clause') {
          for (const n of patternNames(c.childForFieldName('left'))) scope.vars.set(n, [...(scope.vars.get(n) ?? []), c]);
        } else if (c.type === 'as_pattern' || c.type === 'with_item') {
          const alias = c.childForFieldName('alias') ?? namedChildren(c).find(x => x.type === 'as_pattern_target');
          for (const n of patternNames(alias ?? null)) scope.vars.set(n, [...(scope.vars.get(n) ?? []), c]);
        } else if (c.type === 'except_clause') {
          const ids = namedChildren(c).filter(x => x.type === 'identifier');
          if (ids.length > 1) scope.vars.set(ids[ids.length - 1].text, [c]);
        }
        walk(c);
      }
    };
    const body = fn.childForFieldName('body');
    if (body) walk(fn.type === 'lambda' ? fn : body);
    this.scopes.set(fn.id, scope);
    return scope;
  }

  /** The nearest function scope binding `name`, innermost first. */
  private localBinding(start: Node, name: string): { kind: 'param' | 'var' | 'def'; node: Node; fn: Node } | null {
    for (let n: Node | null = start.parent; n && n.type !== 'module'; n = n.parent) {
      if (!DEF_NODES.has(n.type)) continue;
      const s = this.scopeOf(n);
      const p = s.params.get(name);
      if (p) return { kind: 'param', node: p, fn: n };
      const d = s.defs.get(name);
      if (d) return { kind: 'def', node: d, fn: n };
      const v = s.vars.get(name);
      if (v) return { kind: 'var', node: v[v.length - 1], fn: n };
    }
    return null;
  }

  private localScopeHas(node: Node, name: string): boolean {
    return this.localBinding(node, name) !== null;
  }

  private enclosingFunction(node: Node): Node | null {
    for (let n: Node | null = node.parent; n; n = n.parent) if (n.type === 'function_definition') return n;
    return null;
  }

  /** The class whose method `node` is in, when `node`'s function is a method. */
  private enclosingClass(ctx: FileCtx, node: Node): StableDecl | null {
    const fn = this.enclosingFunction(node);
    const holder = fn ? holderOf(fn) : null;
    const cls = holder?.parent?.type === 'block' ? holder.parent.parent : null;
    if (cls?.type !== 'class_definition') return null;
    const d = ctx.byStart.get(posKey(holderOf(cls)));
    return d?.kind === 'type' ? d : null;
  }

  /** `self` / `cls`: the first parameter of a method. */
  private isSelf(node: Node): boolean {
    if (node.type !== 'identifier') return false;
    const fn = this.enclosingFunction(node);
    const params = fn?.childForFieldName('parameters');
    const first = params ? namedChildren(params)[0] : undefined;
    const holder = fn ? holderOf(fn) : null;
    const isStatic = holder?.type === 'decorated_definition' && /@staticmethod\b/.test(holder.text.split('\n')[0] + (namedChildren(holder).filter(c => c.type === 'decorator').map(c => c.text).join(' ')));
    return !isStatic && first !== undefined && patternNames(first)[0] === node.text && holder?.parent?.parent?.type === 'class_definition';
  }

  // -- types -----------------------------------------------------------------

  private classFromExpr(ctx: FileCtx, node: Node | null): StableDecl | 'external' | null {
    if (!node) return null;
    if (node.type === 'type') return this.classFromExpr(ctx, namedChildren(node)[0] ?? null);
    if (node.type === 'string') {
      const t = str(node);
      return t ? this.classFromName(ctx, t) : null;
    }
    if (node.type === 'generic_type' || node.type === 'subscript') return null;
    const t = this.resolveExpr(ctx, node);
    if (t.kind === 'decls') return t.decls.find(d => d.kind === 'type') ?? null;
    return t.kind === 'external' ? 'external' : null;
  }

  private classFromName(ctx: FileCtx, name: string): StableDecl | 'external' | null {
    const t = this.resolveName(ctx, name);
    if (t.kind === 'decls') return t.decls.find(d => d.kind === 'type') ?? null;
    return t.kind === 'external' ? 'external' : null;
  }

  /** The class an assignment's value constructs (`C(...)`). */
  private classOfValue(ctx: FileCtx, value: Node | null): StableDecl | 'external' | null {
    if (value?.type !== 'call') return null;
    return this.classFromExpr(ctx, value.childForFieldName('function'));
  }

  private typeOf(ctx: FileCtx, expr: Node): StableDecl | 'external' | null {
    if (expr.type === 'identifier') {
      if (this.isSelf(expr)) return this.enclosingClass(ctx, expr);
      const b = this.localBinding(expr, expr.text);
      if (b?.kind === 'param') return this.classFromExpr(ctx, b.node.childForFieldName('type'));
      if (b?.kind === 'var') {
        const a = b.node.type === 'assignment' ? b.node : null;
        return a ? this.classFromExpr(ctx, a.childForFieldName('type')) ?? this.classOfValue(ctx, a.childForFieldName('right')) : null;
      }
      if (b) return null;
      const top = ctx.topVars.get(expr.text);
      return top ? this.classFromExpr(ctx, top.childForFieldName('type')) ?? this.classOfValue(ctx, top.childForFieldName('right')) : null;
    }
    if (expr.type === 'call') {
      return this.classOfValue(ctx, expr);
    }
    if (expr.type === 'attribute') {
      const object = expr.childForFieldName('object');
      const attr = expr.childForFieldName('attribute')?.text;
      if (object && attr && this.isSelf(object)) {
        const cls = this.enclosingClass(ctx, expr);
        return cls ? this.attributeType(cls, attr) : null;
      }
    }
    return null;
  }

  /** The class of `self.<attr>`: a class-level annotation, or an assignment in a method. */
  private attributeType(cls: StableDecl, attr: string, seen = new Set<string>()): StableDecl | 'external' | null {
    if (seen.has(cls.id)) return null;
    seen.add(cls.id);
    const entry = this.classNodes.get(cls.id);
    if (!entry) return null;
    const { node, ctx } = entry;
    let found: StableDecl | 'external' | null = null;
    const visit = (n: Node): void => {
      if (found) return;
      if (n.type === 'assignment') {
        const left = n.childForFieldName('left');
        const isClassLevel = left?.type === 'identifier' && left.text === attr && n.parent?.parent?.parent === node;
        const isSelfAttr = left?.type === 'attribute' && left.childForFieldName('attribute')?.text === attr && this.isSelf(left.childForFieldName('object') as Node);
        if (isClassLevel || isSelfAttr) {
          found = this.classFromExpr(ctx, n.childForFieldName('type')) ?? this.classOfValue(ctx, n.childForFieldName('right'));
          const right = n.childForFieldName('right');
          if (!found && right?.type === 'identifier') {
            const b = this.localBinding(right, right.text);
            if (b?.kind === 'param') found = this.classFromExpr(ctx, b.node.childForFieldName('type'));
          }
          if (found) return;
        }
      }
      for (const c of namedChildren(n)) visit(c);
    };
    visit(node);
    if (found) return found;
    for (const b of this.bases.get(cls.id) ?? []) {
      if (b === 'external') continue;
      const t = this.attributeType(b, attr, seen);
      if (t) return t;
    }
    return null;
  }

  // -- members ---------------------------------------------------------------

  private membersOf(type: StableDecl, name: string): StableDecl[] {
    return (this.methodsByName.get(name) ?? []).filter(d => d.parent === type.id);
  }

  /** Method resolution order, depth-first left to right (enough without diamonds). */
  private findMember(type: StableDecl, name: string, seen = new Set<string>()): { decl: StableDecl; owner: StableDecl } | 'external' | null {
    if (seen.has(type.id)) return null;
    seen.add(type.id);
    const own = this.membersOf(type, name);
    if (own.length > 0) return { decl: own[own.length - 1], owner: type };
    let external = false;
    for (const b of this.bases.get(type.id) ?? []) {
      if (b === 'external') {
        external = true;
        continue;
      }
      const r = this.findMember(b, name, seen);
      if (r && r !== 'external') return r;
      if (r === 'external') external = true;
    }
    return external ? 'external' : null;
  }

  private overrides(type: StableDecl, name: string): StableDecl[] {
    const out = new Map<string, StableDecl>();
    const walk = (t: StableDecl, seen: Set<string>): void => {
      for (const s of this.subs.get(t.id) ?? []) {
        if (seen.has(s.id)) continue;
        seen.add(s.id);
        for (const m of this.membersOf(s, name)) out.set(m.id, m);
        walk(s, seen);
      }
    };
    walk(type, new Set([type.id]));
    return [...out.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
  }

  // -- sites -----------------------------------------------------------------

  run(): void {
    for (const ctx of this.files) this.walk(ctx, ctx.root);
    this.composeRoutes();
  }

  private walk(ctx: FileCtx, node: Node): void {
    const t = node.type;
    if (t === 'call') {
      this.site(ctx, node);
      this.urlConf(ctx, node);
      this.mount(ctx, node);
      const args = node.childForFieldName('arguments');
      for (const a of args ? namedChildren(args) : []) this.reference(ctx, a.type === 'keyword_argument' ? a.childForFieldName('value') : a);
    } else if (t === 'list' || t === 'tuple' || t === 'set') for (const c of namedChildren(node)) this.reference(ctx, c);
    else if (t === 'pair') this.reference(ctx, node.childForFieldName('value'));
    else if (t === 'return_statement') this.reference(ctx, namedChildren(node)[0] ?? null);
    else if (t === 'assignment') this.reference(ctx, node.childForFieldName('right'));
    else if (t === 'decorated_definition') this.decorated(ctx, node);
    else if (t === 'if_statement') this.mainGuard(ctx, node);
    for (const c of namedChildren(node)) this.walk(ctx, c);
  }

  private site(ctx: FileCtx, node: Node): void {
    const fn = node.childForFieldName('function');
    if (!fn) return;
    this.sites++;
    const site: CallEdgeSite = { file: ctx.path, line: node.startPosition.row + 1, col: node.startPosition.column };
    const from = (ctx.locate(site.line, site.col) ?? ctx.ids.decls[0]).id;
    const edge = (to: StableDecl, tier: Tier, name: string, evidence: string, via?: StableDecl): void => {
      const e: CallEdge = { from, to: to.id, tier, methodName: name, site, evidence };
      if (via) e.via = via.id;
      this.edges.push(e);
    };
    const unresolved = (name: string, reason: UnresolvedReason, evidence: string): void => {
      this.unresolved.push({ from, methodName: name, site, reason, evidence });
    };
    if (fn.type === 'identifier') {
      const name = fn.text;
      const b = this.localBinding(fn, name);
      if (b) {
        const def = b.kind === 'def' ? b.node : b.kind === 'var' && b.node.childForFieldName('right')?.type === 'lambda' ? b.node.childForFieldName('right') : null;
        const d = def ? ctx.byStart.get(posKey(holderOf(def))) : undefined;
        if (d) {
          const target = d.kind === 'type' ? this.membersOf(d, '__init__').at(-1) ?? d : d;
          edge(target, 'exact', name, 'function scope');
        } else unresolved(name, 'dynamic', b.kind === 'param' ? 'callee is a parameter' : 'callee is a local value');
        return;
      }
      this.bind(this.resolveName(ctx, name), name, edge, unresolved);
      return;
    }
    if (fn.type === 'attribute') {
      const object = fn.childForFieldName('object');
      const name = fn.childForFieldName('attribute')?.text ?? '';
      if (!object) return;
      // super().m()
      if (object.type === 'call' && object.childForFieldName('function')?.text === 'super') {
        const cls = this.enclosingClass(ctx, node);
        const bases = cls ? this.bases.get(cls.id) ?? [] : [];
        for (const b of bases) {
          if (b === 'external') continue;
          const r = this.findMember(b, name);
          if (r && r !== 'external') {
            edge(r.decl, 'exact', name, 'super()');
            return;
          }
        }
        unresolved(name, bases.includes('external') ? 'external' : 'unknown', 'super() member not in the tree');
        return;
      }
      if (!this.isSelf(object)) {
        const t = this.resolveExpr(ctx, object);
        if (t.kind === 'module') {
          const m = this.resolveName(t.ctx, name);
          if (m.kind === 'none') unresolved(name, 'unknown', 'not defined by a module in the tree');
          else this.bind(m, name, edge, unresolved);
          return;
        }
        if (t.kind === 'external') {
          unresolved(name, 'external', 'receiver from outside the tree');
          return;
        }
        if (t.kind === 'decls') {
          const type = t.decls.find(d => d.kind === 'type');
          if (type) {
            const r = this.findMember(type, name);
            if (r && r !== 'external') edge(r.decl, 'exact', name, 'class attribute');
            else unresolved(name, r === 'external' ? 'external' : 'unknown', 'class attribute not found');
            return;
          }
        }
        if (object.type === 'identifier' && t.kind === 'none' && !this.localBinding(object, object.text) && !ctx.topVars.has(object.text) && !ctx.top.has(object.text)) {
          unresolved(name, 'external', 'receiver not declared in the tree (builtin)');
          return;
        }
      }
      const type = this.typeOf(ctx, object);
      if (type === 'external') {
        unresolved(name, 'external', 'receiver class from outside the tree');
        return;
      }
      if (type) {
        const r = this.findMember(type, name);
        if (r === 'external') unresolved(name, 'external', 'member inherited from outside the tree');
        else if (!r) unresolved(name, 'unknown', 'member not found on the receiver class');
        else {
          const subs = this.overrides(r.owner, name);
          if (subs.length === 0) edge(r.decl, 'exact', name, 'receiver class known; no override in the tree');
          else for (const b of [r.decl, ...subs]) edge(b, 'polymorphic', name, 'receiver class known; overridden', r.decl);
        }
        return;
      }
      this.infer(name, edge, unresolved);
      return;
    }
    if (fn.type === 'parenthesized_expression' && namedChildren(fn)[0]?.type === 'lambda') {
      const d = ctx.byStart.get(posKey(namedChildren(fn)[0]));
      if (d) {
        edge(d, 'exact', '<lambda>', 'immediately called lambda');
        return;
      }
    }
    unresolved('<expr>', 'dynamic', `callee is a ${fn.type}`);
  }

  private bind(
    t: Target,
    name: string,
    edge: (to: StableDecl, tier: Tier, name: string, evidence: string) => void,
    unresolved: (name: string, reason: UnresolvedReason, evidence: string) => void,
  ): void {
    if (t.kind === 'external') return unresolved(name, 'external', 'imported from outside the tree');
    if (t.kind === 'none') return unresolved(name, 'external', 'not declared in the tree (builtin)');
    if (t.kind === 'module') return unresolved(name, 'dynamic', 'a module is not callable');
    const d = t.decls[t.decls.length - 1];
    if (d.kind === 'function') return edge(d, 'exact', name, 'module scope or import');
    if (d.kind === 'type') {
      const init = this.findMember(d, '__init__');
      return edge(init && init !== 'external' ? init.decl : d, 'exact', name, 'class instantiation');
    }
    unresolved(name, 'dynamic', 'callee is a value, not a declared function');
  }

  private infer(
    name: string,
    edge: (to: StableDecl, tier: Tier, name: string, evidence: string) => void,
    unresolved: (name: string, reason: UnresolvedReason, evidence: string) => void,
  ): void {
    const all = this.methodsByName.get(name) ?? [];
    const max = this.options.maxInferred ?? 16;
    if (all.length === 0) return unresolved(name, 'unknown', 'receiver class unknown and no method of this name in the tree');
    if (all.length > max) return unresolved(name, 'unknown', `receiver class unknown; ${all.length} methods of this name exceed the bound`);
    for (const d of [...all].sort((a, b) => (a.id < b.id ? -1 : 1))) edge(d, 'inferred', name, 'bound by name alone');
  }

  // -- references --------------------------------------------------------------

  private valueTargets(ctx: FileCtx, node: Node): StableDecl[] {
    if (node.type === 'identifier') {
      const b = this.localBinding(node, node.text);
      if (b) {
        const d = b.kind === 'def' ? ctx.byStart.get(posKey(holderOf(b.node))) : undefined;
        return d ? [d] : [];
      }
      const t = this.resolveName(ctx, node.text);
      return t.kind === 'decls' ? t.decls.filter(d => d.kind === 'function' || d.kind === 'type') : [];
    }
    if (node.type === 'attribute') {
      const object = node.childForFieldName('object');
      const name = node.childForFieldName('attribute')?.text;
      if (!object || !name) return [];
      if (this.isSelf(object)) {
        const cls = this.enclosingClass(ctx, node);
        const r = cls ? this.findMember(cls, name) : null;
        return r && r !== 'external' ? [r.decl, ...this.overrides(r.owner, name)] : [];
      }
      const t = this.resolveExpr(ctx, object);
      if (t.kind === 'module') {
        const m = this.resolveName(t.ctx, name);
        return m.kind === 'decls' ? m.decls.filter(d => d.kind === 'function' || d.kind === 'type') : [];
      }
      if (t.kind === 'decls') {
        const type = t.decls.find(d => d.kind === 'type');
        const r = type ? this.findMember(type, name) : null;
        return r && r !== 'external' ? [r.decl] : [];
      }
    }
    return [];
  }

  private reference(ctx: FileCtx, node: Node | null): void {
    if (!node) return;
    const targets = this.valueTargets(ctx, node);
    if (targets.length === 0) return;
    const site: CallEdgeSite = { file: ctx.path, line: node.startPosition.row + 1, col: node.startPosition.column };
    const from = (ctx.locate(site.line, site.col) ?? ctx.ids.decls[0]).id;
    for (const d of targets) if (d.id !== from) this.references.push({ from, to: d.id, site });
  }

  // -- entries -----------------------------------------------------------------

  private entry(d: StableDecl, kind: EntryKind, certainty: EntryCertainty, file: string, evidence: string, extra: Partial<TsEntry> = {}): void {
    this.entries.push({ id: d.id, kind, certainty, file, line: d.start_line, evidence, ...extra });
  }

  /** The package an identifier comes from, through this file's imports. */
  private packageOf(ctx: FileCtx, name: string): string | null {
    const imp = ctx.imports.get(name);
    return imp?.external ? imp.module : null;
  }

  /** A router object: created by a factory from a framework package, with its own prefix. */
  private routerOf(ctx: FileCtx, receiver: Node | null, depth = 0): { row: PythonRouterRow; key: string } | null {
    if (receiver?.type !== 'identifier' || depth > 3) return null;
    const assign = ctx.topVars.get(receiver.text);
    if (!assign) {
      const imp = ctx.imports.get(receiver.text);
      if (imp?.kind === 'name' && !imp.external) {
        const target = this.modules.get(imp.module);
        const v = target?.topVars.get(imp.name);
        if (target && v) return this.routerOf(target, v.childForFieldName('left'), depth + 1);
      }
      return null;
    }
    const call = assign.childForFieldName('right');
    if (call?.type !== 'call') return null;
    const fn = call.childForFieldName('function');
    const factory = fn?.type === 'attribute' ? fn.childForFieldName('attribute')?.text : fn?.text;
    const root = fn?.type === 'attribute' ? fn.childForFieldName('object')?.text : fn?.text;
    if (!factory || !root) return null;
    const pkg = this.packageOf(ctx, root);
    const row = this.tables.routers.find(r => r.factories.includes(factory) && pkg !== null && (pkg === r.package || pkg.startsWith(r.package + '.')));
    if (!row) return null;
    const key = `${ctx.path}#${receiver.text}`;
    if (!this.routers.has(key)) {
      const args = call.childForFieldName('arguments');
      const kw = args ? namedChildren(args).find(a => a.type === 'keyword_argument' && a.childForFieldName('name')?.text === row.prefixKeyword) : undefined;
      this.routers.set(key, { prefix: str(kw?.childForFieldName('value')) ?? '' });
    }
    return { row, key };
  }

  private convert(path: string, row?: PythonRouterRow): string {
    return row?.converters ? path.replace(/<(?:[^:<>]+:)?([^<>]+)>/g, '{$1}') : path;
  }

  private decorated(ctx: FileCtx, node: Node): void {
    const def = node.childForFieldName('definition');
    const decl = ctx.byStart.get(posKey(node));
    if (!def || !decl) return;
    for (const dec of namedChildren(node)) {
      if (dec.type !== 'decorator') continue;
      const expr = namedChildren(dec)[0];
      const call = expr?.type === 'call' ? expr : null;
      const callee = call ? call.childForFieldName('function') : expr;
      const args = call?.childForFieldName('arguments');
      const argv = args ? namedChildren(args) : [];
      const last = callee?.type === 'attribute' ? callee.childForFieldName('attribute')?.text : callee?.text;
      const receiver = callee?.type === 'attribute' ? callee.childForFieldName('object') : null;
      if (!last) continue;
      // Routes: @app.route('/x', methods=[...]) / @router.get('/x').
      const router = this.routerOf(ctx, receiver);
      const verbs = router?.row.verbs ?? this.tables.routers.find(r => last in r.verbs)?.verbs;
      const path = str(argv.find(a => a.type === 'string'));
      if (verbs && last in verbs && path !== null && (path.startsWith('/') || path === '')) {
        const verb = verbs[last];
        const kw = argv.find(a => a.type === 'keyword_argument' && a.childForFieldName('name')?.text === 'methods');
        const methods = verb ?? null;
        const list = methods ? [methods] : (kw ? namedChildren(kw.childForFieldName('value') as Node).map(s => str(s)).filter((s): s is string => s !== null) : []);
        for (const m of list.length > 0 ? list : ['GET']) {
          this.routes.push({
            decl, certainty: router ? 'declared' : 'inferred', framework: router?.row.package, method: m.toUpperCase(),
            path: this.convert(path, router?.row), file: ctx.path, line: decl.start_line, router: router?.key,
          });
        }
        continue;
      }
      // Other decorators by table.
      const root = callee?.type === 'attribute' ? (() => {
        let o: Node | null = callee;
        while (o?.type === 'attribute') o = o.childForFieldName('object');
        return o?.text ?? null;
      })() : callee?.text ?? null;
      const pkg = root ? this.packageOf(ctx, root) : null;
      for (const row of this.tables.decorators) {
        if (!row.names.includes(last)) continue;
        const fromPkg = pkg !== null && row.packages.some(p => pkg === p || pkg.startsWith(p + '.'));
        // `@cli.command()` on a group made by `@click.group()`: the receiver is a decorated function.
        const viaGroup = !fromPkg && receiver?.type === 'identifier' && this.isDecoratedBy(ctx, receiver.text, row.packages);
        if (fromPkg || viaGroup) this.entry(decl, row.kind, 'declared', ctx.path, `@${dec.text.replace(/^@/, '').slice(0, 40)}`, { framework: row.packages[0] });
      }
    }
    this.testDefinition(ctx, def, decl);
  }

  private isDecoratedBy(ctx: FileCtx, name: string, packages: readonly string[]): boolean {
    const d = ctx.top.get(name)?.[0];
    if (!d) return false;
    const holder = namedChildren(ctx.root).find(s => s.type === 'decorated_definition' && posKey(s) === `${d.start_line}:${d.start_column}`);
    return !!holder && namedChildren(holder).some(dec => {
      if (dec.type !== 'decorator') return false;
      const root = dec.text.replace(/^@\s*/, '').split(/[.(]/)[0];
      const pkg = this.packageOf(ctx, root);
      return pkg !== null && packages.includes(pkg);
    });
  }

  /** pytest and unittest conventions. */
  private testDefinition(ctx: FileCtx, def: Node, decl: StableDecl): void {
    if (!this.tables.testFile.test(ctx.path) || def.type !== 'function_definition') return;
    const name = decl.name;
    const parent = this.declById(decl.parent ?? '');
    const inTestClass = parent?.kind === 'type' && (/^Test/.test(parent.name) || (this.bases.get(parent.id) ?? []).includes('external'));
    if ((parent?.kind === 'module' && /^test/.test(name)) || (inTestClass && /^(test|setUp|tearDown|setup_|teardown_)/.test(name))) {
      this.entry(decl, 'test', 'conventional', ctx.path, 'test by naming convention');
    }
  }

  /** Undecorated test functions and methods (decorated ones go through `decorated`). */
  tests(ctx: FileCtx): void {
    if (!this.tables.testFile.test(ctx.path)) return;
    this.entry(ctx.ids.decls[0], 'test', 'conventional', ctx.path, 'test module');
    const visit = (node: Node): void => {
      if (node.type === 'function_definition' && node.parent?.type !== 'decorated_definition') {
        const d = ctx.byStart.get(posKey(node));
        if (d) this.testDefinition(ctx, node, d);
      }
      for (const c of namedChildren(node)) visit(c);
    };
    visit(ctx.root);
  }

  private mainGuard(ctx: FileCtx, node: Node): void {
    if (node.parent?.type !== 'module') return;
    const cond = node.childForFieldName('condition')?.text.replace(/\s+/g, '').replace(/'/g, '"');
    if (cond === '__name__=="__main__"' || cond === '"__main__"==__name__') {
      this.entry(ctx.ids.decls[0], 'main', 'declared', ctx.path, 'if __name__ == "__main__"');
    }
  }

  /** Django `path('x/', view)` in a URL configuration. */
  private urlConf(ctx: FileCtx, node: Node): void {
    const fn = node.childForFieldName('function');
    if (fn?.type !== 'identifier' || !this.tables.urlConf.functions.includes(fn.text)) return;
    const imp = ctx.imports.get(fn.text);
    if (!imp || imp.module !== this.tables.urlConf.package) return;
    const args = node.childForFieldName('arguments');
    const argv = args ? namedChildren(args).filter(a => a.type !== 'keyword_argument') : [];
    const route = str(argv[0]);
    const view = argv[1];
    if (route === null || !view) return;
    const path = joinRoutePath([route.replace(/^\^|\$$/g, '').replace(/<(?:[^:<>]+:)?([^<>]+)>/g, '{$1}')]);
    const site: CallEdgeSite = { file: ctx.path, line: node.startPosition.row + 1, col: node.startPosition.column };
    // `View.as_view()`: the class's HTTP-method handlers.
    if (view.type === 'call' && view.childForFieldName('function')?.type === 'attribute' && view.childForFieldName('function')?.childForFieldName('attribute')?.text === 'as_view') {
      const t = this.resolveExpr(ctx, view.childForFieldName('function')?.childForFieldName('object') as Node);
      const cls = t.kind === 'decls' ? t.decls.find(d => d.kind === 'type') : undefined;
      if (cls) {
        for (const m of ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'dispatch']) {
          const r = this.findMember(cls, m);
          if (r && r !== 'external') this.entry(r.decl, 'route', 'declared', ctx.path, 'Django class-based view', { framework: 'django', method: m === 'dispatch' ? 'ANY' : m.toUpperCase(), path });
        }
        return;
      }
    }
    if (view.type === 'call') return; // include(...) and other factories
    const targets = this.valueTargets(ctx, view);
    if (targets.length === 0) {
      this.unresolvedRegistrations.push({ site, reason: 'handler-unresolved', evidence: `path ${path}: view ${view.text.slice(0, 40)} not tied to a declaration` });
      return;
    }
    for (const d of targets) this.entry(d, 'route', 'declared', ctx.path, 'Django path()', { framework: 'django', method: 'ANY', path });
  }

  /** `app.register_blueprint(bp, url_prefix=...)`, `app.include_router(r, prefix=...)`. */
  private mount(ctx: FileCtx, node: Node): void {
    const fn = node.childForFieldName('function');
    if (fn?.type !== 'attribute') return;
    const method = fn.childForFieldName('attribute')?.text ?? '';
    const parent = this.routerOf(ctx, fn.childForFieldName('object'));
    if (!parent || !(method in parent.row.mounts)) return;
    const args = node.childForFieldName('arguments');
    const argv = args ? namedChildren(args) : [];
    const child = this.routerOf(ctx, argv.find(a => a.type !== 'keyword_argument') ?? null);
    const kw = argv.find(a => a.type === 'keyword_argument' && a.childForFieldName('name')?.text === parent.row.mounts[method]);
    if (!child) {
      this.unresolvedRegistrations.push({
        site: { file: ctx.path, line: node.startPosition.row + 1, col: node.startPosition.column },
        reason: 'mount-unresolved',
        evidence: `${method}: the router is not one the tree creates`,
      });
      return;
    }
    this.mounts.push({ parent: parent.key, child: child.key, prefix: str(kw?.childForFieldName('value')) ?? '' });
  }

  private chains(key: string | undefined, seen: ReadonlySet<string> = new Set()): string[][] {
    if (key === undefined || seen.has(key)) return [[]];
    const own = this.routers.get(key)?.prefix ?? '';
    const parents = this.mounts.filter(m => m.child === key);
    const next = new Set(seen).add(key);
    const base = parents.length === 0 ? [[]] : parents.flatMap(m => this.chains(m.parent, next).map(c => (m.prefix ? [...c, m.prefix] : c)));
    return base.slice(0, 16).map(c => (own ? [...c, own] : c));
  }

  private composeRoutes(): void {
    for (const r of this.routes) {
      for (const chain of this.chains(r.router)) {
        const extra: Partial<TsEntry> = { method: r.method, path: joinRoutePath([...chain, r.path]) };
        if (chain.length > 0) {
          extra.registeredPath = r.path;
          extra.mounts = chain;
        }
        if (r.framework) extra.framework = r.framework;
        this.entry(r.decl, 'route', r.certainty, r.file, r.framework ? `${r.framework} route` : 'route-shaped decorator on a receiver of unknown origin', extra);
      }
    }
  }

  /** `pkg.mod:func` targets of `pyproject.toml` scripts. */
  scripts(text: string): void {
    let inScripts = false;
    for (const raw of text.split('\n')) {
      const line = raw.replace(/#.*$/, '').trim();
      if (line.startsWith('[')) {
        inScripts = /^\[(?:project\.scripts|tool\.poetry\.scripts|project\.gui-scripts)\]$/.test(line);
        continue;
      }
      if (!inScripts) continue;
      const m = line.match(/^["']?[\w.-]+["']?\s*=\s*["']([\w.]+):([\w.]+)["']/);
      if (!m) continue;
      const ctx = this.modules.get(m[1]);
      const t = ctx ? this.resolveName(ctx, m[2].split('.')[0]) : null;
      if (t?.kind === 'decls') for (const d of t.decls) this.entry(d, 'main', 'declared', ctx?.path ?? '', `pyproject script ${m[1]}:${m[2]}`);
      else this.unresolvedRegistrations.push({ site: { file: 'pyproject.toml', line: 1, col: 0 }, reason: 'manifest-unresolved', evidence: `script ${m[1]}:${m[2]} not found in the tree` });
    }
  }

  exports(path: string): void {
    const ctx = this.files.find(f => f.path === path);
    if (!ctx) return;
    const all = ctx.topVars.get('__all__')?.childForFieldName('right');
    const names = all && (all.type === 'list' || all.type === 'tuple')
      ? namedChildren(all).map(s => str(s)).filter((s): s is string => s !== null)
      : [...ctx.top.keys(), ...ctx.imports.keys()].filter(n => !n.startsWith('_'));
    for (const n of [...new Set(names)].sort()) {
      const t = this.resolveName(ctx, n);
      if (t.kind === 'decls') for (const d of t.decls) this.entry(d, 'export', 'declared', ctx.path, 'public name of an export root');
    }
  }
}

/** Python graph facts for a set of files. Deterministic: the same files give the same graph. */
export async function buildPythonGraph(files: readonly PythonSourceFile[], options: PythonGraphOptions = {}): Promise<PythonGraph> {
  const tables = options.entryTables ?? DEFAULT_PYTHON_ENTRY_TABLES;
  const sorted = [...files].filter(f => /\.pyi?$/.test(f.path)).sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const trees: Tree[] = [];
  try {
    const ctxs: FileCtx[] = [];
    for (const f of sorted) {
      const tree = await parse(f.code, 'python');
      trees.push(tree);
      const module = f.module ?? pythonModuleName(f.path);
      const ids = derivePythonIds(tree, f.path, { module });
      const isInit = /(^|\/)__init__\.pyi?$/.test(f.path);
      ctxs.push({
        path: f.path, module, pkg: isInit ? module : module.split('.').slice(0, -1).join('.'), ids, root: tree.rootNode,
        top: new Map(), topVars: new Map(), imports: new Map(), locate: declLocator(ids), byStart: new Map(),
      });
    }
    const b = new PythonGraphBuilder(ctxs, tables, options);
    b.link();
    b.run();
    for (const ctx of ctxs) b.tests(ctx);
    if (options.pyprojectToml) b.scripts(options.pyprojectToml);
    for (const p of options.exportRoots ?? []) b.exports(p);
    const cmp = (x: string, y: string): number => (x < y ? -1 : x > y ? 1 : 0);
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
      scheme: PYTHON_GRAPH_SCHEME,
      ids: 'ids@0.1',
      files: ctxs.map(c => c.ids),
      edges: [...b.edges].sort((x, y) => bySite(x, y) || cmp(x.to, y.to)),
      unresolved: [...b.unresolved].sort(bySite),
      references: [...b.references].sort((x, y) => bySite(x, y) || cmp(x.to, y.to)),
      loads: b.loads,
      entryScheme: 'entry-index@0.1',
      entries,
      unresolvedRegistrations: [...b.unresolvedRegistrations].sort(bySite),
      partial: ctxs.filter(c => c.ids.partial).map(c => c.path),
      typeOnly: [...b.typeOnly].sort(),
      sites: b.siteCount,
    };
  } finally {
    for (const t of trees) disposeTree(t);
  }
}
