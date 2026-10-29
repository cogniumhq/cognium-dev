/**
 * TypeScript/JavaScript call edges keyed by stable declaration ids.
 *
 * Every call site in a set of files becomes either an **edge** from the
 * enclosing declaration to the declaration(s) it can run, labelled with the
 * same tiers as the Java navigation index, or an **unresolved** site with a
 * reason from the same closed vocabulary. Nothing is dropped silently: the
 * two lists together account for every call and `new` expression walked.
 *
 * Tiers:
 * - `exact` — the callee is a single declaration with a body, bound through
 *   lexical scope, an import, a namespace, a class name, or a receiver whose
 *   type is known (a type annotation, a `new` initializer, `this`, `super`)
 *   and whose method no subtype in the tree overrides.
 * - `polymorphic` — the receiver's type is known and dispatch is open: the
 *   method is abstract or on an interface, or a subtype overrides it. One
 *   edge per body that could run, each carrying `via` (the declaring member).
 * - `inferred` — a member call on a receiver of unknown type, bound by the
 *   method's name alone to every method of that name in the tree. Reported
 *   and labelled, never promoted.
 *
 * Bounds of this version, each surfacing as an unresolved site rather than
 * a guess: no type inference beyond the shapes above (a call's return type is
 * not followed); `tsconfig` path aliases only through `moduleAliases`; JSX
 * element rendering is not a call; module-level names are importable whether
 * or not they are exported.
 */

import { disposeTree, parse, type Node, type Tree } from '../core/parser.js';
import { declLocator } from '../stable-ids/nodes.js';
import { deriveTypeScriptIds } from '../stable-ids/typescript.js';
import type { StableDecl, StableIdFile, StableIdOptions } from '../stable-ids/types.js';
import type { Tier, UnresolvedReason } from './types.js';

export const TS_CALL_EDGES_SCHEME = 'ts-call-edges@0.1' as const;

export interface TsSourceFile {
  /** Repository-relative path, `/`-separated. */
  path: string;
  code: string;
  /** Stable-id options for this file (package name and root, module). */
  ids?: StableIdOptions;
}

export interface TsCallGraphOptions {
  /** Non-relative import prefixes mapped to repository paths, e.g. `{ '@app/': 'src/' }`. */
  moduleAliases?: Readonly<Record<string, string>>;
  /** Most `inferred` edges one site may carry; beyond it the site is unresolved. Default 16. */
  maxInferred?: number;
}

export interface CallEdgeSite {
  file: string;
  /** 1-based. */
  line: number;
  /** 0-based. */
  col: number;
}

export interface CallEdge {
  /** The enclosing declaration's id (the module's for top-level code). */
  from: string;
  /** The declaration that can run. */
  to: string;
  tier: Tier;
  /** The name as written at the site (`new` sites: the class name). */
  methodName: string;
  site: CallEdgeSite;
  /** On `polymorphic`: the member the receiver's static type declares. */
  via?: string;
  /** How the tier was reached, in one line. */
  evidence: string;
}

export interface UnresolvedCall {
  from: string;
  methodName: string;
  site: CallEdgeSite;
  reason: UnresolvedReason;
  evidence: string;
}

export interface TsCallGraph {
  scheme: typeof TS_CALL_EDGES_SCHEME;
  ids: 'ids@0.1';
  /** The stable ids of every file, in path order. */
  files: StableIdFile[];
  edges: CallEdge[];
  unresolved: UnresolvedCall[];
  /** Files that did not parse cleanly; their sites may be missing. */
  partial: string[];
  /** Call and `new` sites walked; equals the distinct sites over `edges` and `unresolved`. */
  sites: number;
}

// ---------------------------------------------------------------------------
// Paths

const EXTENSIONS = ['.ts', '.tsx', '.mts', '.cts', '.d.ts', '.js', '.jsx', '.mjs', '.cjs'];

function normalizePath(p: string): string {
  const out: string[] = [];
  for (const part of p.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') out.pop();
    else out.push(part);
  }
  return out.join('/');
}

function dirname(p: string): string {
  const i = p.lastIndexOf('/');
  return i < 0 ? '' : p.slice(0, i);
}

function languageOf(path: string): { grammar: 'typescript' | 'javascript' | 'tsx'; ids: 'typescript' | 'javascript' } | null {
  const lower = path.toLowerCase();
  if (lower.endsWith('.tsx')) return { grammar: 'tsx', ids: 'typescript' };
  if (lower.endsWith('.jsx')) return { grammar: 'tsx', ids: 'javascript' };
  if (/\.[mc]?ts$/.test(lower)) return { grammar: 'typescript', ids: 'typescript' };
  if (/\.[mc]?js$/.test(lower)) return { grammar: 'javascript', ids: 'javascript' };
  return null;
}

// ---------------------------------------------------------------------------
// Per-file tables

type ImportBinding =
  | { kind: 'named'; module: string | null; name: string }
  | { kind: 'default'; module: string | null }
  | { kind: 'namespace'; module: string | null };

interface FileCtx {
  path: string;
  ids: StableIdFile;
  root: Node;
  module: StableDecl;
  /** Module-level declarations by name. */
  top: Map<string, StableDecl[]>;
  /** Module-level variable declarators by name. */
  topVars: Map<string, Node>;
  imports: Map<string, ImportBinding>;
  /** Exported name → local name. */
  exports: Map<string, string>;
  defaultLocal: string | null;
  reexports: Map<string, { module: string | null; name: string }>;
  stars: (string | null)[];
  locate: (line: number, column?: number) => StableDecl | null;
  /** Declarations by `line:col:kind` of their node. */
  byStart: Map<string, StableDecl>;
}

type Target =
  | { kind: 'decls'; decls: StableDecl[]; ctx: FileCtx }
  | { kind: 'namespace'; ctx: FileCtx }
  | { kind: 'external' }
  | { kind: 'none' };

const FUNCTION_NODES = new Set([
  'function_declaration', 'generator_function_declaration', 'function_expression', 'function',
  'generator_function', 'arrow_function', 'method_definition',
]);

function named(node: Node): Node[] {
  const out: Node[] = [];
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i);
    if (c && c.type !== 'comment') out.push(c);
  }
  return out;
}

function stringValue(node: Node | null): string | null {
  if (!node || node.type !== 'string') return null;
  return named(node).map(c => c.text).join('');
}

function posKey(node: Node, kind: string): string {
  return `${node.startPosition.row + 1}:${node.startPosition.column}:${kind}`;
}

function isRequire(node: Node | null): Node | null {
  if (node?.type !== 'call_expression') return null;
  const fn = node.childForFieldName('function');
  if (fn?.type !== 'identifier' || fn.text !== 'require') return null;
  const arg = node.childForFieldName('arguments')?.namedChild(0) ?? null;
  return arg?.type === 'string' ? arg : null;
}

/** Identifier leaves of a binding pattern. */
function patternNames(node: Node | null, out: string[] = []): string[] {
  if (!node) return out;
  if (node.type === 'identifier' || node.type === 'shorthand_property_identifier_pattern') {
    out.push(node.text);
    return out;
  }
  if (node.type === 'pair_pattern') return patternNames(node.childForFieldName('value'), out);
  if (node.type === 'assignment_pattern') return patternNames(node.childForFieldName('left'), out);
  for (const c of named(node)) {
    if (c.type === 'type_annotation' || c.type === 'property_identifier') continue;
    patternNames(c, out);
  }
  return out;
}

class Graph {
  private readonly files = new Map<string, FileCtx>();
  readonly edges: CallEdge[] = [];
  readonly unresolved: UnresolvedCall[] = [];
  private sites = 0;
  /** Type decl id → its class or interface node and file. */
  private readonly typeNodes = new Map<string, { node: Node; ctx: FileCtx }>();
  /** Type decl id → direct supertypes (resolved decls). */
  private readonly supers = new Map<string, { extends: StableDecl | 'external' | null; implements: StableDecl[] }>();
  /** Type decl id → direct subtypes. */
  private readonly subs = new Map<string, StableDecl[]>();
  /** Declarations without a body: overload, interface and abstract signatures. */
  private readonly bodiless = new Set<string>();
  /** Method declarations by name, across the tree, for `inferred`. */
  private readonly methodsByName = new Map<string, StableDecl[]>();
  private readonly maxInferred: number;

  constructor(private readonly options: TsCallGraphOptions) {
    this.maxInferred = options.maxInferred ?? 16;
  }

  get siteCount(): number {
    return this.sites;
  }

  // -- loading ---------------------------------------------------------------

  add(path: string, tree: Tree, ids: StableIdFile): void {
    const root = tree.rootNode;
    const ctx: FileCtx = {
      path, ids, root, module: ids.decls[0],
      top: new Map(), topVars: new Map(), imports: new Map(), exports: new Map(),
      defaultLocal: null, reexports: new Map(), stars: [],
      locate: declLocator(ids), byStart: new Map(),
    };
    for (const d of ids.decls) {
      if (d.parent === ctx.module.id) {
        const list = ctx.top.get(d.name);
        if (list) list.push(d);
        else ctx.top.set(d.name, [d]);
      }
      if (d.kind === 'method' && !d.signature.startsWith('get ') && !d.signature.startsWith('set ')
        && !d.signature.startsWith('static get ') && !d.signature.startsWith('static set ')) {
        const list = this.methodsByName.get(d.name);
        if (list) list.push(d);
        else this.methodsByName.set(d.name, [d]);
      }
    }
    this.files.set(path, ctx);
  }

  /** Second pass, once every file is loaded: module tables, node positions, hierarchy. */
  link(): void {
    for (const ctx of this.sortedFiles()) this.scanModule(ctx);
    for (const ctx of this.sortedFiles()) this.scanTypes(ctx, ctx.root);
    for (const [id, s] of this.supers) {
      const parents = [...(s.extends && s.extends !== 'external' ? [s.extends] : []), ...s.implements];
      for (const p of parents) {
        const list = this.subs.get(p.id);
        const self = this.declById(id);
        if (!self) continue;
        if (list) list.push(self);
        else this.subs.set(p.id, [self]);
      }
    }
  }

  private sortedFiles(): FileCtx[] {
    return [...this.files.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  }

  private readonly idIndex = new Map<string, StableDecl>();
  private declById(id: string): StableDecl | undefined {
    if (this.idIndex.size === 0) {
      for (const ctx of this.files.values()) for (const d of ctx.ids.decls) this.idIndex.set(d.id, d);
    }
    return this.idIndex.get(id);
  }

  resolveModule(from: string, specifier: string): string | null {
    let base: string | null = null;
    if (specifier.startsWith('./') || specifier.startsWith('../') || specifier === '.' || specifier === '..') {
      base = normalizePath(`${dirname(from)}/${specifier}`);
    } else {
      for (const [prefix, target] of Object.entries(this.options.moduleAliases ?? {}).sort()) {
        if (specifier.startsWith(prefix)) {
          base = normalizePath(target + specifier.slice(prefix.length));
          break;
        }
      }
    }
    if (base === null) return null;
    const stems = [base];
    const js = base.match(/^(.*)\.(?:m|c)?jsx?$/);
    if (js) stems.push(js[1]);
    for (const stem of stems) {
      if (this.files.has(stem)) return stem;
      for (const ext of EXTENSIONS) if (this.files.has(stem + ext)) return stem + ext;
      for (const ext of EXTENSIONS) if (this.files.has(`${stem}/index${ext}`)) return `${stem}/index${ext}`;
    }
    return null;
  }

  private scanModule(ctx: FileCtx): void {
    for (const d of ctx.ids.decls) {
      // Index every declaration by the position its node starts at.
      ctx.byStart.set(`${d.start_line}:${d.start_column}:${d.kind}`, d);
    }
    for (const stmt of named(ctx.root)) this.scanStatement(ctx, stmt);
    this.markBodiless(ctx.root, ctx);
  }

  private markBodiless(node: Node, ctx: FileCtx): void {
    const t = node.type;
    if (t === 'function_signature' || t === 'method_signature' || t === 'abstract_method_signature') {
      const kind = t === 'function_signature' ? 'function' : 'method';
      const d = ctx.byStart.get(posKey(node, kind));
      if (d) this.bodiless.add(d.id);
    }
    for (const c of named(node)) this.markBodiless(c, ctx);
  }

  private scanStatement(ctx: FileCtx, stmt: Node): void {
    const t = stmt.type;
    if (t === 'import_statement') {
      const spec = stringValue(stmt.childForFieldName('source'));
      if (spec === null) return;
      const module = this.resolveModule(ctx.path, spec);
      const clause = named(stmt).find(c => c.type === 'import_clause');
      if (!clause) return;
      for (const c of named(clause)) {
        if (c.type === 'identifier') ctx.imports.set(c.text, { kind: 'default', module });
        else if (c.type === 'namespace_import') {
          const id = named(c).find(x => x.type === 'identifier');
          if (id) ctx.imports.set(id.text, { kind: 'namespace', module });
        } else if (c.type === 'named_imports') {
          for (const s of named(c)) {
            if (s.type !== 'import_specifier') continue;
            const name = s.childForFieldName('name')?.text;
            const alias = s.childForFieldName('alias')?.text ?? name;
            if (name && alias) ctx.imports.set(alias, name === 'default' ? { kind: 'default', module } : { kind: 'named', module, name });
          }
        }
      }
      return;
    }
    if (t === 'export_statement') {
      const source = stringValue(stmt.childForFieldName('source'));
      const declaration = stmt.childForFieldName('declaration');
      const value = stmt.childForFieldName('value');
      const clause = named(stmt).find(c => c.type === 'export_clause');
      if (source !== null) {
        const module = this.resolveModule(ctx.path, source);
        if (!clause) {
          ctx.stars.push(module);
          return;
        }
        for (const s of named(clause)) {
          const name = s.childForFieldName('name')?.text;
          const alias = s.childForFieldName('alias')?.text ?? name;
          if (name && alias) ctx.reexports.set(alias, { module, name });
        }
        return;
      }
      if (clause) {
        for (const s of named(clause)) {
          const name = s.childForFieldName('name')?.text;
          const alias = s.childForFieldName('alias')?.text ?? name;
          if (name && alias) {
            if (alias === 'default') ctx.defaultLocal = name;
            else ctx.exports.set(alias, name);
          }
        }
        return;
      }
      if (declaration) {
        let isDefault = false;
        for (let i = 0; i < stmt.childCount; i++) {
          const c = stmt.child(i);
          if (c && !c.isNamed && c.text === 'default') isDefault = true;
        }
        const nameNode = declaration.childForFieldName('name');
        if (isDefault && nameNode) ctx.defaultLocal = nameNode.text;
        this.scanStatement(ctx, declaration);
        return;
      }
      if (value) {
        if (value.type === 'identifier') ctx.defaultLocal = value.text;
        else {
          const own = value.childForFieldName('name');
          ctx.defaultLocal = own ? own.text : 'default';
        }
      }
      return;
    }
    if (t === 'lexical_declaration' || t === 'variable_declaration') {
      for (const d of named(stmt)) {
        if (d.type !== 'variable_declarator') continue;
        const nameNode = d.childForFieldName('name');
        const value = d.childForFieldName('value');
        const req = isRequire(value);
        if (nameNode?.type === 'identifier') {
          ctx.topVars.set(nameNode.text, d);
          if (req) ctx.imports.set(nameNode.text, { kind: 'namespace', module: this.resolveModule(ctx.path, stringValue(req) ?? '') });
        } else if (nameNode?.type === 'object_pattern' && req) {
          const module = this.resolveModule(ctx.path, stringValue(req) ?? '');
          for (const p of named(nameNode)) {
            if (p.type === 'shorthand_property_identifier_pattern') ctx.imports.set(p.text, { kind: 'named', module, name: p.text });
            else if (p.type === 'pair_pattern') {
              const key = p.childForFieldName('key')?.text;
              const local = p.childForFieldName('value');
              if (key && local?.type === 'identifier') ctx.imports.set(local.text, { kind: 'named', module, name: key });
            }
          }
        }
      }
    }
  }

  /** Classes and interfaces: their nodes and resolved supertypes. */
  private scanTypes(ctx: FileCtx, node: Node): void {
    const t = node.type;
    if (t === 'class_declaration' || t === 'abstract_class_declaration' || t === 'class' || t === 'interface_declaration') {
      const decl = this.typeDeclAt(ctx, node);
      if (decl) {
        this.typeNodes.set(decl.id, { node, ctx });
        let ext: StableDecl | 'external' | null = null;
        const impls: StableDecl[] = [];
        const heritage = named(node).find(c => c.type === 'class_heritage');
        const extendsNodes: Node[] = [];
        const implNodes: Node[] = [];
        if (heritage) {
          for (const c of named(heritage)) {
            if (c.type === 'extends_clause') {
              const v = c.childForFieldName('value') ?? named(c)[0];
              if (v) extendsNodes.push(v);
            } else if (c.type === 'implements_clause') implNodes.push(...named(c));
            else extendsNodes.push(c); // JavaScript: `class_heritage (identifier)`
          }
        }
        const ifaceExt = named(node).find(c => c.type === 'extends_type_clause');
        if (ifaceExt) implNodes.push(...named(ifaceExt));
        if (extendsNodes[0]) {
          const r = this.resolveTypeRef(ctx, extendsNodes[0]);
          ext = r === null ? null : r;
        }
        for (const n of implNodes) {
          const r = this.resolveTypeRef(ctx, n);
          if (r && r !== 'external') impls.push(r);
        }
        this.supers.set(decl.id, { extends: ext, implements: impls });
      }
    }
    for (const c of named(node)) this.scanTypes(ctx, c);
  }

  private typeDeclAt(ctx: FileCtx, node: Node): StableDecl | null {
    const direct = ctx.byStart.get(posKey(node, 'type'));
    if (direct) return direct;
    // `const C = class {}` / `export default class {}`: the declaration starts at the holder.
    let best: StableDecl | null = null;
    const line = node.startPosition.row + 1;
    for (const d of ctx.ids.decls) {
      if (d.kind !== 'type') continue;
      const inside = (line > d.start_line || (line === d.start_line && node.startPosition.column >= d.start_column))
        && node.endPosition.row + 1 <= d.end_line;
      if (inside && (!best || d.start_line > best.start_line || (d.start_line === best.start_line && d.start_column >= best.start_column))) best = d;
    }
    return best;
  }

  // -- name resolution -------------------------------------------------------

  private resolveExport(ctx: FileCtx, name: string, depth: number): Target {
    if (depth > 8) return { kind: 'none' };
    if (name === 'default') {
      if (ctx.defaultLocal !== null) {
        if (ctx.defaultLocal === 'default') {
          const d = ctx.top.get('default');
          return d ? { kind: 'decls', decls: d, ctx } : { kind: 'none' };
        }
        return this.resolveLocal(ctx, ctx.defaultLocal, depth + 1);
      }
      const d = ctx.top.get('default');
      return d ? { kind: 'decls', decls: d, ctx } : { kind: 'none' };
    }
    const local = ctx.exports.get(name);
    if (local !== undefined) return this.resolveLocal(ctx, local, depth + 1);
    const re = ctx.reexports.get(name);
    if (re) {
      const target = re.module === null ? undefined : this.files.get(re.module);
      return target ? this.resolveExport(target, re.name, depth + 1) : { kind: 'external' };
    }
    if (ctx.top.has(name)) return this.resolveLocal(ctx, name, depth + 1);
    for (const m of ctx.stars) {
      const target = m === null ? undefined : this.files.get(m);
      if (!target) continue;
      const r = this.resolveExport(target, name, depth + 1);
      if (r.kind !== 'none') return r;
    }
    return { kind: 'none' };
  }

  /** A module-level name: a declaration here, or an import followed to its file. */
  resolveLocal(ctx: FileCtx, name: string, depth = 0): Target {
    const decls = ctx.top.get(name);
    if (decls) return { kind: 'decls', decls, ctx };
    const imp = ctx.imports.get(name);
    if (!imp) return { kind: 'none' };
    const target = imp.module === null ? undefined : this.files.get(imp.module);
    if (!target) return { kind: 'external' };
    if (imp.kind === 'namespace') return { kind: 'namespace', ctx: target };
    return this.resolveExport(target, imp.kind === 'default' ? 'default' : imp.name, depth + 1);
  }

  private resolveTypeRef(ctx: FileCtx, node: Node): StableDecl | 'external' | null {
    let n: Node | null = node;
    if (n.type === 'type_annotation') n = named(n)[0] ?? null;
    if (n?.type === 'generic_type') n = n.childForFieldName('name') ?? named(n)[0] ?? null;
    if (!n) return null;
    if (n.type === 'nested_type_identifier' || n.type === 'member_expression') {
      const parts = n.text.split('.');
      if (parts.length !== 2) return 'external';
      const ns = this.resolveLocal(ctx, parts[0]);
      if (ns.kind !== 'namespace') return 'external';
      const r = this.resolveExport(ns.ctx, parts[1], 0);
      return r.kind === 'decls' ? (r.decls.find(d => d.kind === 'type') ?? 'external') : 'external';
    }
    if (n.type !== 'type_identifier' && n.type !== 'identifier') return null;
    const r = this.resolveLocal(ctx, n.text);
    if (r.kind === 'decls') return r.decls.find(d => d.kind === 'type') ?? null;
    return 'external';
  }

  // -- lexical scope ---------------------------------------------------------

  /**
   * The nearest binding of `name` inside the enclosing functions and blocks
   * (module level excluded): a parameter, a variable declarator, or a nested
   * function declaration.
   */
  private localBinding(start: Node, name: string): { kind: 'param'; node: Node } | { kind: 'var'; node: Node } | { kind: 'fn'; node: Node } | null {
    for (let n: Node | null = start.parent; n && n.type !== 'program'; n = n.parent) {
      if (FUNCTION_NODES.has(n.type)) {
        const params = n.childForFieldName('parameters');
        const single = n.childForFieldName('parameter');
        if (single && single.text === name) return { kind: 'param', node: single };
        if (params) {
          for (const p of named(params)) {
            const pattern = p.childForFieldName('pattern') ?? p;
            if (patternNames(pattern).includes(name)) return { kind: 'param', node: p };
          }
        }
      }
      if (n.type === 'catch_clause' && patternNames(n.childForFieldName('parameter')).includes(name)) {
        return { kind: 'param', node: n };
      }
      if (n.type === 'statement_block' || n.type === 'for_statement' || n.type === 'for_in_statement') {
        for (const s of named(n)) {
          if ((s.type === 'function_declaration' || s.type === 'generator_function_declaration') && s.childForFieldName('name')?.text === name) {
            return { kind: 'fn', node: s };
          }
          if (s.type === 'lexical_declaration' || s.type === 'variable_declaration') {
            for (const d of named(s)) {
              if (d.type === 'variable_declarator' && patternNames(d.childForFieldName('name')).includes(name)) return { kind: 'var', node: d };
            }
          }
        }
        if (n.type === 'for_in_statement' && patternNames(n.childForFieldName('left')).includes(name)) return { kind: 'param', node: n };
      }
    }
    return null;
  }

  private nestedDeclAt(ctx: FileCtx, node: Node): StableDecl | null {
    return ctx.byStart.get(posKey(node, 'function')) ?? null;
  }

  // -- receiver types --------------------------------------------------------

  private enclosingClass(ctx: FileCtx, node: Node): StableDecl | null {
    for (let n: Node | null = node.parent; n; n = n.parent) {
      // A non-arrow function rebinds `this`; methods are the exception.
      if ((n.type === 'function_expression' || n.type === 'function' || n.type === 'function_declaration') && n.parent?.type !== 'class_body') return null;
      if (n.type === 'class_declaration' || n.type === 'abstract_class_declaration' || n.type === 'class') return this.typeDeclAt(ctx, n);
    }
    return null;
  }

  private typeOfVar(ctx: FileCtx, declarator: Node): StableDecl | 'external' | null {
    const type = declarator.childForFieldName('type');
    if (type) return this.resolveTypeRef(ctx, type);
    const value = declarator.childForFieldName('value');
    if (value?.type === 'new_expression') {
      const c = value.childForFieldName('constructor');
      return c ? this.resolveTypeRef(ctx, c) : null;
    }
    return null;
  }

  /** The class's own field or constructor parameter property named `name`, typed. */
  private typeOfField(cls: StableDecl, name: string): StableDecl | 'external' | null {
    const entry = this.typeNodes.get(cls.id);
    if (!entry) return null;
    const body = entry.node.childForFieldName('body');
    if (!body) return null;
    for (const m of named(body)) {
      if ((m.type === 'public_field_definition' || m.type === 'field_definition') && (m.childForFieldName('name') ?? m.childForFieldName('property'))?.text === name) {
        const type = m.childForFieldName('type');
        if (type) return this.resolveTypeRef(entry.ctx, type);
        const value = m.childForFieldName('value');
        if (value?.type === 'new_expression') {
          const c = value.childForFieldName('constructor');
          return c ? this.resolveTypeRef(entry.ctx, c) : null;
        }
        return null;
      }
      if (m.type === 'method_definition' && m.childForFieldName('name')?.text === 'constructor') {
        const params = m.childForFieldName('parameters');
        for (const p of params ? named(params) : []) {
          const hasModifier = named(p).some(c => c.type === 'accessibility_modifier' || c.type === 'override_modifier')
            || /^\s*readonly\b/.test(p.text);
          if (!hasModifier || p.childForFieldName('pattern')?.text !== name) continue;
          const type = p.childForFieldName('type');
          return type ? this.resolveTypeRef(entry.ctx, type) : null;
        }
      }
    }
    const sup = this.supers.get(cls.id)?.extends;
    return sup && sup !== 'external' ? this.typeOfField(sup, name) : null;
  }

  private typeOf(ctx: FileCtx, expr: Node): StableDecl | 'external' | null {
    if (expr.type === 'this') return this.enclosingClass(ctx, expr);
    if (expr.type === 'parenthesized_expression' || expr.type === 'non_null_expression') {
      const inner = named(expr)[0];
      return inner ? this.typeOf(ctx, inner) : null;
    }
    if (expr.type === 'new_expression') {
      const c = expr.childForFieldName('constructor');
      return c ? this.resolveTypeRef(ctx, c) : null;
    }
    if (expr.type === 'identifier') {
      const b = this.localBinding(expr, expr.text);
      if (b?.kind === 'param') {
        const type = b.node.childForFieldName('type');
        return type ? this.resolveTypeRef(ctx, type) : null;
      }
      if (b?.kind === 'var') return this.typeOfVar(ctx, b.node);
      if (b) return null;
      const top = ctx.topVars.get(expr.text);
      return top ? this.typeOfVar(ctx, top) : null;
    }
    if (expr.type === 'member_expression') {
      const object = expr.childForFieldName('object');
      const property = expr.childForFieldName('property');
      if (object?.type === 'this' && property) {
        const cls = this.enclosingClass(ctx, expr);
        return cls ? this.typeOfField(cls, property.text) : null;
      }
    }
    return null;
  }

  // -- members and dispatch --------------------------------------------------

  /** Methods named `name` declared on `type` or inherited through `extends`. */
  private findMember(type: StableDecl, name: string, seen = new Set<string>()): { decls: StableDecl[]; owner: StableDecl } | 'external' | null {
    if (seen.has(type.id)) return null;
    seen.add(type.id);
    const own = this.membersOf(type, name);
    if (own.length > 0) return { decls: own, owner: type };
    const s = this.supers.get(type.id);
    if (s?.extends === 'external') return 'external';
    if (s?.extends) {
      const r = this.findMember(s.extends, name, seen);
      if (r) return r;
    }
    for (const i of s?.implements ?? []) {
      const r = this.findMember(i, name, seen);
      if (r && r !== 'external') return r;
    }
    return null;
  }

  private membersOf(type: StableDecl, name: string): StableDecl[] {
    return (this.methodsByName.get(name) ?? []).filter(d => d.parent === type.id);
  }

  /** Bodies overriding `name` in every subtype of `type`, sorted by id. */
  private overrides(type: StableDecl, name: string): StableDecl[] {
    const out = new Map<string, StableDecl>();
    const walk = (t: StableDecl, seen: Set<string>): void => {
      for (const s of this.subs.get(t.id) ?? []) {
        if (seen.has(s.id)) continue;
        seen.add(s.id);
        for (const m of this.membersOf(s, name)) if (!this.bodiless.has(m.id)) out.set(m.id, m);
        walk(s, seen);
      }
    };
    walk(type, new Set([type.id]));
    return [...out.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
  }

  // -- sites -----------------------------------------------------------------

  walk(ctx: FileCtx, node: Node): void {
    if (node.type === 'call_expression' || node.type === 'new_expression') this.site(ctx, node);
    for (const c of named(node)) this.walk(ctx, c);
  }

  private site(ctx: FileCtx, node: Node): void {
    const fn = node.type === 'new_expression' ? node.childForFieldName('constructor') : node.childForFieldName('function');
    if (!fn) return;
    // Module loading is not a call.
    if (node.type === 'call_expression' && (fn.type === 'import' || (fn.type === 'identifier' && fn.text === 'require' && isRequire(node)))) return;
    this.sites++;
    const site: CallEdgeSite = { file: ctx.path, line: node.startPosition.row + 1, col: node.startPosition.column };
    const from = (ctx.locate(site.line, site.col) ?? ctx.module).id;
    const edge = (to: StableDecl, tier: Tier, methodName: string, evidence: string, via?: StableDecl): void => {
      const e: CallEdge = { from, to: to.id, tier, methodName, site, evidence };
      if (via) e.via = via.id;
      this.edges.push(e);
    };
    const unresolved = (methodName: string, reason: UnresolvedReason, evidence: string): void => {
      this.unresolved.push({ from, methodName, site, reason, evidence });
    };

    if (node.type === 'new_expression') {
      this.construct(ctx, fn, edge, unresolved);
      return;
    }
    if (fn.type === 'super') {
      const cls = this.enclosingClass(ctx, node);
      const sup = cls ? this.supers.get(cls.id)?.extends : null;
      if (sup === 'external') unresolved('super', 'external', 'superclass outside the tree');
      else if (sup) this.constructType(sup, 'super', edge);
      else unresolved('super', 'unknown', 'no superclass found');
      return;
    }
    if (fn.type === 'identifier') {
      this.callName(ctx, fn, edge, unresolved);
      return;
    }
    if (fn.type === 'parenthesized_expression') {
      const inner = named(fn)[0];
      const d = inner && FUNCTION_NODES.has(inner.type) ? this.nestedDeclAt(ctx, inner) : null;
      if (d) edge(d, 'exact', '<iife>', 'immediately invoked function');
      else unresolved('<expr>', 'dynamic', 'callee is an expression');
      return;
    }
    if (fn.type === 'member_expression') {
      this.callMember(ctx, fn, edge, unresolved);
      return;
    }
    unresolved('<expr>', 'dynamic', `callee is a ${fn.type}`);
  }

  private construct(
    ctx: FileCtx,
    fn: Node,
    edge: (to: StableDecl, tier: Tier, name: string, evidence: string, via?: StableDecl) => void,
    unresolved: (name: string, reason: UnresolvedReason, evidence: string) => void,
  ): void {
    const name = fn.text;
    if (fn.type !== 'identifier' && fn.type !== 'member_expression') {
      unresolved(name, 'dynamic', 'constructed from an expression');
      return;
    }
    if (fn.type === 'identifier' && this.localBinding(fn, fn.text)) {
      unresolved(name, 'dynamic', 'class bound to a local value');
      return;
    }
    const t = this.resolveTypeRef(ctx, fn);
    if (t === 'external' || t === null) unresolved(name, 'external', 'class outside the tree');
    else this.constructType(t, name, edge);
  }

  private constructType(t: StableDecl, name: string, edge: (to: StableDecl, tier: Tier, name: string, evidence: string) => void): void {
    const ctor = this.membersOf(t, 'constructor').find(d => !this.bodiless.has(d.id));
    edge(ctor ?? t, 'exact', name, ctor ? 'constructor of a resolved class' : 'class without its own constructor');
  }

  private callName(
    ctx: FileCtx,
    fn: Node,
    edge: (to: StableDecl, tier: Tier, name: string, evidence: string) => void,
    unresolved: (name: string, reason: UnresolvedReason, evidence: string) => void,
  ): void {
    const name = fn.text;
    const local = this.localBinding(fn, name);
    if (local) {
      const holder = local.kind === 'var' ? local.node.childForFieldName('value') : local.kind === 'fn' ? local.node : null;
      const d = holder && FUNCTION_NODES.has(holder.type) ? this.nestedDeclAt(ctx, holder) : null;
      if (d) edge(d, 'exact', name, 'nested function in lexical scope');
      else unresolved(name, 'dynamic', local.kind === 'param' ? 'callee is a parameter' : 'callee is a local value');
      return;
    }
    this.bindTarget(this.resolveLocal(ctx, name), name, edge, unresolved, 'module scope or import');
  }

  private bindTarget(
    target: Target,
    name: string,
    edge: (to: StableDecl, tier: Tier, name: string, evidence: string) => void,
    unresolved: (name: string, reason: UnresolvedReason, evidence: string) => void,
    how: string,
  ): void {
    if (target.kind === 'external') {
      unresolved(name, 'external', 'imported from outside the tree');
      return;
    }
    if (target.kind === 'none') {
      unresolved(name, 'external', 'not declared in the tree (global or ambient)');
      return;
    }
    if (target.kind === 'namespace') {
      unresolved(name, 'dynamic', 'a module namespace is not callable');
      return;
    }
    const fns = target.decls.filter(d => d.kind === 'function');
    if (fns.length === 0) {
      const type = target.decls.find(d => d.kind === 'type');
      if (type) unresolved(name, 'unknown', 'a class called without new');
      else unresolved(name, 'dynamic', 'callee is a value, not a declared function');
      return;
    }
    const bodied = fns.filter(d => !this.bodiless.has(d.id));
    if (bodied.length === 1) edge(bodied[0], 'exact', name, how);
    else if (bodied.length === 0) unresolved(name, 'external', 'declared without a body (ambient)');
    else unresolved(name, 'overload-ambiguous', `${bodied.length} bodies with this name`);
  }

  private callMember(
    ctx: FileCtx,
    fn: Node,
    edge: (to: StableDecl, tier: Tier, name: string, evidence: string, via?: StableDecl) => void,
    unresolved: (name: string, reason: UnresolvedReason, evidence: string) => void,
  ): void {
    const object = fn.childForFieldName('object');
    const property = fn.childForFieldName('property');
    if (!object || !property) {
      unresolved(fn.text, 'dynamic', 'incomplete member expression');
      return;
    }
    const name = property.text;
    if (property.type === 'private_property_identifier' && object.type !== 'this') {
      unresolved(name, 'unknown', 'private member on another receiver');
      return;
    }
    // `super.m()`
    if (object.type === 'super') {
      const cls = this.enclosingClass(ctx, fn);
      const sup = cls ? this.supers.get(cls.id)?.extends : null;
      if (!sup || sup === 'external') {
        unresolved(name, sup === 'external' ? 'external' : 'unknown', 'superclass method');
        return;
      }
      const found = this.findMember(sup, name);
      if (found === 'external' || !found) unresolved(name, found === 'external' ? 'external' : 'unknown', 'superclass method not in the tree');
      else this.bindMembers(found.decls, name, 'exact', edge, unresolved, 'super call');
      return;
    }
    // `ns.f()` on a module namespace, `C.m()` on a class name
    if (object.type === 'identifier' && !this.localBinding(object, object.text)) {
      const target = this.resolveLocal(ctx, object.text);
      if (target.kind === 'namespace') {
        this.bindTarget(this.resolveExport(target.ctx, name, 0), name, edge, unresolved, 'module namespace');
        return;
      }
      if (target.kind === 'external' || (target.kind === 'none' && !ctx.topVars.has(object.text))) {
        unresolved(name, 'external', 'receiver declared outside the tree');
        return;
      }
      if (target.kind === 'decls') {
        const type = target.decls.find(d => d.kind === 'type');
        if (type) {
          const found = this.findMember(type, name);
          if (found && found !== 'external') this.bindMembers(found.decls, name, 'exact', edge, unresolved, 'static member of a resolved class');
          else unresolved(name, found === 'external' ? 'external' : 'unknown', 'static member not found');
          return;
        }
      }
    }
    const type = this.typeOf(ctx, object);
    if (type === 'external') {
      unresolved(name, 'external', 'receiver type declared outside the tree');
      return;
    }
    if (type) {
      this.dispatch(type, name, edge, unresolved);
      return;
    }
    this.infer(name, edge, unresolved);
  }

  private dispatch(
    type: StableDecl,
    name: string,
    edge: (to: StableDecl, tier: Tier, name: string, evidence: string, via?: StableDecl) => void,
    unresolved: (name: string, reason: UnresolvedReason, evidence: string) => void,
  ): void {
    const found = this.findMember(type, name);
    if (found === 'external') {
      unresolved(name, 'external', 'member inherited from outside the tree');
      return;
    }
    if (!found) {
      unresolved(name, 'unknown', 'member not found on the receiver type');
      return;
    }
    const bodied = found.decls.filter(d => !this.bodiless.has(d.id));
    if (bodied.length > 1) {
      unresolved(name, 'overload-ambiguous', `${bodied.length} bodies with this name`);
      return;
    }
    const declaring = bodied[0] ?? found.decls[0];
    const subs = this.overrides(found.owner, name);
    if (bodied.length === 1 && subs.length === 0) {
      edge(bodied[0], 'exact', name, 'receiver type known; no override in the tree');
      return;
    }
    const bodies = [...(bodied.length === 1 ? [bodied[0]] : []), ...subs];
    if (bodies.length === 0) {
      unresolved(name, 'external', 'abstract or interface member with no implementation in the tree');
      return;
    }
    for (const b of bodies) edge(b, 'polymorphic', name, 'receiver type known; dispatch open', declaring);
  }

  private bindMembers(
    decls: StableDecl[],
    name: string,
    tier: Tier,
    edge: (to: StableDecl, tier: Tier, name: string, evidence: string) => void,
    unresolved: (name: string, reason: UnresolvedReason, evidence: string) => void,
    evidence: string,
  ): void {
    const bodied = decls.filter(d => !this.bodiless.has(d.id));
    if (bodied.length === 1) edge(bodied[0], tier, name, evidence);
    else if (bodied.length === 0) unresolved(name, 'unknown', 'member declared without a body');
    else unresolved(name, 'overload-ambiguous', `${bodied.length} bodies with this name`);
  }

  private infer(
    name: string,
    edge: (to: StableDecl, tier: Tier, name: string, evidence: string) => void,
    unresolved: (name: string, reason: UnresolvedReason, evidence: string) => void,
  ): void {
    const all = (this.methodsByName.get(name) ?? []).filter(d => !this.bodiless.has(d.id));
    if (all.length === 0) {
      unresolved(name, 'unknown', 'receiver type unknown and no method of this name in the tree');
      return;
    }
    if (all.length > this.maxInferred) {
      unresolved(name, 'unknown', `receiver type unknown; ${all.length} methods of this name exceed the bound`);
      return;
    }
    for (const d of [...all].sort((a, b) => (a.id < b.id ? -1 : 1))) edge(d, 'inferred', name, 'bound by name alone');
  }

  run(): void {
    for (const ctx of this.sortedFiles()) this.walk(ctx, ctx.root);
  }
}

/**
 * Call edges for a set of TypeScript/JavaScript files. Files of other
 * extensions are ignored. Deterministic: the same files give the same graph.
 */
export async function buildTsCallGraph(files: readonly TsSourceFile[], options: TsCallGraphOptions = {}): Promise<TsCallGraph> {
  const graph = new Graph(options);
  const trees: Tree[] = [];
  const out: StableIdFile[] = [];
  const partial: string[] = [];
  try {
    const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    for (const f of sorted) {
      const path = normalizePath(f.path.replace(/\\/g, '/'));
      const lang = languageOf(path);
      if (!lang) continue;
      const tree = await parse(f.code, lang.grammar);
      trees.push(tree);
      const ids = deriveTypeScriptIds(tree, path, lang.ids, f.ids ?? {});
      if (ids.partial) partial.push(path);
      out.push(ids);
      graph.add(path, tree, ids);
    }
    graph.link();
    graph.run();
  } finally {
    for (const t of trees) disposeTree(t);
  }
  const bySite = (a: { site: CallEdgeSite }, b: { site: CallEdgeSite }): number =>
    a.site.file < b.site.file ? -1 : a.site.file > b.site.file ? 1 : a.site.line - b.site.line || a.site.col - b.site.col;
  return {
    scheme: TS_CALL_EDGES_SCHEME,
    ids: 'ids@0.1',
    files: out,
    edges: [...graph.edges].sort((a, b) => bySite(a, b) || (a.to < b.to ? -1 : a.to > b.to ? 1 : 0)),
    unresolved: [...graph.unresolved].sort(bySite),
    partial,
    sites: graph.siteCount,
  };
}
