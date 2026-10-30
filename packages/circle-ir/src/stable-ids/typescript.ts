/**
 * `ids@0.1` declaration and body ids for TypeScript and JavaScript.
 *
 * Declarations: the module itself; functions (declarations, overload
 * signatures, `const f = () => …`, `exports.f = function …`); classes,
 * interfaces, type aliases and enums (kind `type`); methods and accessors;
 * class fields, interface properties and module-level variables (kind
 * `field`); namespaces and ambient modules (kind `module`). Functions and
 * classes nested inside a body, and callbacks in top-level code, are keyed by
 * their enclosing declaration plus a structural path and flagged
 * `unstable:anonymous`.
 *
 * Bodies: a leaf declaration's body is its whole subtree minus its own name
 * (so a rename keeps the body hash). A container's body (module, namespace,
 * class, interface) is its own tokens with each member replaced by a
 * placeholder of the member's kind, name and signature — editing a method body
 * changes the method's body id, not the class's; adding, removing or renaming
 * a member changes both.
 */

import type { Node, Tree } from '../core/parser.js';
import { Builder, placeholder } from './builder.js';
import { bodyTokens, canonicalType, joinTokens, namedChildren } from './normalize.js';
import {
  STABLE_ID_SCHEME,
  type StableDecl,
  type StableDeclKind,
  type StableIdFile,
  type StableIdFlag,
  type StableIdOptions,
} from './types.js';

const FUNCTION_VALUES = new Set(['arrow_function', 'function_expression', 'function', 'generator_function']);
const CLASS_VALUES = new Set(['class']);
const FUNCTION_DECLS = new Set(['function_declaration', 'generator_function_declaration', 'function_signature']);
const CLASS_DECLS = new Set(['class_declaration', 'abstract_class_declaration']);
const NESTED = new Set([
  ...FUNCTION_VALUES, ...CLASS_VALUES,
  'function_declaration', 'generator_function_declaration', 'method_definition', 'class_declaration',
]);
const METHODS = new Set(['method_definition', 'abstract_method_signature', 'method_signature']);
const FIELDS = new Set(['public_field_definition', 'field_definition', 'property_signature']);
const NAMESPACES = new Set(['internal_module', 'module']);

/** The repository-relative path with its extension removed, `\` as `/`. */
function stripExtension(path: string): string {
  return path.replace(/\.(?:[mc]?[jt]s|[jt]sx)$/, '');
}

/**
 * The module path for a TypeScript/JavaScript file: the package name plus the
 * path inside `src/` (or inside the package when it has no `src/`), extension
 * removed; without a package name, the repository-relative path.
 */
export function moduleNameFor(filePath: string, options: StableIdOptions = {}): string {
  let path = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
  if (!options.packageName) return stripExtension(path);
  const root = (options.packageRoot ?? '').replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/$/, '');
  if (root !== '' && path.startsWith(root + '/')) path = path.slice(root.length + 1);
  if (path.startsWith('src/')) path = path.slice(4);
  return `${options.packageName}/${stripExtension(path)}`;
}

function hasToken(node: Node, text: string, before?: Node | null): boolean {
  for (let i = 0; i < node.childCount; i++) {
    const c = node.child(i);
    if (!c) continue;
    if (before && c.id === before.id) return false;
    if (!c.isNamed && c.text === text) return true;
  }
  return false;
}

function nameText(node: Node | null): string | null {
  if (!node) return null;
  if (node.type === 'string') {
    const frag = namedChildren(node).map(c => c.text).join('');
    return frag;
  }
  return joinTokens(bodyTokens([node]));
}

function paramSignature(p: Node): string {
  switch (p.type) {
    case 'required_parameter':
    case 'optional_parameter': {
      const pattern = p.childForFieldName('pattern');
      const type = p.childForFieldName('type');
      const value = p.childForFieldName('value');
      const t = type ? canonicalType(type) : '_';
      const rest = pattern?.type === 'rest_pattern' ? '...' : '';
      const self = pattern?.type === 'this' ? 'this:' : '';
      const optional = p.type === 'optional_parameter' || value ? '?' : '';
      return self + rest + t + optional;
    }
    case 'assignment_pattern':
      return '_?';
    case 'rest_pattern':
      return '..._';
    default:
      return '_';
  }
}

/** `[static ][get |set ][<T…>](P1,P2?,...P3)[:R]` — parameter names never take part. */
function functionSignature(fn: Node, prefix = ''): string {
  const typeParams = fn.childForFieldName('type_parameters');
  const params = fn.childForFieldName('parameters');
  const single = fn.childForFieldName('parameter');
  let list: string[] = [];
  if (params) list = namedChildren(params).map(paramSignature);
  else if (single) list = ['_'];
  const ret = fn.childForFieldName('return_type');
  return prefix
    + (typeParams ? canonicalType(typeParams) : '')
    + '(' + list.join(',') + ')'
    + (ret ? ':' + canonicalType(ret) : '');
}

function typeSignature(node: Node): string {
  const typeParams = node.childForFieldName('type_parameters');
  return typeParams ? canonicalType(typeParams) : '';
}

function memberPrefix(member: Node): string {
  const name = member.childForFieldName('name') ?? member.childForFieldName('property');
  let prefix = hasToken(member, 'static', name) ? 'static ' : '';
  if (hasToken(member, 'get', name)) prefix += 'get ';
  else if (hasToken(member, 'set', name)) prefix += 'set ';
  return prefix;
}

/** Name of a nested function or class: its own, or the binding it is assigned to. */
function localName(node: Node): string | null {
  const own = node.childForFieldName('name');
  if (own) return nameText(own);
  const parent = node.parent;
  if (!parent) return null;
  if (parent.type === 'variable_declarator') return nameText(parent.childForFieldName('name'));
  if (parent.type === 'pair') return nameText(parent.childForFieldName('key'));
  if (parent.type === 'assignment_expression') return nameText(parent.childForFieldName('left'));
  if (parent.type === 'public_field_definition' || parent.type === 'field_definition') {
    return nameText(parent.childForFieldName('name') ?? parent.childForFieldName('property'));
  }
  return null;
}

/** `exports.X` / `module.exports.X` → `X`. */
function commonJsExportName(left: Node | null): string | null {
  if (!left || left.type !== 'member_expression') return null;
  const object = left.childForFieldName('object');
  const property = left.childForFieldName('property');
  if (!object || !property) return null;
  const o = joinTokens(bodyTokens([object]));
  return o === 'exports' || o === 'module.exports' ? property.text : null;
}

class Extractor {
  constructor(private readonly b: Builder) {}

  /** Functions and classes inside `node`'s subtree, keyed under `enclosing`. */
  nested(
    node: Node,
    enclosing: StableDecl,
    exclude: ReadonlySet<number>,
    path = '',
    self: Node | null = null,
  ): void {
    const kids = namedChildren(node);
    for (let i = 0; i < kids.length; i++) {
      const c = kids[i];
      if (exclude.has(c.id)) continue;
      const p = path === '' ? `${i}` : `${path}.${i}`;
      // `self` is the declaration's own function value (`const f = () => …`):
      // walked through, never declared a second time as a nested function.
      if (NESTED.has(c.type) && c.id !== self?.id) this.declareNested(c, enclosing, p);
      else this.nested(c, enclosing, exclude, p, self);
    }
  }

  private declareNested(node: Node, enclosing: StableDecl, path: string): void {
    const name = localName(node) ?? '<anonymous>';
    const isClass = node.type === 'class' || node.type === 'class_declaration';
    const kind: StableDeclKind = isClass ? 'type' : 'function';
    const signature = isClass ? typeSignature(node) : functionSignature(node, node.type === 'method_definition' ? memberPrefix(node) : '');
    const decl = this.b.add(kind, name, `${enclosing.qualified_name}/${name}@${path}`, signature, node, enclosing.id, ['unstable:anonymous']);
    const own = node.childForFieldName('name');
    const skip = new Set<number>(own ? [own.id] : []);
    this.b.setBody(decl, bodyTokens([node], { skip }));
    this.nested(node, decl, skip);
  }

  /** A leaf declaration: body = `nodes` minus `nameNode`, nested functions under it. */
  private leaf(
    kind: StableDeclKind,
    name: string,
    prefix: string,
    signature: string,
    at: Node,
    nodes: Node[],
    nameNode: Node | null,
    parent: StableDecl,
    self: Node | null = null,
  ): StableDecl {
    const decl = this.b.add(kind, name, prefix + name, signature, at, parent.id);
    const skip = new Set<number>(nameNode ? [nameNode.id] : []);
    this.b.setBody(decl, bodyTokens(nodes, { skip }));
    for (const n of nodes) this.nested(n, decl, skip, '', self);
    return decl;
  }

  /**
   * One statement of a module or namespace body. Members found are added to
   * `replace` (member node → placeholder) so the container's own body does
   * not change when only a member's body does.
   */
  statement(stmt: Node, prefix: string, parent: StableDecl, replace: Map<number, string>): void {
    const t = stmt.type;
    if (t === 'export_statement') {
      const declaration = stmt.childForFieldName('declaration');
      if (declaration) {
        this.statement(declaration, prefix, parent, replace);
        return;
      }
      const value = stmt.childForFieldName('value');
      if (value && (FUNCTION_VALUES.has(value.type) || CLASS_VALUES.has(value.type))) {
        this.binding('default', value, value, null, prefix, parent, replace);
      }
      return;
    }
    if (t === 'ambient_declaration' || (t === 'expression_statement' && stmt.namedChildCount === 1 && NAMESPACES.has(stmt.namedChild(0)?.type ?? ''))) {
      for (const c of namedChildren(stmt)) this.statement(c, prefix, parent, replace);
      return;
    }
    if (FUNCTION_DECLS.has(t) || FUNCTION_VALUES.has(t) || CLASS_DECLS.has(t) || CLASS_VALUES.has(t)) {
      const nameNode = stmt.childForFieldName('name');
      this.binding(nameNode ? nameText(nameNode) ?? 'default' : 'default', stmt, stmt, nameNode, prefix, parent, replace);
      return;
    }
    if (t === 'interface_declaration') {
      const nameNode = stmt.childForFieldName('name');
      const decl = this.b.add('type', nameText(nameNode) ?? 'default', prefix + (nameText(nameNode) ?? 'default'), typeSignature(stmt), stmt, parent.id);
      replace.set(stmt.id, placeholder('type', decl.name, decl.signature));
      this.members(decl, stmt, nameNode, stmt.childForFieldName('body'));
      return;
    }
    if (t === 'type_alias_declaration' || t === 'enum_declaration') {
      const nameNode = stmt.childForFieldName('name');
      const name = nameText(nameNode) ?? 'default';
      const signature = typeSignature(stmt);
      this.leaf('type', name, prefix, signature, stmt, [stmt], nameNode, parent);
      replace.set(stmt.id, placeholder('type', name, signature));
      return;
    }
    if (NAMESPACES.has(t)) {
      const nameNode = stmt.childForFieldName('name');
      const name = nameText(nameNode) ?? 'global';
      const decl = this.b.add('module', name, prefix + name, '', stmt, parent.id);
      replace.set(stmt.id, placeholder('module', name, ''));
      const inner = new Map<number, string>();
      const body = stmt.childForFieldName('body');
      if (body) for (const s of namedChildren(body)) this.statement(s, decl.qualified_name + '.', decl, inner);
      const skip = new Set<number>(nameNode ? [nameNode.id] : []);
      this.b.setBody(decl, bodyTokens([stmt], { skip, replace: inner }));
      this.nested(stmt, decl, new Set([...skip, ...inner.keys()]));
      return;
    }
    if (t === 'lexical_declaration' || t === 'variable_declaration') {
      for (const d of namedChildren(stmt)) {
        if (d.type !== 'variable_declarator') continue;
        const nameNode = d.childForFieldName('name');
        if (nameNode?.type !== 'identifier') continue;
        const value = d.childForFieldName('value');
        this.binding(nameNode.text, d, value, nameNode, prefix, parent, replace);
      }
      return;
    }
    if (t === 'expression_statement') {
      const expr = stmt.namedChild(0);
      if (expr?.type === 'assignment_expression') {
        const name = commonJsExportName(expr.childForFieldName('left'));
        if (name) this.binding(name, expr, expr.childForFieldName('right'), expr.childForFieldName('left'), prefix, parent, replace);
      }
    }
  }

  /**
   * A named binding at module or namespace level: `holder` is the node that
   * is replaced in the container, `value` decides the kind.
   */
  private binding(
    name: string,
    holder: Node,
    value: Node | null,
    nameNode: Node | null,
    prefix: string,
    parent: StableDecl,
    replace: Map<number, string>,
  ): void {
    const v = value ?? holder;
    if (CLASS_DECLS.has(v.type) || CLASS_VALUES.has(v.type)) {
      const decl = this.b.add('type', name, prefix + name, typeSignature(v), holder, parent.id);
      replace.set(holder.id, placeholder('type', name, decl.signature));
      const ownName = v.childForFieldName('name');
      const skipName = new Set<number>([...(nameNode ? [nameNode.id] : []), ...(ownName ? [ownName.id] : [])]);
      this.members(decl, holder, null, v.childForFieldName('body'), skipName);
      return;
    }
    if (value && (FUNCTION_DECLS.has(v.type) || FUNCTION_VALUES.has(v.type))) {
      const signature = functionSignature(v);
      this.leaf('function', name, prefix, signature, holder, [holder], nameNode, parent, v);
      replace.set(holder.id, placeholder('function', name, signature));
      return;
    }
    this.leaf('field', name, prefix, '', holder, [holder], nameNode, parent);
    replace.set(holder.id, placeholder('field', name, ''));
  }

  /** Members of a class or interface body; then the container's own body. */
  private members(decl: StableDecl, node: Node, nameNode: Node | null, body: Node | null, extraSkip: ReadonlySet<number> = new Set()): void {
    const replace = new Map<number, string>();
    const prefix = decl.qualified_name + '.';
    let decorators: Node[] = [];
    if (body) {
      for (const m of namedChildren(body)) {
        if (m.type === 'decorator') {
          decorators.push(m);
          continue;
        }
        const memberName = m.childForFieldName('name') ?? m.childForFieldName('property');
        const nodes = [...decorators, m];
        if (METHODS.has(m.type)) {
          const name = nameText(memberName) ?? '<computed>';
          const signature = functionSignature(m, memberPrefix(m));
          this.leaf('method', name, prefix, signature, m, nodes, memberName, decl);
          replace.set(m.id, placeholder('method', name, signature));
          for (const d of decorators) replace.set(d.id, '');
        } else if (FIELDS.has(m.type)) {
          const name = nameText(memberName) ?? '<computed>';
          const signature = memberPrefix(m).trim();
          this.leaf('field', name, prefix, signature, m, nodes, memberName, decl);
          replace.set(m.id, placeholder('field', name, signature));
          for (const d of decorators) replace.set(d.id, '');
        }
        decorators = [];
      }
    }
    const skip = new Set<number>([...extraSkip, ...(nameNode ? [nameNode.id] : [])]);
    this.b.setBody(decl, bodyTokens([node], { skip, replace }));
    this.nested(node, decl, new Set([...skip, ...replace.keys()]));
  }

  module(root: Node, decl: StableDecl): void {
    const replace = new Map<number, string>();
    for (const stmt of namedChildren(root)) this.statement(stmt, decl.qualified_name + ':', decl, replace);
    this.b.setBody(decl, bodyTokens([root], { replace }));
    this.nested(root, decl, new Set(replace.keys()));
  }
}

/** Derive `ids@0.1` ids from an already-parsed TypeScript/JavaScript tree. */
export function deriveTypeScriptIds(
  tree: Tree,
  filePath: string,
  language: 'javascript' | 'typescript',
  options: StableIdOptions = {},
): StableIdFile {
  const module = options.module ?? moduleNameFor(filePath, options);
  const builder = new Builder(language, options.keepBodyTokens === true);
  const root = tree.rootNode;
  const moduleDecl = builder.add('module', module, module, '', root, null);
  new Extractor(builder).module(root, moduleDecl);
  return {
    scheme: STABLE_ID_SCHEME,
    file: filePath,
    language,
    module,
    decls: builder.decls,
    partial: root.hasError,
  };
}
