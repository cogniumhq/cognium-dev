/**
 * `ids@0.1` declaration and body ids for Python.
 *
 * Declarations: the module (its dotted name); functions; classes (kind
 * `type`); methods; module- and class-level assignments to a plain name
 * (kind `field`). Functions, classes and lambdas inside a body are keyed by
 * their enclosing declaration plus a structural path and flagged
 * `unstable:anonymous`.
 *
 * Module name: the file's dotted path — `src/` dropped, `__init__` naming
 * its package — unless the caller passes one. Signature: arity plus
 * annotations, parameter names never — `(_,int?,*_,_?,**_)->str` — so a
 * parameter rename does not re-key a function. Decorators are body.
 *
 * Bodies: leaf tokens as in the other languages, with each `block` marked so
 * that indentation, which carries Python's structure, is not lost; comments
 * and docstrings are not body.
 */

import { partialOf } from './parse-errors.js';
import type { Node, Tree } from '../core/parser.js';
import { Builder, placeholder } from './builder.js';
import { bodyTokens, namedChildren } from './normalize.js';
import { STABLE_ID_SCHEME, type StableDecl, type StableDeclKind, type StableIdFile, type StableIdOptions } from './types.js';

const WRAP: ReadonlySet<string> = new Set(['block']);
const NESTED = new Set(['function_definition', 'class_definition', 'lambda']);

/** The dotted module name for a repository-relative `.py` path. */
export function pythonModuleName(filePath: string): string {
  let p = filePath.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\.pyi?$/, '');
  if (p.startsWith('src/')) p = p.slice(4);
  const parts = p.split('/').filter(x => x !== '');
  if (parts[parts.length - 1] === '__init__') parts.pop();
  return parts.join('.') || '__main__';
}

function compact(text: string): string {
  return text.replace(/\s+/g, '');
}

/** `(_,int?,*_,**_)->T` — names never, annotations and defaults (as `?`) always. */
export function pythonSignature(fn: Node): string {
  const params = fn.childForFieldName('parameters');
  const out: string[] = [];
  for (const p of params ? namedChildren(params) : []) {
    switch (p.type) {
      case 'identifier': out.push('_'); break;
      case 'typed_parameter': {
        const inner = namedChildren(p)[0];
        const t = compact(p.childForFieldName('type')?.text ?? '_');
        out.push(inner?.type === 'list_splat_pattern' ? `*${t}` : inner?.type === 'dictionary_splat_pattern' ? `**${t}` : t);
        break;
      }
      case 'default_parameter': out.push('_?'); break;
      case 'typed_default_parameter': out.push(compact(p.childForFieldName('type')?.text ?? '_') + '?'); break;
      case 'list_splat_pattern': out.push('*_'); break;
      case 'dictionary_splat_pattern': out.push('**_'); break;
      case 'keyword_separator': out.push('*'); break;
      case 'positional_separator': out.push('/'); break;
      default: out.push('_');
    }
  }
  const ret = fn.childForFieldName('return_type');
  return '(' + out.join(',') + ')' + (ret ? '->' + compact(ret.text) : '');
}

/** The docstring statement of a block, if it opens with one. */
function docstring(block: Node | null): Node | null {
  const first = block ? namedChildren(block)[0] : undefined;
  if (first?.type !== 'expression_statement') return null;
  const inner = namedChildren(first);
  return inner.length === 1 && inner[0].type === 'string' ? first : null;
}

/** The definition a statement holds, and the node that carries its decorators. */
function definitionOf(stmt: Node): { def: Node; holder: Node } | null {
  if (stmt.type === 'decorated_definition') {
    const def = stmt.childForFieldName('definition');
    return def ? { def, holder: stmt } : null;
  }
  if (stmt.type === 'function_definition' || stmt.type === 'class_definition') return { def: stmt, holder: stmt };
  return null;
}

class PythonExtractor {
  constructor(private readonly b: Builder) {}

  private tokens(nodes: Node[], skip: Set<number>, replace?: Map<number, string>): string[] {
    return bodyTokens(nodes, { skip, replace, wrap: WRAP });
  }

  /** `self` is the declaration's own definition under its decorators: walked through, not declared again. */
  nested(node: Node, enclosing: StableDecl, exclude: ReadonlySet<number>, path = '', self: Node | null = null): void {
    const kids = namedChildren(node);
    for (let i = 0; i < kids.length; i++) {
      const c = kids[i];
      if (exclude.has(c.id)) continue;
      const p = path === '' ? `${i}` : `${path}.${i}`;
      if (NESTED.has(c.type) && c.id !== self?.id) this.declareNested(c, enclosing, p);
      else this.nested(c, enclosing, exclude, p, self);
    }
  }

  private declareNested(node: Node, enclosing: StableDecl, path: string): void {
    const own = node.childForFieldName('name');
    const name = own?.text ?? '<lambda>';
    const kind: StableDeclKind = node.type === 'class_definition' ? 'type' : 'function';
    let signature = '';
    if (node.type === 'function_definition') signature = pythonSignature(node);
    else if (node.type === 'lambda') {
      const params = node.childForFieldName('parameters');
      signature = '(' + (params ? namedChildren(params).map(() => '_').join(',') : '') + ')';
    }
    const holder = node.parent?.type === 'decorated_definition' ? node.parent : node;
    const decl = this.b.add(kind, name, `${enclosing.qualified_name}/${name}@${path}`, signature, holder, enclosing.id, ['unstable:anonymous']);
    const skip = new Set<number>(own ? [own.id] : []);
    const doc = docstring(node.childForFieldName('body'));
    if (doc) skip.add(doc.id);
    this.b.setBody(decl, this.tokens([holder], skip));
    this.nested(holder, decl, skip, '', node);
  }

  /** One statement of a module or class body. */
  statement(stmt: Node, prefix: string, parent: StableDecl, inClass: boolean, replace: Map<number, string>): void {
    const d = definitionOf(stmt);
    if (d) {
      const nameNode = d.def.childForFieldName('name');
      const name = nameNode?.text ?? '<unnamed>';
      if (d.def.type === 'class_definition') {
        this.type(d.def, d.holder, name, nameNode, prefix, parent, replace);
        return;
      }
      const kind: StableDeclKind = inClass ? 'method' : 'function';
      const signature = pythonSignature(d.def);
      const decl = this.b.add(kind, name, prefix + name, signature, d.holder, parent.id);
      replace.set(d.holder.id, placeholder(kind, name, signature));
      const skip = new Set<number>(nameNode ? [nameNode.id] : []);
      const doc = docstring(d.def.childForFieldName('body'));
      if (doc) skip.add(doc.id);
      this.b.setBody(decl, this.tokens([d.holder], skip));
      this.nested(d.holder, decl, skip, '', d.def);
      return;
    }
    if (stmt.type === 'expression_statement') {
      const a = namedChildren(stmt)[0];
      if (a?.type !== 'assignment') return;
      const left = a.childForFieldName('left');
      if (left?.type !== 'identifier') return;
      const t = a.childForFieldName('type');
      const signature = t ? compact(t.text) : '';
      const decl = this.b.add('field', left.text, prefix + left.text, signature, stmt, parent.id);
      replace.set(stmt.id, placeholder('field', left.text, signature));
      const skip = new Set<number>([left.id]);
      this.b.setBody(decl, this.tokens([stmt], skip));
      this.nested(stmt, decl, skip);
    }
  }

  private type(def: Node, holder: Node, name: string, nameNode: Node | null, prefix: string, parent: StableDecl, replace: Map<number, string>): void {
    const supers = def.childForFieldName('superclasses');
    const signature = supers ? compact(supers.text) : '';
    const decl = this.b.add('type', name, prefix + name, signature, holder, parent.id);
    replace.set(holder.id, placeholder('type', name, signature));
    const inner = new Map<number, string>();
    const body = def.childForFieldName('body');
    const doc = docstring(body);
    for (const s of body ? namedChildren(body) : []) {
      if (s !== doc) this.statement(s, decl.qualified_name + '.', decl, true, inner);
    }
    const skip = new Set<number>(nameNode ? [nameNode.id] : []);
    if (doc) skip.add(doc.id);
    this.b.setBody(decl, this.tokens([holder], skip, inner));
    this.nested(holder, decl, new Set([...skip, ...inner.keys()]), '', def);
  }

  module(root: Node, decl: StableDecl): void {
    const replace = new Map<number, string>();
    const doc = docstring(root);
    for (const s of namedChildren(root)) if (s !== doc) this.statement(s, decl.qualified_name + ':', decl, false, replace);
    const skip = new Set<number>(doc ? [doc.id] : []);
    this.b.setBody(decl, this.tokens([root], skip, replace));
    this.nested(root, decl, new Set([...skip, ...replace.keys()]));
  }
}

/** Derive `ids@0.1` ids from an already-parsed Python tree. */
export function derivePythonIds(tree: Tree, filePath: string, options: StableIdOptions = {}): StableIdFile {
  const module = options.module ?? pythonModuleName(filePath);
  const builder = new Builder('python', options.keepBodyTokens === true);
  const moduleDecl = builder.add('module', module, module, '', tree.rootNode, null);
  new PythonExtractor(builder).module(tree.rootNode, moduleDecl);
  return { scheme: STABLE_ID_SCHEME, file: filePath, language: 'python', module, decls: builder.decls, ...partialOf(tree.rootNode) };
}
