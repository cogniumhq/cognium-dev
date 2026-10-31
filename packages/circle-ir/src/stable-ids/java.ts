/**
 * `ids@0.1` declaration and body ids for Java.
 *
 * Declarations: the compilation unit (`module`, named `<package>/<File>`);
 * classes, interfaces, enums, records and annotation types (kind `type`);
 * methods, constructors (named `constructor`) and static initializers
 * (`<clinit>`) (kind `method`); fields, enum constants and record components
 * (kind `field`). Lambdas, anonymous classes and local classes inside a body
 * are keyed by their enclosing declaration plus a structural path and
 * flagged `unstable:anonymous`.
 *
 * Qualified name: `<package>:<Outer>.<Inner>.<member>` (`<default>` for the
 * default package). Signature: the erased parameter types, simple names —
 * `(List,String[],int...)` — so a parameter rename, a generic argument
 * change or an import change does not re-key a method, and overloads stay
 * apart. Type variables keep their names.
 *
 * Bodies follow the TypeScript rules: a leaf's body is its subtree minus its
 * own name; a type's body holds a placeholder per member, so editing a
 * method changes only the method's body id.
 */

import { partialOf } from './parse-errors.js';
import type { Node, Tree } from '../core/parser.js';
import { Builder, placeholder } from './builder.js';
import { bodyTokens, namedChildren } from './normalize.js';
import { STABLE_ID_SCHEME, type StableDecl, type StableDeclKind, type StableIdFile, type StableIdOptions } from './types.js';

const TYPE_DECLS = new Set([
  'class_declaration', 'interface_declaration', 'enum_declaration', 'record_declaration', 'annotation_type_declaration',
]);
const NESTED = new Set(['lambda_expression', 'class_declaration', 'record_declaration', 'enum_declaration', 'interface_declaration']);

/** A Java type as written, erased: generics and annotations dropped, last name segment kept, dimensions kept. */
export function eraseJavaType(text: string): string {
  let t = text.replace(/@[\w.]+(\([^)]*\))?\s*/g, '').replace(/\bfinal\s+/g, '').trim();
  let prev = '';
  while (prev !== t) {
    prev = t;
    t = t.replace(/<[^<>]*>/g, '');
  }
  t = t.replace(/\s+/g, '');
  let dims = '';
  while (t.endsWith('[]')) {
    dims += '[]';
    t = t.slice(0, -2);
  }
  const base = t.split('.').pop() ?? t;
  return base + dims;
}

function paramSignature(params: Node | null): string {
  if (!params) return '()';
  const out: string[] = [];
  for (const p of namedChildren(params)) {
    if (p.type === 'formal_parameter') {
      const type = p.childForFieldName('type');
      const dims = p.childForFieldName('dimensions');
      out.push(eraseJavaType((type?.text ?? '_') + (dims?.text ?? '')));
    } else if (p.type === 'spread_parameter') {
      const type = namedChildren(p).find(c => c.type !== 'modifiers' && c.type !== 'variable_declarator');
      out.push(eraseJavaType(type?.text ?? '_') + '...');
    }
  }
  return '(' + out.join(',') + ')';
}

function typeParams(node: Node): string {
  const tp = node.childForFieldName('type_parameters');
  return tp ? '<' + namedChildren(tp).map(c => c.childForFieldName('name')?.text ?? namedChildren(c)[0]?.text ?? c.text).join(',') + '>' : '';
}

function packageOf(root: Node): string {
  for (const c of namedChildren(root)) {
    if (c.type === 'package_declaration') {
      const n = namedChildren(c).find(x => x.type === 'scoped_identifier' || x.type === 'identifier');
      if (n) return n.text.replace(/\s+/g, '');
    }
  }
  return '';
}

function fileBase(path: string): string {
  const name = path.replace(/\\/g, '/').split('/').pop() ?? path;
  return name.replace(/\.java$/, '');
}

class JavaExtractor {
  constructor(private readonly b: Builder) {}

  /** Lambdas, anonymous and local classes inside `node`, keyed under `enclosing`. */
  nested(node: Node, enclosing: StableDecl, exclude: ReadonlySet<number>, path = ''): void {
    const kids = namedChildren(node);
    for (let i = 0; i < kids.length; i++) {
      const c = kids[i];
      if (exclude.has(c.id)) continue;
      const p = path === '' ? `${i}` : `${path}.${i}`;
      const anonymousClass = c.type === 'object_creation_expression' ? c.childForFieldName('body') ?? namedChildren(c).find(x => x.type === 'class_body') : null;
      if (NESTED.has(c.type) || anonymousClass) this.declareNested(c, enclosing, p, anonymousClass ?? null);
      else this.nested(c, enclosing, exclude, p);
    }
  }

  private declareNested(node: Node, enclosing: StableDecl, path: string, anonymousBody: Node | null): void {
    const isLambda = node.type === 'lambda_expression';
    const kind: StableDeclKind = isLambda ? 'function' : 'type';
    const own = isLambda || anonymousBody ? null : node.childForFieldName('name');
    const name = own?.text ?? (anonymousBody ? `<anonymous ${eraseJavaType(node.childForFieldName('type')?.text ?? '')}>` : '<lambda>');
    let signature = '';
    if (isLambda) {
      const params = node.childForFieldName('parameters');
      signature = params?.type === 'formal_parameters' ? paramSignature(params) : `(${params ? namedChildren(params).map(() => '_').join(',') || '_' : ''})`;
    }
    const decl = this.b.add(kind, name, `${enclosing.qualified_name}/${name}@${path}`, signature, node, enclosing.id, ['unstable:anonymous']);
    const skip = new Set<number>(own ? [own.id] : []);
    this.b.setBody(decl, bodyTokens([node], { skip }));
    this.nested(anonymousBody ?? node, decl, skip);
  }

  /** A type declaration and its members. */
  type(node: Node, prefix: string, parent: StableDecl, replace: Map<number, string>): void {
    const nameNode = node.childForFieldName('name');
    const name = nameNode?.text ?? '<unnamed>';
    const signature = typeParams(node);
    const decl = this.b.add('type', name, prefix + name, signature, node, parent.id);
    replace.set(node.id, placeholder('type', name, signature));
    const inner = new Map<number, string>();
    const memberPrefix = decl.qualified_name + '.';
    // Record components are fields declared in the header.
    if (node.type === 'record_declaration') {
      const params = node.childForFieldName('parameters');
      for (const p of params ? namedChildren(params) : []) {
        const pn = p.childForFieldName('name');
        if (!pn) continue;
        const f = this.b.add('field', pn.text, memberPrefix + pn.text, eraseJavaType(p.childForFieldName('type')?.text ?? ''), p, decl.id);
        this.b.setBody(f, bodyTokens([p], { skip: new Set([pn.id]) }));
      }
    }
    const body = node.childForFieldName('body');
    for (const m of body ? namedChildren(body) : []) this.member(m, memberPrefix, decl, inner);
    const skip = new Set<number>(nameNode ? [nameNode.id] : []);
    this.b.setBody(decl, bodyTokens([node], { skip, replace: inner }));
    this.nested(node, decl, new Set([...skip, ...inner.keys()]));
  }

  private leaf(kind: StableDeclKind, name: string, prefix: string, signature: string, node: Node, nameNode: Node | null, parent: StableDecl, replace: Map<number, string>): void {
    const decl = this.b.add(kind, name, prefix + name, signature, node, parent.id);
    replace.set(node.id, placeholder(kind, name, signature));
    const skip = new Set<number>(nameNode ? [nameNode.id] : []);
    this.b.setBody(decl, bodyTokens([node], { skip }));
    this.nested(node, decl, skip);
  }

  private member(m: Node, prefix: string, parent: StableDecl, replace: Map<number, string>): void {
    const t = m.type;
    if (TYPE_DECLS.has(t)) {
      this.type(m, prefix, parent, replace);
      return;
    }
    if (t === 'enum_body_declarations') {
      for (const c of namedChildren(m)) this.member(c, prefix, parent, replace);
      return;
    }
    if (t === 'method_declaration' || t === 'annotation_type_element_declaration') {
      const nameNode = m.childForFieldName('name');
      const sig = typeParams(m) + paramSignature(m.childForFieldName('parameters'));
      this.leaf('method', nameNode?.text ?? '<unnamed>', prefix, sig, m, nameNode, parent, replace);
      return;
    }
    if (t === 'constructor_declaration' || t === 'compact_constructor_declaration') {
      const nameNode = m.childForFieldName('name');
      const sig = t === 'compact_constructor_declaration' ? '<compact>' : typeParams(m) + paramSignature(m.childForFieldName('parameters'));
      this.leaf('method', 'constructor', prefix, sig, m, nameNode, parent, replace);
      return;
    }
    if (t === 'static_initializer') {
      this.leaf('method', '<clinit>', prefix, '', m, null, parent, replace);
      return;
    }
    if (t === 'field_declaration' || t === 'constant_declaration') {
      const type = eraseJavaType(m.childForFieldName('type')?.text ?? '');
      const marks: string[] = [];
      for (const d of namedChildren(m)) {
        if (d.type !== 'variable_declarator') continue;
        const nameNode = d.childForFieldName('name');
        if (!nameNode) continue;
        const decl = this.b.add('field', nameNode.text, prefix + nameNode.text, type, d, parent.id);
        marks.push(placeholder('field', nameNode.text, type));
        this.b.setBody(decl, bodyTokens([d], { skip: new Set([nameNode.id]) }));
        this.nested(d, decl, new Set([nameNode.id]));
      }
      if (marks.length > 0) replace.set(m.id, marks.join(''));
      return;
    }
    if (t === 'enum_constant') {
      const nameNode = m.childForFieldName('name');
      if (!nameNode) return;
      this.leaf('field', nameNode.text, prefix, '', m, nameNode, parent, replace);
    }
  }
}

/** Derive `ids@0.1` ids from an already-parsed Java tree. */
export function deriveJavaIds(tree: Tree, filePath: string, options: StableIdOptions = {}): StableIdFile {
  const root = tree.rootNode;
  const pkg = packageOf(root) || '<default>';
  const module = options.module ?? `${pkg}/${fileBase(filePath)}`;
  const builder = new Builder('java', options.keepBodyTokens === true);
  const moduleDecl = builder.add('module', module, module, '', root, null);
  const ex = new JavaExtractor(builder);
  const replace = new Map<number, string>();
  // The package names the module, as a declaration's own name does: it is not body.
  const skip = new Set<number>();
  for (const c of namedChildren(root)) {
    if (TYPE_DECLS.has(c.type)) ex.type(c, `${pkg}:`, moduleDecl, replace);
    else if (c.type === 'package_declaration') skip.add(c.id);
  }
  builder.setBody(moduleDecl, bodyTokens([root], { replace, skip }));
  return { scheme: STABLE_ID_SCHEME, file: filePath, language: 'java', module, decls: builder.decls, ...partialOf(root) };
}
