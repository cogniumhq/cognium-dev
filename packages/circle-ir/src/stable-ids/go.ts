/**
 * `ids@0.1` declaration and body ids for Go.
 *
 * Declarations: the file (`module`, named `<package dir>/<file>`); functions;
 * types (kind `type`); methods, keyed by their receiver type; package-level
 * `var` and `const` names (kind `field`). Function literals inside a body
 * are keyed by their enclosing declaration plus a structural path and
 * flagged `unstable:anonymous`.
 *
 * Package: the file's directory (Go's unit of naming), `.` for the root,
 * unless the caller passes one. Qualified name: `<package>:<Name>`,
 * `<package>:<Type>.<Method>`. `init` may repeat across a package's files,
 * so it is keyed by file: `<package>:init@<file>`. Signature: parameter and
 * result types, parameter names never — `(string,...int)(int,error)` — so a
 * rename does not re-key a function. A method's pointer or value receiver is
 * not part of its name.
 */

import { partialOf } from './parse-errors.js';
import type { Node, Tree } from '../core/parser.js';
import { Builder, placeholder } from './builder.js';
import { bodyTokens, namedChildren } from './normalize.js';
import { STABLE_ID_SCHEME, type StableDecl, type StableIdFile, type StableIdOptions } from './types.js';

/** The package directory for a repository-relative `.go` path. */
export function goPackageDir(filePath: string): string {
  const p = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
  const i = p.lastIndexOf('/');
  return i < 0 ? '.' : p.slice(0, i);
}

function fileBase(filePath: string): string {
  const p = filePath.replace(/\\/g, '/');
  return p.slice(p.lastIndexOf('/') + 1).replace(/\.go$/, '');
}

const compact = (s: string): string => s.replace(/\s+/g, '');

function paramTypes(list: Node | null): string[] {
  const out: string[] = [];
  for (const p of list ? namedChildren(list) : []) {
    if (p.type === 'parameter_declaration' || p.type === 'variadic_parameter_declaration') {
      const t = compact(p.childForFieldName('type')?.text ?? '_');
      const names = namedChildren(p).filter(c => c.type === 'identifier').length || 1;
      const written = p.type === 'variadic_parameter_declaration' ? `...${t}` : t;
      for (let i = 0; i < names; i++) out.push(written);
    }
  }
  return out;
}

/** `(T1,T2)(R1,R2)` — parameter and result types only. */
export function goSignature(fn: Node): string {
  const params = paramTypes(fn.childForFieldName('parameters'));
  const result = fn.childForFieldName('result');
  let res = '';
  if (result) res = result.type === 'parameter_list' ? `(${paramTypes(result).join(',')})` : compact(result.text);
  return `(${params.join(',')})${res}`;
}

/** The receiver's type name, pointer and type parameters dropped (`*Server[T]` → `Server`). */
export function goReceiverType(method: Node): string {
  const recv = method.childForFieldName('receiver');
  const decl = recv ? namedChildren(recv).find(c => c.type === 'parameter_declaration') : undefined;
  const t = compact(decl?.childForFieldName('type')?.text ?? '');
  return t.replace(/^\*/, '').replace(/\[.*$/, '');
}

class GoExtractor {
  constructor(private readonly b: Builder, private readonly pkg: string, private readonly file: string) {}

  private nested(node: Node, enclosing: StableDecl, path = ''): void {
    const kids = namedChildren(node);
    for (let i = 0; i < kids.length; i++) {
      const c = kids[i];
      const p = path === '' ? `${i}` : `${path}.${i}`;
      if (c.type === 'func_literal') {
        const decl = this.b.add('function', '<func>', `${enclosing.qualified_name}/<func>@${p}`, goSignature(c), c, enclosing.id, ['unstable:anonymous']);
        this.b.setBody(decl, bodyTokens([c]));
        this.nested(c, decl);
      } else this.nested(c, enclosing, p);
    }
  }

  module(root: Node, moduleDecl: StableDecl): void {
    const replace = new Map<number, string>();
    const types = new Map<string, StableDecl>();
    const stmts = namedChildren(root);
    // Types first, so that methods declared before their type still find it.
    for (const s of stmts) {
      if (s.type !== 'type_declaration') continue;
      for (const spec of namedChildren(s)) {
        if (spec.type !== 'type_spec' && spec.type !== 'type_alias') continue;
        const nameNode = spec.childForFieldName('name');
        if (!nameNode) continue;
        const decl = this.b.add('type', nameNode.text, `${this.pkg}:${nameNode.text}`, '', spec, moduleDecl.id);
        replace.set(spec.id, placeholder('type', nameNode.text, ''));
        this.b.setBody(decl, bodyTokens([spec], { skip: new Set([nameNode.id]) }));
        types.set(nameNode.text, decl);
      }
    }
    for (const s of stmts) {
      if (s.type === 'function_declaration') {
        const nameNode = s.childForFieldName('name');
        const name = nameNode?.text ?? '<unnamed>';
        const sig = goSignature(s);
        const qname = name === 'init' ? `${this.pkg}:init@${this.file}` : `${this.pkg}:${name}`;
        const decl = this.b.add('function', name, qname, sig, s, moduleDecl.id);
        replace.set(s.id, placeholder('function', name, sig));
        this.b.setBody(decl, bodyTokens([s], { skip: new Set(nameNode ? [nameNode.id] : []) }));
        this.nested(s, decl);
      } else if (s.type === 'method_declaration') {
        const nameNode = s.childForFieldName('name');
        const name = nameNode?.text ?? '<unnamed>';
        const recv = goReceiverType(s);
        const sig = goSignature(s);
        const parent = types.get(recv) ?? moduleDecl;
        const decl = this.b.add('method', name, `${this.pkg}:${recv}.${name}`, sig, s, parent.id);
        replace.set(s.id, placeholder('method', name, sig));
        const skip = new Set<number>(nameNode ? [nameNode.id] : []);
        const r = s.childForFieldName('receiver');
        if (r) skip.add(r.id);
        this.b.setBody(decl, bodyTokens([s], { skip }));
        this.nested(s, decl);
      } else if (s.type === 'var_declaration' || s.type === 'const_declaration') {
        const specs = namedChildren(s).flatMap(c => (c.type === 'var_spec_list' || c.type === 'const_spec_list' ? namedChildren(c) : [c]));
        for (const spec of specs) {
          if (spec.type !== 'var_spec' && spec.type !== 'const_spec') continue;
          const t = compact(spec.childForFieldName('type')?.text ?? '');
          for (const n of namedChildren(spec).filter(c => c.type === 'identifier')) {
            if (n.text === '_') continue;
            const decl = this.b.add('field', n.text, `${this.pkg}:${n.text}`, t, spec, moduleDecl.id);
            this.b.setBody(decl, bodyTokens([spec], { skip: new Set([n.id]) }));
            this.nested(spec, decl);
          }
          replace.set(spec.id, placeholder('field', namedChildren(spec).filter(c => c.type === 'identifier').map(c => c.text).join(','), t));
        }
      }
    }
    this.b.setBody(moduleDecl, bodyTokens([root], { replace }));
  }
}

/** Derive `ids@0.1` ids from an already-parsed Go tree. */
export function deriveGoIds(tree: Tree, filePath: string, options: StableIdOptions = {}): StableIdFile {
  const pkg = options.module ?? goPackageDir(filePath);
  const file = fileBase(filePath);
  const builder = new Builder('go', options.keepBodyTokens === true);
  const moduleDecl = builder.add('module', file, `${pkg}/${file}`, '', tree.rootNode, null);
  new GoExtractor(builder, pkg, file).module(tree.rootNode, moduleDecl);
  return { scheme: STABLE_ID_SCHEME, file: filePath, language: 'go', module: pkg, decls: builder.decls, ...partialOf(tree.rootNode) };
}
