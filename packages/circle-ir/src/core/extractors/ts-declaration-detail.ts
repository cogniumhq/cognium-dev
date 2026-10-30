/**
 * TypeScript/JavaScript declaration detail, added to `ir.types` and
 * `ir.exports` only under `AnalyzerOptions.declarationDetail`.
 *
 * The default extraction leaves TypeScript declarations without their
 * `export`, access modifiers, return types, class decorators and decorator
 * arguments, and lists every declaration in `ir.exports`. This pass fills
 * those in after the default extraction, matching declarations by name and
 * line, so the default output is byte-identical when the option is off.
 *
 * Added, all optional or appended:
 * - `TypeInfo.modifiers` — `export`, `default`, `abstract`, `declare`
 * - `TypeInfo.decorators`, `MethodInfo.decorators`, `FieldInfo.decorators`,
 *   `ParameterInfo.decorators` — name plus arguments (source text, and the
 *   value of a string literal)
 * - `MethodInfo.modifiers` gains `export`/`default` (module functions) and
 *   `public`/`private`/`protected`/`readonly`/`abstract`/`override`
 *   (members; a `#name` is `private`)
 * - `MethodInfo.return_type` from the annotation, without the leading `:`
 * - `FieldInfo.modifiers` gains access modifiers and `readonly`;
 *   `FieldInfo.type` from the annotation
 */

import type { Node, Tree } from 'web-tree-sitter';
import type { DecoratorInfo, ExportInfo, FieldInfo, MethodInfo, TypeInfo } from '../../types/index.js';

function named(node: Node): Node[] {
  const out: Node[] = [];
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i);
    if (c && c.type !== 'comment') out.push(c);
  }
  return out;
}

function tokens(node: Node): string[] {
  const out: string[] = [];
  for (let i = 0; i < node.childCount; i++) {
    const c = node.child(i);
    if (c && !c.isNamed) out.push(c.text);
  }
  return out;
}

function stringLiteral(node: Node): string | undefined {
  if (node.type !== 'string') return undefined;
  return named(node).map(c => c.text).join('');
}

/** A decorator's name and arguments. */
export function decoratorInfo(node: Node): DecoratorInfo | null {
  const expr = named(node)[0];
  if (!expr) return null;
  let callee: Node | null = expr;
  let args: Node[] = [];
  if (expr.type === 'call_expression') {
    callee = expr.childForFieldName('function');
    const a = expr.childForFieldName('arguments');
    args = a ? named(a) : [];
  }
  if (!callee) return null;
  const name = callee.type === 'member_expression' ? callee.childForFieldName('property')?.text : callee.text;
  if (!name) return null;
  return {
    name,
    arguments: args.map(a => {
      const value = stringLiteral(a);
      return value === undefined ? { text: a.text } : { text: a.text, value };
    }),
  };
}

function decoratorsOf(nodes: readonly Node[]): DecoratorInfo[] {
  return nodes.filter(n => n.type === 'decorator').map(decoratorInfo).filter((d): d is DecoratorInfo => d !== null);
}

/** `export` / `default` for a declaration whose statement is exported. */
function exportModifiers(holder: Node): string[] {
  const stmt = holder.parent?.type === 'export_statement' ? holder.parent : null;
  if (!stmt) return [];
  return tokens(stmt).includes('default') ? ['export', 'default'] : ['export'];
}

const MEMBER_WORDS = ['readonly', 'abstract', 'override', 'static', 'declare'];

/** Access and other member modifiers, in source order. */
function memberModifiers(member: Node): string[] {
  const out: string[] = [];
  for (let i = 0; i < member.childCount; i++) {
    const c = member.child(i);
    if (!c) continue;
    if (c.type === 'accessibility_modifier') out.push(c.text);
    else if (c.type === 'override_modifier') out.push('override');
    else if (!c.isNamed && MEMBER_WORDS.includes(c.text)) out.push(c.text);
  }
  const name = member.childForFieldName('name') ?? member.childForFieldName('property');
  if (name?.type === 'private_property_identifier' && !out.includes('private')) out.push('private');
  return out;
}

function annotationText(node: Node | null): string | null {
  return node ? node.text.replace(/^:\s*/, '') : null;
}

function addModifiers(target: string[], extra: readonly string[]): void {
  for (const m of extra) if (!target.includes(m)) target.push(m);
}

/** Exported local names from `export { a, b as c }` and `export default a`. */
function clauseExports(root: Node): { names: Set<string>; defaultName: string | null } {
  const names = new Set<string>();
  let defaultName: string | null = null;
  for (const stmt of named(root)) {
    if (stmt.type !== 'export_statement' || stmt.childForFieldName('source')) continue;
    const clause = named(stmt).find(c => c.type === 'export_clause');
    for (const s of clause ? named(clause) : []) {
      const name = s.childForFieldName('name')?.text;
      const alias = s.childForFieldName('alias')?.text;
      if (!name) continue;
      if (alias === 'default') defaultName = name;
      else names.add(name);
    }
    const value = stmt.childForFieldName('value');
    if (value?.type === 'identifier') defaultName = value.text;
  }
  return { names, defaultName };
}

function enrichMethod(m: MethodInfo, fn: Node, decorators: readonly Node[], extra: readonly string[]): void {
  addModifiers(m.modifiers, extra);
  const ret = fn.childForFieldName('return_type');
  if (ret && m.return_type === null) m.return_type = annotationText(ret);
  const decs = decoratorsOf(decorators);
  if (decs.length > 0) m.decorators = decs;
  const params = fn.childForFieldName('parameters');
  for (const p of params ? named(params) : []) {
    const pd = decoratorsOf(named(p));
    if (pd.length === 0) continue;
    const line = p.startPosition.row + 1;
    const info = m.parameters.find(x => x.line === line && !x.decorators && p.text.includes(x.name.replace(/^\.\.\./, '')));
    if (info) info.decorators = pd;
  }
}

function enrichClassBody(type: TypeInfo, body: Node): void {
  let pending: Node[] = [];
  for (const member of named(body)) {
    if (member.type === 'decorator') {
      pending.push(member);
      continue;
    }
    const line = member.startPosition.row + 1;
    const nameNode = member.childForFieldName('name') ?? member.childForFieldName('property');
    const name = nameNode?.text;
    if (member.type === 'method_definition' && name) {
      const m = type.methods.find(x => x.name === name && x.start_line === line);
      if (m) enrichMethod(m, member, pending, memberModifiers(member));
    } else if ((member.type === 'public_field_definition' || member.type === 'field_definition') && name) {
      const f: FieldInfo | undefined = type.fields.find(x => x.name === name);
      if (f) {
        addModifiers(f.modifiers, memberModifiers(member));
        if (f.type === null) f.type = annotationText(member.childForFieldName('type'));
        const decs = decoratorsOf(pending);
        if (decs.length > 0) f.decorators = decs;
      }
    }
    pending = [];
  }
}

/**
 * Fill in TypeScript/JavaScript declaration detail on the types the default
 * extraction produced. Mutates `types` in place.
 */
export function enrichTsDeclarations(tree: Tree, types: TypeInfo[]): void {
  const root = tree.rootNode;
  const { names, defaultName } = clauseExports(root);
  const clauseMods = (name: string): string[] =>
    name === defaultName ? ['export', 'default'] : names.has(name) ? ['export'] : [];
  const visit = (node: Node): void => {
    const t = node.type;
    if (t === 'class_declaration' || t === 'abstract_class_declaration' || t === 'interface_declaration') {
      const line = node.startPosition.row + 1;
      const name = node.childForFieldName('name')?.text;
      const type = types.find(x => x.name === name && x.start_line === line);
      if (type && name) {
        const mods = [...exportModifiers(node), ...clauseMods(name)];
        if (t === 'abstract_class_declaration') mods.push('abstract');
        if (node.parent?.type === 'ambient_declaration') mods.push('declare');
        type.modifiers = [...new Set(mods)];
        const decs = decoratorsOf([...(node.parent?.type === 'export_statement' ? named(node.parent) : []), ...named(node)]);
        if (decs.length > 0) type.decorators = decs;
        const body = node.childForFieldName('body');
        if (body && t !== 'interface_declaration') enrichClassBody(type, body);
      }
    } else if (t === 'function_declaration' || t === 'generator_function_declaration') {
      const module = types.find(x => x.name === '<module>');
      const name = node.childForFieldName('name')?.text;
      const m = module?.methods.find(x => x.name === name && x.start_line === node.startPosition.row + 1);
      if (m && name) enrichMethod(m, node, [], [...exportModifiers(node), ...clauseMods(name)]);
    } else if (t === 'variable_declarator') {
      const value = node.childForFieldName('value');
      const name = node.childForFieldName('name')?.text;
      const decl = node.parent;
      const module = types.find(x => x.name === '<module>');
      const m = module?.methods.find(x => x.name === name && x.start_line === node.startPosition.row + 1);
      if (m && name && value?.type === 'arrow_function' && decl) enrichMethod(m, value, [], [...exportModifiers(decl), ...clauseMods(name)]);
    }
    for (const c of named(node)) visit(c);
  };
  visit(root);
}

/**
 * `ir.exports` for a TypeScript/JavaScript file under declaration detail: a
 * file with ES exports exports only what it marks `export`; a member is
 * exported with its class unless `private`, as `protected` when protected.
 * A file without any ES export keeps every declaration (CommonJS).
 */
export function extractTsExports(types: readonly TypeInfo[]): ExportInfo[] | null {
  const esm = types.some(t => t.modifiers?.includes('export') || t.methods.some(m => m.modifiers.includes('export')));
  if (!esm) return null;
  const out: ExportInfo[] = [];
  const visibility = (mods: readonly string[]): ExportInfo['visibility'] | null =>
    mods.includes('private') ? null : mods.includes('protected') ? 'protected' : 'public';
  for (const t of types) {
    if (t.name === '<module>') {
      for (const m of t.methods) if (m.modifiers.includes('export')) out.push({ symbol: m.name, kind: 'method', visibility: 'public' });
      continue;
    }
    if (!t.modifiers?.includes('export')) continue;
    out.push({ symbol: t.name, kind: t.kind === 'enum' ? 'class' : t.kind, visibility: 'public' });
    for (const m of t.methods) {
      const v = visibility(m.modifiers);
      if (v) out.push({ symbol: `${t.name}.${m.name}`, kind: 'method', visibility: v });
    }
    for (const f of t.fields) {
      const v = visibility(f.modifiers);
      if (v) out.push({ symbol: `${t.name}.${f.name}`, kind: 'field', visibility: v });
    }
  }
  return out;
}
