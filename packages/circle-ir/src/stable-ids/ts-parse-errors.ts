/**
 * Which TypeScript parse errors can hide a declaration (cognium-ai #855).
 *
 * tree-sitter-typescript 0.23.2, the newest release, does not parse an array
 * of an import type, `import('m').T[]`. It is valid TypeScript, and circle-ir's
 * own passes use it. Recovery stays local:
 *
 * - in a parameter, field, property or return type the `[]` becomes an
 *   `ERROR` node inside the `type_annotation`;
 * - in a `const x: import('m').T[]` / `type A = import('m').T[]` declaration
 *   the parser inserts a `MISSING ";"` after the import type and reads the
 *   `[]` (plus any initializer) as the next expression statement; with a
 *   union or intersection (`import('m').T[] | undefined`) that statement is
 *   `[] | undefined`;
 * - `importOriginal<typeof import('m')>()` as a declarator's value leaves an
 *   `ERROR` of `>()` after the declarator.
 *
 * Either way every declaration is still in the tree, so the file is not
 * "partial" for stable ids or dead code. Any other error still is.
 */
import type { Node } from '../core/parser.js';
import type { ParseErrorSite } from './types.js';
import { firstParseError } from './parse-errors.js';

const TYPE_CONTEXTS = new Set(['type_annotation', 'type_arguments']);
const DECLARATIONS = new Set(['lexical_declaration', 'variable_declaration', 'type_alias_declaration']);

/** `import('m').T` as the grammar reads it: a member expression on an `import(...)` call. */
function isImportTypeExpression(n: Node | null): boolean {
  if (!n || n.type !== 'member_expression') return false;
  const obj = n.childForFieldName('object');
  return !!obj && obj.type === 'call_expression' && obj.childForFieldName('function')?.type === 'import';
}

function insideTypeContext(n: Node): boolean {
  for (let p = n.parent; p; p = p.parent) {
    if (TYPE_CONTEXTS.has(p.type)) return true;
    if (p.type === 'statement_block' || p.type === 'program' || p.type === 'class_body') return false;
  }
  return false;
}

/** The `[]` the parser split off: `[]` or `[] = <initializer>` as an expression statement. */
function isSplitArraySuffix(n: Node | null): boolean {
  if (!n || n.type !== 'expression_statement') return false;
  let e = n.namedChild(0);
  // `import('m').T[] | undefined` / `… & B`: the rest of a union or
  // intersection type is read as `[] | undefined`, a bitwise expression whose
  // leftmost operand is the split-off `[]` (cognium-dev#1004).
  while (e && e.type === 'binary_expression' && /^[|&]$/.test(e.child(1)?.type ?? '')) {
    e = e.childForFieldName('left');
  }
  if (!e) return false;
  if (e.type === 'array') return e.namedChildCount === 0;
  if (e.type === 'assignment_expression') {
    const left = e.childForFieldName('left');
    return !!left && left.type === 'array_pattern' && left.namedChildCount === 0;
  }
  return false;
}

function isSplitImportArrayDeclaration(missing: Node): boolean {
  const decl = missing.parent;
  if (!decl || !DECLARATIONS.has(decl.type)) return false;
  let typed: Node | null;
  if (decl.type === 'type_alias_declaration') {
    typed = decl.childForFieldName('value');
  } else {
    const declarators = decl.namedChildren.filter((c): c is Node => !!c && c.type === 'variable_declarator');
    const last = declarators[declarators.length - 1];
    const ann = last?.childForFieldName('type');
    if (last?.childForFieldName('value')) return false;
    typed = ann?.namedChild(0) ?? null;
  }
  if (!isImportTypeExpression(typed)) return false;
  const holder = decl.parent?.type === 'export_statement' ? decl.parent : decl;
  return isSplitArraySuffix(holder.nextNamedSibling);
}

/**
 * `const actual = await importOriginal<typeof import('m')>();` (the vitest
 * mock idiom): the grammar reads `<` as a comparison against
 * `typeof import('m')`, and the leftover `>()` becomes an `ERROR` holding `>`
 * and an empty parameter list, right after the declarator. The declaration is
 * still in the tree and nothing follows inside the error (cognium-dev#1004).
 * When the recovery instead swallows the next statement (a `class` read as an
 * expression), the error sits elsewhere and still counts.
 */
/**
 * Generic call signatures with conditional type-parameter defaults (zx `Shell`)
 * leave an `ERROR` inside `interface_body` while the interface and the first
 * call signature are still present (cognium-dev#1193).
 */
function isBenignInterfaceMemberRecoveryError(n: Node): boolean {
  if (n.type !== 'ERROR') return false;
  for (let p = n.parent; p; p = p.parent) {
    if (p.type === 'interface_body') {
      const iface = p.parent;
      return iface?.type === 'interface_declaration' && iface.childForFieldName('name') != null;
    }
    if (p.type === 'program' || p.type === 'class_body' || p.type === 'statement_block') return false;
  }
  return false;
}

function isSplitTypeofImportCall(n: Node): boolean {
  if (n.parent?.type !== 'lexical_declaration' || n.childCount !== 2) return false;
  const [gt, params] = [n.child(0), n.child(1)];
  if (gt?.type !== '>' || params?.type !== 'formal_parameters' || params.namedChildCount !== 0) return false;
  const declarator = n.previousNamedSibling;
  if (declarator?.type !== 'variable_declarator') return false;
  const value = declarator.childForFieldName('value');
  if (value?.type !== 'binary_expression' || value.child(1)?.type !== '<') return false;
  const right = value.childForFieldName('right');
  if (right?.type !== 'unary_expression' || right.child(0)?.type !== 'typeof') return false;
  const arg = right.namedChild(0);
  return arg?.type === 'call_expression' && arg.childForFieldName('function')?.type === 'import';
}

function isBenign(n: Node): boolean {
  if (n.type === 'ERROR') {
    return insideTypeContext(n) || isSplitTypeofImportCall(n) || isBenignInterfaceMemberRecoveryError(n);
  }
  if (n.isMissing) return n.type === ';' && isSplitImportArrayDeclaration(n);
  return false;
}

/**
 * True when the tree has a parse error that could hide a declaration, which
 * is what `StableIdFile.partial` means. False for a clean tree and for the
 * import-type-array recoveries described above.
 */
export function hasDeclarationHidingError(root: Node): boolean {
  return firstDeclarationHidingError(root) !== undefined;
}

/** The first error, in source order, that could hide a declaration. */
export function firstDeclarationHidingError(root: Node): ParseErrorSite | undefined {
  return firstParseError(root, isBenign);
}
