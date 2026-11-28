/**
 * Declaration recovery after a partial parse (cognium-dev#1307).
 *
 * Tree-sitter's error recovery can fold every declaration after a syntax
 * error into one ERROR node (JavaScript / TypeScript: a broken top-level
 * statement swallows the functions and classes after it) or into the broken
 * method's body (Java: an unclosed method body turns the next method's
 * header into a local variable). The extractors skip both shapes, so the
 * file loses those declarations even though they are well formed.
 *
 * The repair edits a copy of the source without moving any character —
 * broken lines are blanked to spaces, and a Java method body is closed by
 * turning one indentation space into `}` — so every node of the re-parsed
 * tree keeps the original line and column. Declarations found in the
 * re-parse are merged into the ones the original tree produced.
 */
import type { Node, Tree } from './parser.js';
import { parse, disposeTree } from './parser.js';
import { extractTypes, type TypeExtractionOptions } from './extractors/types.js';
import type { SupportedLanguage, TypeInfo } from '../types/index.js';

/** Upper bound on repair-and-reparse rounds per file. */
const MAX_ROUNDS = 8;

/** A line that starts a top-level JavaScript / TypeScript declaration. */
const JS_TOP_LEVEL_DECLARATION =
  /^(?:export\s+(?:default\s+)?)?(?:declare\s+)?(?:async\s+)?(?:function\b|(?:abstract\s+)?class\b|const\b|let\b|var\b|interface\b|type\s+[A-Za-z_$]|enum\b|namespace\b)/;

/**
 * A Java method or constructor header that opens its body on the same line:
 * optional modifiers, an optional return type, a name, then `(`.
 */
const JAVA_MEMBER_HEADER =
  /^(\s*)(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|static|final|abstract|synchronized|native|default|strictfp)\s+)*(?:<[^>]*>\s*)?(?:([\w$.?]+(?:<[^<>()]*(?:<[^<>()]*>[^<>()]*)*>)?(?:\[\])*)\s+)?([A-Za-z_$][\w$]*)\s*\([^;]*\)\s*(?:throws\s[\w$.,\s]*)?\{/;

/** Words that can precede `(` in a statement and are not a member name. */
const JAVA_NOT_A_MEMBER = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'synchronized', 'try', 'do', 'else',
  'return', 'new', 'throw', 'case', 'assert', 'yield', 'super', 'this',
]);

function blankRows(lines: string[], from: number, to: number): void {
  for (let r = from; r < to && r < lines.length; r++) lines[r] = ' '.repeat(lines[r].length);
}

/**
 * Blank the broken start of each program-level ERROR in a JS / TS tree, up
 * to the first line inside it that begins a top-level declaration.
 */
function repairJavaScript(root: Node, lines: string[]): boolean {
  let changed = false;
  for (const child of root.namedChildren) {
    if (child?.type !== 'ERROR') continue;
    const first = child.startPosition.row;
    for (let r = first + 1; r <= child.endPosition.row && r < lines.length; r++) {
      if (JS_TOP_LEVEL_DECLARATION.test(lines[r])) {
        blankRows(lines, first, r);
        changed = true;
        break;
      }
    }
  }
  return changed;
}

/**
 * Close a broken Java method body just before the first line inside it that
 * reads as a member header indented no deeper than the method itself.
 */
function repairJava(root: Node, lines: string[]): boolean {
  let changed = false;
  const stack: Node[] = [root];
  while (stack.length > 0) {
    const node = stack.pop()!;
    if (node.type === 'method_declaration' || node.type === 'constructor_declaration') {
      const body = node.childForFieldName('body');
      if (body && body.hasError && repairJavaMethod(node, body, lines)) changed = true;
      continue;
    }
    for (const child of node.namedChildren) {
      if (child && child.hasError) stack.push(child);
    }
  }
  return changed;
}

function repairJavaMethod(method: Node, body: Node, lines: string[]): boolean {
  const indent = method.startPosition.column;
  for (let r = body.startPosition.row + 1; r <= body.endPosition.row && r < lines.length; r++) {
    const m = JAVA_MEMBER_HEADER.exec(lines[r]);
    if (!m) continue;
    const lead = m[1].length;
    if (lead === 0 || lead > indent) continue;
    if (JAVA_NOT_A_MEMBER.has(m[3]) || (m[2] !== undefined && JAVA_NOT_A_MEMBER.has(m[2]))) continue;
    lines[r] = lines[r].slice(0, lead - 1) + '}' + lines[r].slice(lead);
    return true;
  }
  return false;
}

/** Add the recovered types and methods that `base` does not already hold. */
function mergeRecovered(base: TypeInfo[], recovered: TypeInfo[]): TypeInfo[] {
  const merged = base.map((t) => ({ ...t, methods: [...t.methods] }));
  const byKey = new Map(merged.map((t) => [`${t.kind}:${t.name}`, t]));
  for (const t of recovered) {
    const key = `${t.kind}:${t.name}`;
    const existing = byKey.get(key);
    if (!existing) {
      merged.push(t);
      byKey.set(key, t);
      continue;
    }
    const seen = new Set(existing.methods.map((m) => m.name + ':' + m.start_line));
    for (const m of t.methods) {
      if (!seen.has(m.name + ':' + m.start_line)) existing.methods.push(m);
    }
  }
  return merged;
}

/**
 * Recover the declarations a partial JS / TS / Java parse dropped. Returns
 * `types` unchanged when the language is not covered, the tree is clean, or
 * no repair applies.
 */
export async function recoverPartialParseTypes(
  tree: Tree,
  code: string,
  language: SupportedLanguage,
  grammar: SupportedLanguage,
  types: TypeInfo[],
  options?: TypeExtractionOptions,
): Promise<TypeInfo[]> {
  const isJs = language === 'javascript' || language === 'typescript';
  if (!tree.rootNode.hasError || (!isJs && language !== 'java')) return types;
  const repair = isJs ? repairJavaScript : repairJava;

  const lines = code.split('\n');
  let current = tree;
  let result = types;
  try {
    for (let round = 0; round < MAX_ROUNDS && current.rootNode.hasError; round++) {
      if (!repair(current.rootNode, lines)) break;
      const next = await parse(lines.join('\n'), grammar);
      if (current !== tree) disposeTree(current);
      current = next;
      result = mergeRecovered(result, extractTypes(current, undefined, language, options));
    }
  } finally {
    if (current !== tree) disposeTree(current);
  }
  return result;
}
