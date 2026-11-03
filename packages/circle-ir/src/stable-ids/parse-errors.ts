/**
 * The first parse error in a tree, in source order, as a `ParseErrorSite`.
 *
 * Stable ids call this for `StableIdFile.parseError`, so a consumer that
 * withholds an answer because a file is partial can say which file, where,
 * and what the parser could not read (cognium-dev#1004).
 */
import type { Node } from '../core/parser.js';
import type { ParseErrorSite } from './types.js';

/**
 * The first `ERROR` or `MISSING` node for which `ignore` is false, in source
 * order, or `undefined` when there is none.
 */
export function firstParseErrorNode(root: Node, ignore: (n: Node) => boolean = () => false): Node | undefined {
  if (!root.hasError) return undefined;
  const stack: Node[] = [root];
  while (stack.length > 0) {
    const n = stack.pop()!;
    // A root the grammar gave up on is itself an ERROR; the useful site is inside it.
    if ((n.type === 'ERROR' || n.isMissing) && n !== root) {
      if (!ignore(n)) return n;
      continue;
    }
    // Push in reverse so the leftmost child is visited first.
    for (let i = n.childCount - 1; i >= 0; i--) {
      const c = n.child(i);
      if (c && (c.hasError || c.isMissing)) stack.push(c);
    }
  }
  return root.type === 'ERROR' && !ignore(root) ? root : undefined;
}

/** A tree node as a `ParseErrorSite`. */
export function parseErrorSite(n: Node): ParseErrorSite {
  return {
    line: n.startPosition.row + 1,
    column: n.startPosition.column + 1,
    nodeKind: n.isMissing ? `MISSING ${n.type}` : 'ERROR',
    // Directly under the root (even a root the grammar gave up on): the program.
    parent: n.parent && n.parent.parent ? n.parent.type : 'program',
  };
}

/** The first parse error in the tree, or `undefined` for a clean parse. */
export function firstParseError(root: Node, ignore?: (n: Node) => boolean): ParseErrorSite | undefined {
  const n = firstParseErrorNode(root, ignore);
  return n ? parseErrorSite(n) : undefined;
}

/** `partial` and, when set, `parseError` for a `StableIdFile`, from any error in the tree. */
export function partialOf(root: Node): { partial: boolean; parseError?: ParseErrorSite } {
  const parseError = firstParseError(root);
  return parseError ? { partial: true, parseError } : { partial: false };
}
