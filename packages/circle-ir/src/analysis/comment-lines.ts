/**
 * cognium-dev#999 — security results on lines that are only a comment.
 *
 * Several passes scan source text line by line (LanguageSourcesPass,
 * mass-assignment, tls-verify-disabled), so a doc comment such as
 * ` * JSON.parse(req.body)` produced a high-severity finding. This answers,
 * from the syntax tree, whether a line holds nothing but comment text: the
 * first non-blank column sits inside a comment node that runs to the end of
 * the line's content. Mixed lines (`foo(x); // note`) are code and keep their
 * results. String literals are not comments and are untouched.
 */
import type { Node } from 'web-tree-sitter';

export function makeCommentOnlyLineTest(root: Node, code: string): (line: number) => boolean {
  const lines = code.split('\n');
  const cache = new Map<number, boolean>();
  return (line: number): boolean => {
    const hit = cache.get(line);
    if (hit !== undefined) return hit;
    let result = false;
    const text = lines[line - 1];
    if (text !== undefined) {
      const first = text.search(/\S/);
      if (first >= 0) {
        const end = text.trimEnd().length;
        const node = root.descendantForPosition({ row: line - 1, column: first });
        let n: Node | null = node;
        // Climb to the comment node itself (some grammars nest a content child).
        while (n && !/comment/.test(n.type) && n.startPosition.row === line - 1 &&
               n.startPosition.column === first && n.parent) {
          n = n.parent;
        }
        if (n && /comment/.test(n.type)) {
          const startsBefore =
            n.startPosition.row < line - 1 ||
            (n.startPosition.row === line - 1 && n.startPosition.column <= first);
          const endsAfter =
            n.endPosition.row > line - 1 ||
            (n.endPosition.row === line - 1 && n.endPosition.column >= end);
          result = startsBefore && endsAfter;
        }
      }
    }
    cache.set(line, result);
    return result;
  };
}
