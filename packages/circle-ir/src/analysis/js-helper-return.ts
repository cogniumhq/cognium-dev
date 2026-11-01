/**
 * JS/TS helper-return judgement shared by source detection (#992).
 */

/**
 * #992 — does the same-file JS function `name` provably return none of its
 * parameters? Only two return shapes count: a literal (`return 'k'`), or a
 * constant index into a local one-line array literal whose element there is a
 * literal (`const list = ['safe', x]; return list[0];`). Anything else, or a
 * name declared more than once, answers false (the source is kept).
 */
export function jsHelperReturnsNoParam(sourceCode: string, rawName: string): boolean {
  // Call names come from the extractor and can be arbitrary text in minified
  // code; only a plain identifier is a helper we can look up.
  if (!/^[A-Za-z_$][\w$]*$/.test(rawName)) return false;
  const name = rawName.replace(/\$/g, '\\$');
  const decls = [...sourceCode.matchAll(new RegExp(`\\bfunction\\s+${name}\\s*\\(([^)]*)\\)\\s*\\{`, 'g'))];
  if (decls.length !== 1) return false;
  if (new RegExp(`(?:const|let|var)\\s+${name}\\s*=`).test(sourceCode)) return false;
  const open = (decls[0].index ?? 0) + decls[0][0].length - 1;
  let depth = 0;
  let close = -1;
  for (let i = open; i < sourceCode.length; i++) {
    const ch = sourceCode[i];
    if (ch === '{') depth++;
    else if (ch === '}' && --depth === 0) { close = i; break; }
  }
  if (close < 0) return false;
  const body = sourceCode.slice(open + 1, close).replace(/\/\/.*$/gm, '');
  if (/\bfunction\b|=>/.test(body)) return false; // nested functions: out of scope
  const literal = /^(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`[^`$]*`|-?\d+(?:\.\d+)?|true|false|null)$/;
  const returns = [...body.matchAll(/\breturn\b\s*([^;]*);?/g)].map(m => m[1]!.trim());
  if (returns.length === 0) return false;
  for (const expr of returns) {
    if (literal.test(expr)) continue;
    const slot = /^([A-Za-z_$][\w$]*)\s*\[\s*(\d+)\s*\]$/.exec(expr);
    if (!slot) return false;
    const arr = slot[1]!.replace(/\$/g, '\\$');
    // The array: declared once as a one-line literal, never written afterwards.
    const declRe = new RegExp(`(?:const|let|var)\\s+${arr}\\s*=\\s*\\[([^\\]]*)\\]\\s*;?`);
    const d = declRe.exec(body);
    if (!d) return false;
    if (new RegExp(`\\b${arr}\\s*(?:\\[[^\\]]*\\]\\s*=(?!=)|\\.\\s*(?:push|unshift|splice|shift|pop|reverse|sort|fill|copyWithin)\\s*\\()`).test(body)) return false;
    const elems = d[1]!.split(',').map(e => e.trim());
    const el = elems[Number(slot[2])];
    if (el === undefined || !literal.test(el)) return false;
  }
  return true;
}
