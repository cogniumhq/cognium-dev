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

/** Calls whose result is always a number, whatever the argument. */
const NUMERIC_CALL = /^(?:Number|parseInt|parseFloat|Number\.parseInt|Number\.parseFloat|Math\.[A-Za-z]+)\s*\(/;
const NUMERIC_LITERAL = /^-?(?:\d[\d_]*(?:\.\d+)?|0[xX][0-9a-fA-F]+)$/;

/** Index of the bracket closing the one at `open`, or -1. Skips string literals. */
function closeAt(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const ch = text[i]!;
    if (ch === '"' || ch === "'" || ch === '`') {
      let j = i + 1;
      for (; j < text.length && text[j] !== ch; j++) if (text[j] === '\\') j++;
      i = j;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if ((ch === ')' || ch === ']' || ch === '}') && --depth === 0) return i;
  }
  return -1;
}

/** `cond ? a : b` split at depth 0, or null when `expr` is not one ternary. */
function splitTernary(expr: string): [string, string] | null {
  let depth = 0;
  let q = -1;
  let nested = 0;
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i]!;
    if (ch === '"' || ch === "'" || ch === '`') {
      let j = i + 1;
      for (; j < expr.length && expr[j] !== ch; j++) if (expr[j] === '\\') j++;
      i = j;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (depth === 0 && ch === '?' && expr[i + 1] !== '.' && expr[i + 1] !== '?') {
      if (q < 0) q = i; else nested++;
    } else if (depth === 0 && ch === ':' && q >= 0) {
      if (nested > 0) { nested--; continue; }
      return [expr.slice(q + 1, i).trim(), expr.slice(i + 1).trim()];
    }
  }
  return null;
}

/**
 * Is `expr`, inside a function `body` with parameters `params`, always a
 * number? A numeric literal, a numeric coercion (`Number(x)`, `parseInt(x)`,
 * `Math.min(…)`, unary `+x`), a ternary of two numbers, or a local of the body
 * that every assignment gives a number.
 */
function isNumericExpr(expr: string, body: string, params: ReadonlySet<string>, depth: number): boolean {
  let e = expr.trim().replace(/\s+as\s+number$/, '');
  while (e.startsWith('(') && closeAt(e, 0) === e.length - 1) e = e.slice(1, -1).trim();
  if (e === '' || depth > 4) return false;
  if (NUMERIC_LITERAL.test(e)) return true;
  const call = NUMERIC_CALL.exec(e);
  if (call) return closeAt(e, call[0].length - 1) === e.length - 1;
  if (/^\+\s*[A-Za-z_$][\w$.]*$/.test(e)) return true;
  const tern = splitTernary(e);
  if (tern) return tern.every(t => isNumericExpr(t, body, params, depth + 1));
  if (!/^[A-Za-z_$][\w$]*$/.test(e) || params.has(e)) return false;
  return localIsNumeric(e, body, params, depth);
}

/** Every write to the local `name` in `body` stores a number. */
function localIsNumeric(name: string, body: string, params: ReadonlySet<string>, depth: number): boolean {
  const esc = name.replace(/\$/g, '\\$');
  if (!new RegExp(`\\b(?:const|let|var)\\s+${esc}\\b`).test(body)) return false;
  // Destructuring and loop bindings take values we do not follow.
  if (new RegExp(`\\b(?:const|let|var)\\s*[{[][^=;]*(?<![\\w$])${esc}(?![\\w$])`).test(body)) return false;
  if (new RegExp(`\\b(?:const|let|var)\\s+${esc}\\s+(?:of|in)\\b`).test(body)) return false;
  const write = new RegExp(`(?<![\\w$.])${esc}\\s*(?::\\s*number\\s*)?(\\*\\*=|[-*/%]=|\\+=|\\?\\?=|\\|\\|=|&&=|=(?![=>])|\\+\\+|--)`, 'g');
  let writes = 0;
  for (const m of body.matchAll(write)) {
    writes++;
    const op = m[1]!;
    if (op === '++' || op === '--' || /^(?:\*\*|[-*/%])=$/.test(op)) continue;
    const rhs = /^[^;\n]*/.exec(body.slice(m.index! + m[0].length))![0];
    if (!isNumericExpr(rhs, body, params, depth + 1)) return false;
  }
  return writes > 0;
}

/**
 * does the same-file JS function `name` return a number on every path?
 * Each `return` must be a number per `isNumericExpr`; a bare `return`, a nested
 * function, or a name declared more than once answers false. The value such a
 * helper hands back cannot carry an injection payload, whatever its input.
 */
export function jsHelperReturnsNumber(sourceCode: string, rawName: string): boolean {
  if (!/^[A-Za-z_$][\w$]*$/.test(rawName)) return false;
  const name = rawName.replace(/\$/g, '\\$');
  const decl = new RegExp(
    `\\bfunction\\s+${name}\\s*(?:<[^>]*>)?\\s*\\(([^)]*)\\)[^{]*\\{` +
    `|\\bconst\\s+${name}\\s*=\\s*(?:async\\s+)?(?:function\\s*)?\\(([^)]*)\\)[^{=]*(?:=>\\s*)?\\{`,
    'g',
  );
  const decls = [...sourceCode.matchAll(decl)];
  if (decls.length !== 1) return false;
  if (new RegExp(`\\b(?:let|var)\\s+${name}\\s*=|(?<![\\w$.])${name}\\s*=(?![=>])[^=]`).test(
    sourceCode.slice(0, decls[0]!.index) + sourceCode.slice(decls[0]!.index! + decls[0]![0].length),
  )) return false;
  const open = decls[0]!.index! + decls[0]![0].length - 1;
  const close = closeAt(sourceCode, open);
  if (close < 0) return false;
  const body = sourceCode.slice(open + 1, close).replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  if (/\bfunction\b|=>|\byield\b/.test(body)) return false;
  const params = new Set(
    (decls[0]![1] ?? decls[0]![2] ?? '').split(',')
      .map(p => /^\s*(?:\.\.\.)?([A-Za-z_$][\w$]*)/.exec(p)?.[1])
      .filter((p): p is string => !!p),
  );
  let returns = 0;
  for (const m of body.matchAll(/\breturn\b([^;\n}]*)/g)) {
    returns++;
    // A return that continues on the next line (`return n\n  + raw`) is not one expression.
    const after = body.slice(m.index! + m[0].length);
    if (after.startsWith('\n') && !/^\s*(?:[}A-Za-z_$]|$)/.test(after)) return false;
    if (!isNumericExpr(m[1]!, body, params, 0)) return false;
  }
  return returns > 0;
}
