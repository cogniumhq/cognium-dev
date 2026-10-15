/**
 * Scalar-derivation taint barrier (#568, parent #349).
 *
 * A local whose whole initializer measures or tests a value — its length, a
 * match count, a boolean from a regex test or a containment check — holds an
 * integer or a boolean. That value carries the magnitude of the input, not
 * its content, so it cannot deliver a string payload to an injection sink.
 *
 * This is a type rule, not sanitizer credit for the call: a string-returning
 * matcher (`re.FindString(text)`, `text.match(re)`) still propagates taint.
 * Numeric parses (`strconv.Atoi`, `parseInt`) are not covered here; a parsed
 * number is attacker-chosen and stays tainted for size-sensitive consumers.
 *
 * The test reads the definition's own line. An initializer that is not a
 * single complete expression on that line is not credited.
 */

import type { DFGDef } from '../types/index.js';

/** Go calls that return an int or a bool computed from their argument. */
const GO_SCALAR_FUNCS = new Set(['len', 'utf8.RuneCountInString', 'utf8.RuneCount']);
/** `strings.X` / `bytes.X` functions with an int or bool result. */
const GO_STRINGS_SCALAR = new Set([
  'Contains', 'ContainsAny', 'ContainsRune', 'HasPrefix', 'HasSuffix', 'EqualFold',
  'Count', 'Index', 'IndexAny', 'IndexByte', 'IndexRune', 'LastIndex', 'Compare',
]);
/** `*regexp.Regexp` methods with a bool result, on any receiver. */
const GO_REGEXP_BOOL = new Set(['MatchString', 'Match']);

/** JS/TS members that yield a number or a boolean. */
const JS_SCALAR_METHODS = new Set([
  'test', 'includes', 'startsWith', 'endsWith', 'indexOf', 'lastIndexOf', 'search',
]);

type Lang = 'go' | 'javascript' | 'typescript';

function scalarLanguage(language: string): Lang | null {
  return language === 'go' || language === 'javascript' || language === 'typescript' ? language : null;
}

/**
 * Split `expr` at depth 0 into its trailing segment. Returns null when the
 * expression is not one postfix chain (an operator, a comma, whitespace or an
 * unbalanced bracket at depth 0).
 *
 * The result names the last member, whether the chain ends in a call of it,
 * and `head`, the chain text before that call (or before `.member`). A JS
 * regex literal may open the chain (`/^\d+$/.test(x)`).
 */
function lastChainSegment(expr: string): { member: string; isCall: boolean; head: string } | null {
  let depth = 0;
  let lastDot = -1;
  let lastGroupOpen = -1;
  let endsWithGroup = false;
  let start = 0;
  if (expr.startsWith('/')) {
    let inClass = false;
    let j = 1;
    for (; j < expr.length; j++) {
      const ch = expr[j]!;
      if (ch === '\\') { j++; continue; }
      if (ch === '[') inClass = true;
      else if (ch === ']') inClass = false;
      else if (ch === '/' && !inClass) break;
    }
    if (j >= expr.length) return null;
    start = j + 1;
  }
  for (let i = start; i < expr.length; i++) {
    const c = expr[i]!;
    if (c === '"' || c === "'" || c === '`') {
      if (c === '`' && depth === 0) return null; // template text may interpolate
      let j = i + 1;
      for (; j < expr.length && expr[j] !== c; j++) if (expr[j] === '\\') j++;
      if (j >= expr.length) return null;
      i = j;
      endsWithGroup = false;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') {
      if (depth === 0) lastGroupOpen = i;
      depth++;
      continue;
    }
    if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth < 0) return null;
      if (depth === 0) endsWithGroup = true;
      continue;
    }
    if (depth > 0) continue;
    if (c === '.') {
      // `?.` optional chaining is still one chain
      lastDot = i;
      endsWithGroup = false;
      continue;
    }
    if (c === '?' && expr[i + 1] === '.') continue;
    if (/[\w$]/.test(c)) {
      endsWithGroup = false;
      continue;
    }
    return null;
  }
  if (depth !== 0) return null;

  if (endsWithGroup) {
    // Trailing `( … )` must be the call of the last member.
    if (expr[lastGroupOpen] !== '(') return null;
    const callee = expr.slice(0, lastGroupOpen).replace(/\?$/, '');
    const m = /(?:^|\.)([\w$]+)$/.exec(callee);
    if (!m || lastDot > lastGroupOpen) return null;
    return { member: m[1]!, isCall: true, head: callee };
  }
  const m = /\.([\w$]+)$/.exec(expr);
  if (!m) return null;
  return { member: m[1]!, isCall: false, head: expr.slice(0, expr.length - m[0].length) };
}

/** True when `rhs` is a whole-expression measure or test of a value. */
export function isScalarDerivation(rhs: string, language: string): boolean {
  const lang = scalarLanguage(language);
  if (!lang) return false;
  let e = rhs.trim();
  // A leading negation keeps a boolean a boolean.
  while (e.startsWith('!')) e = e.slice(1).trim();
  if (e.length === 0) return false;
  const seg = lastChainSegment(e);
  if (!seg) return false;
  if (lang === 'go') {
    if (!seg.isCall) return false;
    if (GO_SCALAR_FUNCS.has(seg.head)) return true;
    const pkg = /^(strings|bytes)\.(\w+)$/.exec(seg.head);
    if (pkg) return GO_STRINGS_SCALAR.has(pkg[2]!);
    return seg.head.includes('.') && GO_REGEXP_BOOL.has(seg.member);
  }
  if (!seg.isCall) return seg.member === 'length';
  return seg.head.includes('.') && JS_SCALAR_METHODS.has(seg.member);
}

/**
 * The initializer of a single-variable local declared or assigned on `line`,
 * or null when the line is not a complete single-target assignment of `name`.
 */
function initializerOf(line: string, name: string, lang: Lang): string | null {
  const esc = name.replace(/[$]/g, '\\$');
  const code = line.replace(/\s*\/\/.*$/, '').trim().replace(/;$/, '').trim();
  const re = lang === 'go'
    ? new RegExp(`^(?:var\\s+)?${esc}(?:\\s+\\w+)?\\s*(?::=|=)\\s*(.+)$`)
    : new RegExp(`^(?:(?:const|let|var)\\s+)?${esc}(?:\\s*:\\s*(?:number|boolean))?\\s*=(?!=)\\s*(.+)$`);
  const m = re.exec(code);
  return m ? m[1]! : null;
}

/**
 * DFG def ids whose value is an integer or boolean derived from another value
 * by a whole-expression measure or test. Taint does not flow into these defs.
 */
export function scalarDerivedDefIds(defs: readonly DFGDef[], code: string, language: string): Set<number> {
  const out = new Set<number>();
  const lang = scalarLanguage(language);
  if (!lang) return out;
  const lines = code.split('\n');
  for (const def of defs) {
    if (def.kind !== 'local') continue;
    const text = lines[def.line - 1];
    if (text === undefined) continue;
    const rhs = initializerOf(text, def.variable, lang);
    if (rhs !== null && isScalarDerivation(rhs, lang)) out.add(def.id);
  }
  return out;
}
