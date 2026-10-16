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

/**
 * JS/TS members that yield a number or a boolean. `search` is left out: on
 * search-index objects (`idx.search(q)`) it returns result data, not a number.
 */
const JS_SCALAR_METHODS = new Set([
  'test', 'includes', 'startsWith', 'endsWith', 'indexOf', 'lastIndexOf',
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

/** An integer literal, optionally with `_` separators or a hex/binary/octal prefix. */
const GO_INT_LITERAL = /^(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO]?[0-7_]+|[1-9][0-9_]*|0)$/;

/** Braces in a Go line, with string, rune and raw-string literals blanked out. */
function goBraceText(text: string): string {
  return text.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`[^`]*`/g, '""');
}

/**
 * Names `n` bounded by `if <... n > K | n >= K ...> { ...; return|panic|continue }`
 * in `lines[from .. to)` where the guard still dominates line `to`. The condition
 * may join the bound with `||` only: under `&&` the branch would not reject every
 * large value. K is an integer literal or a name in `consts` (a same-file integer
 * `const`, see `goIntConstNames`).
 *
 * A guard only holds while the block it sits in is open: once the brace depth
 * falls below the guard's depth (the enclosing `if`, loop, closure or `else`
 * branch closed), or a new `case`/`default` clause of the same switch starts,
 * other paths reach `to` without passing the guard. A write to `n` after the
 * guard (`n = …`, `n op= …`, `n++`, `n--`, or `&n` handed to a callee such as
 * `fmt.Sscanf`) voids every bound on it.
 */
function goUpperBoundGuardedAt(
  lines: readonly string[],
  from: number,
  to: number,
  name: string,
  consts: ReadonlySet<string>,
): boolean {
  const esc = name.replace(/[$]/g, '\\$');
  const bound = new RegExp(`^\\(*\\s*${esc}\\s*>=?\\s*([\\w]+)\\s*\\)*$`);
  const reassign = new RegExp(
    `(?:^|[\\s,;(])${esc}(?:\\s*,\\s*\\w+)*\\s*(?::=|=(?!=)|\\+=|-=|\\*=|/=|%=|&=|\\|=|\\^=|&\\^=|<<=|>>=)` +
      `|(?<![\\w.])${esc}\\s*(?:\\+\\+|--)` +
      `|(?<![&\\w])&\\s*${esc}\\b`,
  );
  // Depth (in braces) of each guard still in force, in source order.
  let guards: number[] = [];
  let depth = 0;
  for (let i = from; i < to; i++) {
    const text = lines[i]!.replace(/\s*\/\/.*$/, '').trim();
    if (guards.length > 0 && reassign.test(text)) guards = [];
    const ifm = /^if\s+(.+?)\s*\{$/.exec(text);
    if (ifm && i + 1 < to) {
      const cond = ifm[1]!;
      if (!cond.includes('&&')) {
        const parts = cond.split('||').map((p) => p.trim());
        const hit = parts.some((p) => {
          const m = bound.exec(p);
          return m !== null && (GO_INT_LITERAL.test(m[1]!) || consts.has(m[1]!));
        });
        if (hit) {
          // The guard block must end in an exit before its closing brace.
          let inner = 1;
          let last = '';
          let j = i + 1;
          for (; j < to; j++) {
            const t = lines[j]!.replace(/\s*\/\/.*$/, '').trim();
            for (const ch of goBraceText(t)) inner += ch === '{' ? 1 : ch === '}' ? -1 : 0;
            if (inner <= 0) break;
            if (t) last = t;
          }
          if (inner <= 0 && /^(?:return\b|panic\(|continue\b)/.test(last)) {
            // The block opened and closed on lines i..j; depth is unchanged.
            guards.push(depth);
            i = j;
            continue;
          }
        }
      }
    }
    if (guards.length > 0 && /^(?:case\b.*|default\s*):$/.test(text)) {
      guards = guards.filter((d) => d < depth);
    }
    for (const ch of goBraceText(text)) {
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (guards.length > 0) guards = guards.filter((d) => d <= depth);
      }
    }
  }
  return guards.length > 0;
}

/**
 * Names declared exactly once in the file, as a package- or function-level
 * `const NAME [type] = <integer literal>` (alone or inside a `const ( … )` block),
 * and never otherwise defined: no `:=` or `var` of the same name, no parameter,
 * result or range variable of that name, no second `const` of it. A name that
 * could be shadowed by a variable is not a constant bound.
 */
function goIntConstNames(lines: readonly string[]): Set<string> {
  const decl = /^(?:const\s+)?([A-Za-z_]\w*)(?:\s+[\w.]+)?\s*=\s*([\w]+)\s*$/;
  const found = new Map<string, number>();
  let inBlock = false;
  const declLines = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i]!.replace(/\s*\/\/.*$/, '').trim();
    if (inBlock) {
      if (text === ')') { inBlock = false; continue; }
      const m = decl.exec(text);
      if (m && GO_INT_LITERAL.test(m[2]!) && !/^const\b/.test(text)) {
        found.set(m[1]!, (found.get(m[1]!) ?? 0) + 1);
        declLines.add(i);
      }
      continue;
    }
    if (/^const\s*\($/.test(text)) { inBlock = true; continue; }
    if (/^const\s/.test(text)) {
      const m = decl.exec(text);
      if (m && GO_INT_LITERAL.test(m[2]!)) {
        found.set(m[1]!, (found.get(m[1]!) ?? 0) + 1);
        declLines.add(i);
      }
    }
  }
  const out = new Set<string>();
  for (const [name, count] of found) {
    if (count !== 1) continue;
    const esc = name.replace(/[$]/g, '\\$');
    const other = new RegExp(
      `(?:^|[\\s,(])${esc}(?:\\s*,\\s*[\\w]+)*\\s*(?::=|=(?!=))` +
        `|\\b(?:var|const|type|func)\\s+${esc}\\b` +
        `|[(,]\\s*${esc}(?:\\s*,\\s*\\w+)*\\s+[\\w*\\[.]`,
    );
    const shadowed = lines.some((l, i) => {
      if (declLines.has(i)) return false;
      const t = l.replace(/\s*\/\/.*$/, '');
      return new RegExp(`(?<![\\w.])${esc}(?![\\w])`).test(t) && other.test(t);
    });
    if (!shadowed) out.add(name);
  }
  return out;
}

/**
 * DFG def ids of a Go local initialised by `make(<type>, <len>[, <cap>])` whose
 * every size argument is an integer literal or a variable rejected above a
 * constant earlier in the same function (`if n > K { return }`). The buffer
 * holds zero values; its size is bounded, so the request text that chose the
 * size does not reach a sink through it. An unbounded size is not credited.
 */
export function boundedMakeDefIds(defs: readonly DFGDef[], code: string, language: string): Set<number> {
  const out = new Set<number>();
  if (language !== 'go') return out;
  const lines = code.split('\n');
  const consts = goIntConstNames(lines);
  for (const def of defs) {
    if (def.kind !== 'local') continue;
    const text = lines[def.line - 1];
    if (text === undefined) continue;
    const rhs = initializerOf(text, def.variable, 'go');
    const mk = rhs === null ? null : /^make\(\s*(\[\][\w.*]+|map\[[^\]]+\][\w.*]+)\s*,\s*([^()]*?)\s*\)$/.exec(rhs);
    if (!mk) continue;
    const sizes = mk[2]!.split(',').map((s) => s.trim());
    if (sizes.length > 2 || sizes.some((s) => s === '')) continue;
    let fnStart = def.line - 1;
    while (fnStart > 0 && !/^func\b/.test(lines[fnStart]!)) fnStart--;
    const ok = sizes.every(
      (s) => GO_INT_LITERAL.test(s) || (/^[A-Za-z_]\w*$/.test(s) && goUpperBoundGuardedAt(lines, fnStart, def.line - 1, s, consts)),
    );
    if (ok) out.add(def.id);
  }
  return out;
}
