/**
 * Pass: redos-regex-literal (CWE-1333, category: security)
 *
 * Pattern pass for JavaScript / TypeScript: a request value is matched
 * against a regular-expression literal that can backtrack exponentially.
 * (A request value used as the pattern itself, `new RegExp(req.query.p)`,
 * is the `redos` taint sink and is not this pass.)
 *
 * The regex: a group repeated without bound (`*`, `+`, `{n,}`) whose body
 * can repeat an unbounded part on its own — every other part of that body
 * is optional — so one input splits across the iterations in exponentially
 * many ways: `(a+)+`, `([a-z0-9]+)*`, `(\w+\s?)*`, `(([-._])?[a-z0-9]+)+`.
 * Something mandatory (a `$` or a required term) must follow the group,
 * otherwise the first try succeeds and nothing backtracks.
 *
 * The match: `RE.test(x)` / `RE.exec(x)`, or `x.match(RE)` / `matchAll` /
 * `search` / `replace` / `replaceAll` / `split`, where `RE` is the literal or
 * a name bound once in the file to the literal, and `x` is a request value:
 * `req.{query,body,params,headers,cookies}…` (also `request.…`, `req` a
 * function parameter), or a local whose reaching definition is one (a
 * `const` / `let` / assignment, or a destructuring of `req.body` and the
 * like), up to three hops. `as T`, `!`, `String(…)`, `.trim()`,
 * `.toString()`, `.toLowerCase()`, `.toUpperCase()` and `|| ''` / `?? ''`
 * are seen through.
 *
 * Precision (abstain rather than guess):
 *   - A body with a required part besides the unbounded one (`(\d+,)*`,
 *     `(ab+)+`) is not reported, even where the parts overlap.
 *   - Alternations that overlap (`(a|a)*`) and polynomial shapes (`\d+\d+`)
 *     are out of scope.
 *   - Patterns with backreferences, the `v` flag, groups nested more than
 *     `MAX_GROUP_DEPTH` deep, a source over `MAX_SOURCE_LENGTH` characters,
 *     or that do not parse are skipped.
 *   - Values that are not visibly from the request (a constant, a database
 *     row, a function result, a parameter of a helper) are skipped.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo, DFG, DFGDef } from '../../types/index.js';

// ---------------------------------------------------------------------------
// Regex structure
// ---------------------------------------------------------------------------

type Atom =
  | { kind: 'char' }
  | { kind: 'assert' }
  | { kind: 'end' }
  | { kind: 'group'; alts: Term[][] };

interface Term {
  atom: Atom;
  min: number;
  max: number;
}

class Unsupported extends Error {}

/**
 * Bounds on what `parseRegex` reads. Past them the pattern is treated as
 * unparsable and the pass abstains. The parser and every helper that walks
 * the parsed tree (`canMatchNonEmpty`, `loopsAlone`, `altLoopsAlone`, the
 * walk in `isExponentialRegex`) recurse once per group level, so the depth
 * cap keeps a deeply nested literal from overflowing the stack. Real
 * patterns nest a handful of groups and run to a few hundred characters.
 */
export const MAX_GROUP_DEPTH = 100;
export const MAX_SOURCE_LENGTH = 10_000;

function isDigit(ch: string | undefined): boolean {
  return ch !== undefined && ch >= '0' && ch <= '9';
}

/**
 * Parse a JS regex source into terms; null for backreferences, anything not
 * understood, groups nested deeper than `MAX_GROUP_DEPTH`, or a source longer
 * than `MAX_SOURCE_LENGTH`.
 */
export function parseRegex(source: string): Term[][] | null {
  if (source.length > MAX_SOURCE_LENGTH) return null;
  let i = 0;
  let depth = 0;
  const n = source.length;

  function readEscape(): Atom {
    // at `\`
    const c = source[i + 1];
    if (c === undefined) throw new Unsupported();
    if (c >= '1' && c <= '9') throw new Unsupported(); // backreference
    if (c === 'k' && source[i + 2] === '<') throw new Unsupported();
    if (c === 'b' || c === 'B') { i += 2; return { kind: 'assert' }; }
    if (c === 'u' && source[i + 2] === '{') {
      const close = source.indexOf('}', i + 3);
      if (close < 0) throw new Unsupported();
      i = close + 1;
      return { kind: 'char' };
    }
    if ((c === 'p' || c === 'P') && source[i + 2] === '{') {
      const close = source.indexOf('}', i + 3);
      if (close < 0) throw new Unsupported();
      i = close + 1;
      return { kind: 'char' };
    }
    if (c === 'u') { i += 6; return { kind: 'char' }; }
    if (c === 'x') { i += 4; return { kind: 'char' }; }
    if (c === 'c') { i += 3; return { kind: 'char' }; }
    i += 2;
    return { kind: 'char' };
  }

  function readClass(): Atom {
    // at `[`
    i++;
    if (source[i] === '^') i++;
    // In JS a `]` always closes the class (`[]` is empty, `[^]` is any).
    while (i < n) {
      const ch = source[i];
      if (ch === '\\') { i += 2; continue; }
      i++;
      if (ch === ']') return { kind: 'char' };
    }
    throw new Unsupported();
  }

  function readQuantifier(): { min: number; max: number } | null {
    const ch = source[i];
    let q: { min: number; max: number } | null = null;
    if (ch === '*') { q = { min: 0, max: Infinity }; i++; }
    else if (ch === '+') { q = { min: 1, max: Infinity }; i++; }
    else if (ch === '?') { q = { min: 0, max: 1 }; i++; }
    else if (ch === '{') {
      let j = i + 1;
      let a = '';
      while (isDigit(source[j])) a += source[j++];
      if (a === '') return null; // literal `{`
      let max = Number(a);
      if (source[j] === ',') {
        j++;
        let b = '';
        while (isDigit(source[j])) b += source[j++];
        max = b === '' ? Infinity : Number(b);
      }
      if (source[j] !== '}') return null;
      q = { min: Number(a), max };
      i = j + 1;
    }
    if (q && source[i] === '?') i++; // lazy
    return q;
  }

  function readAlts(inGroup: boolean): Term[][] {
    const alts: Term[][] = [[]];
    while (i < n) {
      const ch = source[i];
      if (ch === '|') { alts.push([]); i++; continue; }
      if (ch === ')') {
        if (!inGroup) throw new Unsupported();
        return alts;
      }
      let atom: Atom;
      if (ch === '\\') atom = readEscape();
      else if (ch === '[') atom = readClass();
      else if (ch === '^') { atom = { kind: 'assert' }; i++; }
      else if (ch === '$') { atom = { kind: 'end' }; i++; }
      else if (ch === '(') {
        let lookaround = false;
        if (source[i + 1] === '?') {
          const k = source[i + 2];
          if (k === ':') i += 3;
          else if (k === '=' || k === '!') { lookaround = true; i += 3; }
          else if (k === '<' && (source[i + 3] === '=' || source[i + 3] === '!')) { lookaround = true; i += 4; }
          else if (k === '<') {
            const close = source.indexOf('>', i + 3);
            if (close < 0) throw new Unsupported();
            i = close + 1;
          } else throw new Unsupported(); // modifiers `(?i:` and the like
        } else i++;
        if (++depth > MAX_GROUP_DEPTH) throw new Unsupported();
        const inner = readAlts(true);
        depth--;
        if (source[i] !== ')') throw new Unsupported();
        i++;
        atom = lookaround ? { kind: 'assert' } : { kind: 'group', alts: inner };
      } else { atom = { kind: 'char' }; i++; }
      const q = readQuantifier();
      alts[alts.length - 1].push({ atom, min: q ? q.min : 1, max: q ? q.max : 1 });
    }
    if (inGroup) throw new Unsupported();
    return alts;
  }

  try {
    const alts = readAlts(false);
    return i === n ? alts : null;
  } catch (e) {
    if (e instanceof Unsupported) return null;
    throw e;
  }
}

function canMatchNonEmpty(atom: Atom): boolean {
  if (atom.kind === 'char') return true;
  if (atom.kind !== 'group') return false;
  return atom.alts.some(alt => alt.some(t => t.max > 0 && canMatchNonEmpty(t.atom)));
}

/** The term can repeat an unbounded, non-empty part with everything else beside it skipped. */
function loopsAlone(t: Term): boolean {
  if (t.max === 0) return false;
  if (t.max === Infinity && canMatchNonEmpty(t.atom)) return true;
  return t.atom.kind === 'group' && t.atom.alts.some(altLoopsAlone);
}

function altLoopsAlone(alt: Term[]): boolean {
  for (let i = 0; i < alt.length; i++) {
    if (!loopsAlone(alt[i])) continue;
    if (alt.every((t, j) => j === i || t.min === 0)) return true;
  }
  return false;
}

/** A mandatory term: something the input must still match, so a failure there backtracks. */
function isMandatory(t: Term): boolean {
  return t.min >= 1 && (t.atom.kind === 'end' || canMatchNonEmpty(t.atom));
}

/**
 * True when the pattern has a group repeated without bound whose body can
 * repeat an unbounded part on its own, followed by something mandatory.
 */
export function isExponentialRegex(source: string, flags = ''): boolean {
  if (flags.includes('v')) return false;
  const alts = parseRegex(source);
  if (!alts) return false;
  const visit = (seqs: Term[][], followed: boolean): boolean => {
    for (const seq of seqs) {
      for (let i = 0; i < seq.length; i++) {
        const t = seq[i];
        const after = followed || seq.slice(i + 1).some(isMandatory);
        if (t.atom.kind !== 'group') continue;
        if (t.max === Infinity && after && t.atom.alts.some(altLoopsAlone)) return true;
        if (visit(t.atom.alts, after)) return true;
      }
    }
    return false;
  };
  return visit(alts, false);
}

/** `/src/flags` → its parts; null when the text is not exactly one regex literal. */
export function splitRegexLiteral(text: string): { source: string; flags: string } | null {
  const t = text.trim();
  if (t.length < 3 || t[0] !== '/' || t[1] === '/' || t[1] === '*') return null;
  const end = t.lastIndexOf('/');
  if (end <= 0) return null;
  const flags = t.slice(end + 1);
  for (const ch of flags) if (ch < 'a' || ch > 'z') return null;
  // The body must not end the literal early: an unescaped `/` outside a class.
  const source = t.slice(1, end);
  let inClass = false;
  for (let k = 0; k < source.length; k++) {
    const ch = source[k];
    if (ch === '\\') { k++; continue; }
    if (ch === '[') inClass = true;
    else if (ch === ']') inClass = false;
    else if (ch === '/' && !inClass) return null;
    else if (ch === '\n') return null;
  }
  return { source, flags };
}

// ---------------------------------------------------------------------------
// The matched value
// ---------------------------------------------------------------------------

const REQ_NAMES: ReadonlySet<string> = new Set(['req', 'request']);
const REQ_PARTS: ReadonlySet<string> = new Set(['query', 'body', 'params', 'headers', 'cookies']);
const PRESERVING_METHODS: readonly string[] = ['.trim()', '.toString()', '.toLowerCase()', '.toUpperCase()'];

function isIdentStart(ch: string | undefined): boolean {
  return ch !== undefined && (ch === '_' || ch === '$' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'));
}
function isIdentChar(ch: string | undefined): boolean {
  return isIdentStart(ch) || isDigit(ch);
}
export function isIdentifier(s: string): boolean {
  if (!isIdentStart(s[0])) return false;
  for (const ch of s) if (!isIdentChar(ch)) return false;
  return true;
}

function isQuotedEmptyish(s: string): boolean {
  const t = s.trim();
  return t.length >= 2 && (t[0] === "'" || t[0] === '"') && t[t.length - 1] === t[0] && !t.slice(1, -1).includes(t[0]);
}

/** Wrappers that keep the request value as is, removed: `as T`, `!`, `String(x)`, `.trim()`, `|| ''`. */
export function stripWrappers(expr: string): string {
  let e = expr.trim();
  for (let guard = 0; guard < 8; guard++) {
    const before = e;
    if (e.endsWith(';')) e = e.slice(0, -1).trim();
    if (e.endsWith('!')) e = e.slice(0, -1).trim();
    const asAt = e.lastIndexOf(' as ');
    if (asAt > 0 && isIdentifier(e.slice(asAt + 4).trim())) e = e.slice(0, asAt).trim();
    for (const op of [' || ', ' ?? ']) {
      const at = e.lastIndexOf(op);
      if (at > 0 && isQuotedEmptyish(e.slice(at + op.length))) e = e.slice(0, at).trim();
    }
    for (const m of PRESERVING_METHODS) if (e.endsWith(m)) e = e.slice(0, -m.length).trim();
    if (e.startsWith('String(') && e.endsWith(')')) e = e.slice('String('.length, -1).trim();
    if (e.startsWith('(') && e.endsWith(')') && balancedInner(e)) e = e.slice(1, -1).trim();
    if (e === before) break;
  }
  return e;
}

function balancedInner(e: string): boolean {
  let depth = 0;
  for (let k = 0; k < e.length; k++) {
    if (e[k] === '(') depth++;
    else if (e[k] === ')') { depth--; if (depth === 0 && k !== e.length - 1) return false; }
  }
  return depth === 0;
}

/**
 * `req.query.q`, `req.body['email']`, `request.headers.host` → the request
 * object's name; null for anything else (calls, arithmetic, `.length`).
 */
export function requestMemberBase(expr: string): string | null {
  const e = stripWrappers(expr);
  const dot = e.indexOf('.');
  if (dot <= 0) return null;
  const base = e.slice(0, dot);
  if (!REQ_NAMES.has(base)) return null;
  let k = dot + 1;
  let part = '';
  while (isIdentChar(e[k])) part += e[k++];
  if (!REQ_PARTS.has(part)) return null;
  // The rest: `.name` or `['name']` / `["name"]` segments only.
  let segments = 0;
  while (k < e.length) {
    if (e[k] === '.') {
      k++;
      const start = k;
      while (isIdentChar(e[k])) k++;
      if (k === start) return null;
      const seg = e.slice(start, k);
      if (seg === 'length') return null;
      segments++;
    } else if (e[k] === '[') {
      const q = e[k + 1];
      if (q !== "'" && q !== '"') return null;
      const close = e.indexOf(q, k + 2);
      if (close < 0 || e[close + 1] !== ']') return null;
      k = close + 2;
      segments++;
    } else return null;
  }
  // `req.query` alone is an object, not a string, except for `body` (a text body).
  if (segments === 0 && part !== 'body') return null;
  return base;
}

interface Lookup {
  dfg: DFG;
  lines: string[];
  defsById: Map<number, DFGDef>;
}

function reachingDef(lk: Lookup, variable: string, line: number): DFGDef | null {
  for (const u of lk.dfg.uses) {
    if (u.variable !== variable || u.line !== line || u.def_id === null) continue;
    return lk.defsById.get(u.def_id) ?? null;
  }
  return null;
}

/** The request object `base` is a function parameter at `line`. */
function isParamAt(lk: Lookup, base: string, line: number): boolean {
  const d = reachingDef(lk, base, line);
  return d !== null && d.kind === 'param';
}

/** For `const { a, b: c, d = 'x' } = <obj>`, does the pattern bind `name`? */
function destructuresName(pattern: string, name: string): boolean {
  for (const raw of pattern.split(',')) {
    let p = raw.trim();
    const eq = p.indexOf('=');
    if (eq >= 0) p = p.slice(0, eq).trim();
    const colon = p.indexOf(':');
    const bound = colon >= 0 ? p.slice(colon + 1).trim() : p;
    if (bound === name) return true;
  }
  return false;
}

/** Is `expr` at `line` a request value (directly, or through ≤ `depth` local definitions)? */
function isRequestValue(lk: Lookup, expr: string, line: number, depth: number): boolean {
  const e = stripWrappers(expr);
  const base = requestMemberBase(e);
  if (base) return isParamAt(lk, base, line);
  if (!isIdentifier(e) || depth <= 0) return false;
  const def = reachingDef(lk, e, line);
  if (!def || def.kind !== 'local') return false;
  const text = (lk.lines[def.line - 1] ?? '').trim();
  const rhs = definitionRhs(text, e);
  if (rhs === null) return false;
  if (rhs.destructured) {
    const b = requestMemberBase(rhs.expr) ?? (REQ_NAMES.has(rhs.expr.split('.')[0]) ? partOnly(rhs.expr) : null);
    return b !== null && isParamAt(lk, b, def.line);
  }
  return isRequestValue(lk, rhs.expr, def.line, depth - 1);
}

/** `req.body` / `req.query` (no member past it) → `req`; else null. */
function partOnly(expr: string): string | null {
  const e = stripWrappers(expr);
  const dot = e.indexOf('.');
  if (dot <= 0) return null;
  const base = e.slice(0, dot);
  return REQ_NAMES.has(base) && REQ_PARTS.has(e.slice(dot + 1)) ? base : null;
}

/** The right-hand side that defines `name` on a one-line statement. */
function definitionRhs(text: string, name: string): { expr: string; destructured: boolean } | null {
  let t = text;
  for (const kw of ['const ', 'let ', 'var ']) if (t.startsWith(kw)) { t = t.slice(kw.length).trim(); break; }
  if (t.startsWith('{')) {
    const close = t.indexOf('}');
    if (close < 0) return null;
    if (!destructuresName(t.slice(1, close), name)) return null;
    const rest = t.slice(close + 1).trim();
    if (!rest.startsWith('=')) return null;
    return { expr: trimStatement(rest.slice(1)), destructured: true };
  }
  if (!t.startsWith(name)) return null;
  let rest = t.slice(name.length);
  if (isIdentChar(rest[0])) return null;
  rest = rest.trim();
  if (rest.startsWith(':')) {
    // `name: T = …` — a simple type annotation only.
    const eq = rest.indexOf('=');
    if (eq < 0) return null;
    rest = rest.slice(eq);
  }
  if (!rest.startsWith('=') || rest.startsWith('==') || rest.startsWith('=>')) return null;
  return { expr: trimStatement(rest.slice(1)), destructured: false };
}

function trimStatement(s: string): string {
  let e = s.trim();
  if (e.endsWith(';')) e = e.slice(0, -1).trim();
  return e;
}

// ---------------------------------------------------------------------------
// The regex operand
// ---------------------------------------------------------------------------

/** The regex literal `text` denotes: itself, or a name bound once in the file to a literal. */
function regexOf(lk: Lookup, text: string): { source: string; flags: string; literal: string } | null {
  const t = text.trim();
  const direct = splitRegexLiteral(t);
  if (direct) return { ...direct, literal: t };
  if (!isIdentifier(t)) return null;
  const defs = lk.dfg.defs.filter(d => d.variable === t);
  if (defs.length !== 1) return null;
  const line = (lk.lines[defs[0].line - 1] ?? '').trim();
  if (!line.startsWith('const ')) return null;
  const rhs = definitionRhs(line, t);
  if (!rhs || rhs.destructured) return null;
  const lit = splitRegexLiteral(rhs.expr);
  return lit ? { ...lit, literal: rhs.expr } : null;
}

const RECEIVER_REGEX_METHODS: ReadonlySet<string> = new Set(['test', 'exec']);
const STRING_REGEX_METHODS: ReadonlySet<string> = new Set(['match', 'matchAll', 'search', 'replace', 'replaceAll', 'split']);

/** For a regex-applying call, the regex text and the matched value's text. */
export function regexApplication(call: CallInfo): { regex: string; subject: string } | null {
  const receiver = (call.receiver ?? '').trim();
  if (!receiver) return null;
  const arg0 = call.arguments.find(a => a.position === 0)?.expression?.trim();
  if (!arg0) return null;
  if (RECEIVER_REGEX_METHODS.has(call.method_name)) return { regex: receiver, subject: arg0 };
  if (STRING_REGEX_METHODS.has(call.method_name)) return { regex: arg0, subject: receiver };
  return null;
}

// ---------------------------------------------------------------------------
// Pass
// ---------------------------------------------------------------------------

export interface RedosRegexLiteralResult {
  findings: Array<{ line: number; regex: string; subject: string }>;
}

export class RedosRegexLiteralPass implements AnalysisPass<RedosRegexLiteralResult> {
  readonly name = 'redos-regex-literal';
  readonly category = 'security' as const;

  run(ctx: PassContext): RedosRegexLiteralResult {
    const { graph, language, code } = ctx;
    const findings: RedosRegexLiteralResult['findings'] = [];
    if (language !== 'javascript' && language !== 'typescript') return { findings };
    const dfg = graph.ir.dfg;
    if (!dfg) return { findings };
    const lk: Lookup = { dfg, lines: code.split('\n'), defsById: new Map(dfg.defs.map(d => [d.id, d])) };
    const file = graph.ir.meta.file;
    const seen = new Set<number>();

    for (const call of graph.ir.calls) {
      const app = regexApplication(call);
      if (!app) continue;
      const line = call.location.line;
      if (seen.has(line)) continue;
      const re = regexOf(lk, app.regex);
      if (!re || !isExponentialRegex(re.source, re.flags)) continue;
      if (!isRequestValue(lk, app.subject, line, 3)) continue;
      seen.add(line);
      findings.push({ line, regex: re.literal, subject: app.subject });
      ctx.addFinding({
        id: `${this.name}-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-1333',
        severity: 'medium',
        level: 'warning',
        message:
          `Request value \`${app.subject}\` is matched against \`${re.literal}\`, a regex with a ` +
          'repeated group whose body can repeat on its own. A crafted input that almost ' +
          'matches makes the engine try exponentially many splits and blocks the event loop.',
        file,
        line,
        fix:
          'Rewrite the pattern so each input character has one way to match: drop the outer ' +
          'repetition (`^[a-z0-9]+$` rather than `^([a-z0-9]+)*$`), or make the repeated body ' +
          'start with a required separator (`^\\w+(\\s\\w+)*$`). Bounding the input length ' +
          'limits but does not remove the cost.',
        evidence: { regex: re.literal, subject: app.subject, language },
      });
    }
    return { findings };
  }
}
