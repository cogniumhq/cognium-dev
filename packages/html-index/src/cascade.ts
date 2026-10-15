/**
 * Which author declarations of a property family match an element AT REST, each with the rule it
 * came from, in cascade precedence order. Not a style resolver: no value is computed, no condition
 * (`@media`, a sheet's `media`) is evaluated, and no user-agent default is listed. Which
 * declaration applies under which condition is the consumer's question; the list says what the
 * author wrote that could.
 *
 * The selector matcher reads selectors as CSS Selectors 4 defines them, for what a static tree can
 * decide: type, universal, id, class and attribute selectors; the descendant, child, next-sibling
 * and subsequent-sibling combinators; the structural pseudo-classes (`:root`, `:empty`,
 * `:first-child` … `:nth-last-of-type(an+b)`); `:not()`, `:is()`, `:where()`; `:link` and
 * `:any-link`; and the form states the markup states (`:checked`, `:disabled`, `:enabled`,
 * `:required`, `:optional`). A user-action or history state (`:hover`, `:focus`, `:active`,
 * `:visited`, `:target` …) does not hold at rest, so a rule that needs one is not listed. A selector
 * with a pseudo-element styles that pseudo-element, not the element, and is not listed either. Any
 * other pseudo-class, and anything this reader does not parse, is not evaluated: the selector is
 * taken as not matching.
 */
import type { HNode } from './parse.js';

type Specificity = [number, number, number];

interface AttrSel { name: string; op: string; value: string; fold: boolean }
interface Pseudo { name: string; arg: string | null; list: Complex[] | null }
interface Compound { tag: string | null; ids: string[]; classes: string[]; attrs: AttrSel[]; pseudos: Pseudo[]; pseudoElement: boolean }
/** compounds right to left, each with the combinator that joins it to the one on its LEFT */
interface Complex { parts: { compound: Compound; combinator: string | null }[] }

class Unsupported extends Error {}

const HEX = /[0-9a-f]/i;
const identChar = (c: string): boolean => /[\w-]/.test(c) || c.charCodeAt(0) >= 0x80;

function escape(s: string, i: number): [string, number] {
  if (i >= s.length) return ['', i];
  if (!HEX.test(s[i])) { const ch = String.fromCodePoint(s.codePointAt(i)!); return [ch, i + ch.length]; }
  let j = i;
  while (j < s.length && j - i < 6 && HEX.test(s[j])) j++;
  const cp = Number.parseInt(s.slice(i, j), 16);
  if (/\s/.test(s[j] ?? '')) j++;
  return [cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '�', j];
}

function ident(s: string, i: number): [string, number] {
  let out = '';
  while (i < s.length) {
    if (s[i] === '\\') { const [t, j] = escape(s, i + 1); out += t; i = j; }
    else if (identChar(s[i])) out += s[i++];
    else break;
  }
  return [out, i];
}

/** index after the bracket closing the one at `i`; strings and escapes skipped; -1 when unclosed */
function closing(s: string, i: number): number {
  const open = s[i], close = open === '(' ? ')' : ']';
  let depth = 0;
  for (; i < s.length; i++) {
    const c = s[i];
    if (c === '\\') i++;
    else if (c === '"' || c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; }
    else if (c === open) depth++;
    else if (c === close && --depth === 0) return i + 1;
  }
  return -1;
}

/** split a selector list on top-level commas */
function splitList(s: string): string[] {
  const out: string[] = [];
  let depth = 0, cur = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '\\') { cur += c + (s[i + 1] ?? ''); i++; continue; }
    if (c === '"' || c === "'") { let j = i + 1; while (j < s.length && s[j] !== c) { if (s[j] === '\\') j++; j++; } cur += s.slice(i, j + 1); i = j; continue; }
    if (c === '(' || c === '[') depth++;
    if (c === ')' || c === ']') depth--;
    if (c === ',' && depth === 0) { out.push(cur); cur = ''; } else cur += c;
  }
  out.push(cur);
  return out;
}

function attrSel(body: string): AttrSel {
  let i = 0;
  const ws = () => { while (/\s/.test(body[i] ?? '')) i++; };
  ws();
  const [name, a] = ident(body, i);
  if (!name || body[a] === '|') throw new Unsupported(body);
  i = a; ws();
  if (i >= body.length) return { name: name.toLowerCase(), op: '', value: '', fold: false };
  const op = /^[~|^$*]?=/.exec(body.slice(i))?.[0];
  if (!op) throw new Unsupported(body);
  i += op.length; ws();
  let value = '';
  if (body[i] === '"' || body[i] === "'") {
    const q = body[i++];
    while (i < body.length && body[i] !== q) {
      if (body[i] === '\\') { const [t, j] = escape(body, i + 1); value += t; i = j; } else value += body[i++];
    }
    i++;
  } else { const [v, j] = ident(body, i); value = v; i = j; }
  ws();
  const flag = body.slice(i).trim().toLowerCase();
  if (flag !== '' && flag !== 'i' && flag !== 's') throw new Unsupported(body);
  return { name: name.toLowerCase(), op, value, fold: flag === 'i' };
}

const PSEUDO_ELEMENTS_LEGACY = new Set(['before', 'after', 'first-line', 'first-letter']);
const LIST_PSEUDOS = new Set(['not', 'is', 'where', 'matches', '-webkit-any', '-moz-any']);

function parseComplex(src: string): Complex {
  const s = src.trim();
  if (!s) throw new Unsupported(src);
  const compounds: { compound: Compound; combinator: string | null }[] = [];
  let cur: Compound | null = null;
  let pending: string | null = null;   // the combinator before the next compound
  const blank = (): Compound => ({ tag: null, ids: [], classes: [], attrs: [], pseudos: [], pseudoElement: false });
  const part = (): Compound => {
    if (!cur) { cur = blank(); compounds.push({ compound: cur, combinator: compounds.length ? pending ?? ' ' : null }); pending = null; }
    return cur;
  };
  for (let i = 0; i < s.length;) {
    const c = s[i];
    if (/\s/.test(c)) { if (cur) { cur = null; pending = pending ?? ' '; } i++; continue; }
    if (c === '>' || c === '+' || c === '~') {
      if (!cur && !compounds.length) throw new Unsupported(src);   // a relative selector
      cur = null; pending = c; i++; continue;
    }
    if (cur === null && pending === ' ' && compounds.length === 0) pending = null;
    const x = part();
    if (x.pseudoElement) throw new Unsupported(src);   // nothing may follow a pseudo-element here
    if (c === '*') { i++; continue; }
    if (c === '.') { const [k, j] = ident(s, i + 1); if (!k) throw new Unsupported(src); x.classes.push(k); i = j; continue; }
    if (c === '#') { const [k, j] = ident(s, i + 1); if (!k) throw new Unsupported(src); x.ids.push(k); i = j; continue; }
    if (c === '[') { const j = closing(s, i); if (j < 0) throw new Unsupported(src); x.attrs.push(attrSel(s.slice(i + 1, j - 1))); i = j; continue; }
    if (c === ':') {
      const dbl = s[i + 1] === ':';
      const [name, j] = ident(s, i + (dbl ? 2 : 1));
      if (!name) throw new Unsupported(src);
      const lname = name.toLowerCase();
      if (dbl || PSEUDO_ELEMENTS_LEGACY.has(lname)) {
        if (s[j] === '(') { const k = closing(s, j); if (k < 0) throw new Unsupported(src); i = k; } else i = j;
        x.pseudoElement = true;
        continue;
      }
      let arg: string | null = null;
      i = j;
      if (s[i] === '(') { const k = closing(s, i); if (k < 0) throw new Unsupported(src); arg = s.slice(i + 1, k - 1); i = k; }
      x.pseudos.push({ name: lname, arg, list: arg !== null && LIST_PSEUDOS.has(lname) ? splitList(arg).map(parseComplex) : null });
      continue;
    }
    if (c === '\\' || identChar(c)) {
      if (x.tag !== null || x.ids.length || x.classes.length || x.attrs.length || x.pseudos.length) throw new Unsupported(src);
      const [k, j] = ident(s, i);
      if (s[j] === '|') throw new Unsupported(src);   // a namespace prefix
      x.tag = k.toLowerCase();
      i = j;
      continue;
    }
    throw new Unsupported(src);
  }
  if (!compounds.length || cur === null && pending !== null && pending !== ' ') throw new Unsupported(src);
  return { parts: compounds.reverse() };
}

/** A selector list parsed for matching, or null when this reader does not evaluate it. */
export interface ParsedSelector { list: Complex[] }
export function parseSelector(selector: string): ParsedSelector | null {
  try {
    const s = selector.replace(/\/\*[\s\S]*?\*\//g, ' ');
    return { list: splitList(s).map(parseComplex) };
  } catch (e) {
    if (e instanceof Unsupported) return null;
    throw e;
  }
}

// ---------------------------------------------------------------- specificity

const add = (a: Specificity, b: Specificity): Specificity => [a[0] + b[0], a[1] + b[1], a[2] + b[2]];
const cmp = (a: Specificity, b: Specificity): number => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
const maxOf = (xs: Specificity[]): Specificity => xs.reduce((m, x) => (cmp(x, m) > 0 ? x : m), [0, 0, 0] as Specificity);

function compoundSpec(c: Compound): Specificity {
  let s: Specificity = [c.ids.length, c.classes.length + c.attrs.length, c.tag !== null ? 1 : 0];
  for (const p of c.pseudos) {
    if (p.name === 'where') continue;
    if (p.list) s = add(s, maxOf(p.list.map(complexSpec)));
    else s = add(s, [0, 1, 0]);
  }
  if (c.pseudoElement) s = add(s, [0, 0, 1]);
  return s;
}
const complexSpec = (x: Complex): Specificity => x.parts.reduce((s, p) => add(s, compoundSpec(p.compound)), [0, 0, 0] as Specificity);

// ---------------------------------------------------------------- matching

/** the tree a matcher walks: an element's parent and siblings within its own document or shadow tree */
export interface MatchTree { siblingsOf(n: HNode): HNode[]; parentOf(n: HNode): HNode | null }

const isShadowTemplate = (n: HNode): boolean => n.tag === 'template' && 'shadowrootmode' in n.attrs;

function nth(arg: string, pos: number): boolean {
  const a = arg.trim().toLowerCase().replace(/\s+/g, '');
  if (a === 'odd') return pos % 2 === 1;
  if (a === 'even') return pos % 2 === 0;
  const m = /^([+-]?\d*)n([+-]\d+)?$/.exec(a);
  if (m) {
    const A = m[1] === '' || m[1] === '+' ? 1 : m[1] === '-' ? -1 : Number(m[1]);
    const B = m[2] ? Number(m[2]) : 0;
    if (A === 0) return pos === B;
    return (pos - B) / A >= 0 && (pos - B) % A === 0;
  }
  if (/^[+-]?\d+$/.test(a)) return pos === Number(a);
  throw new Unsupported(arg);
}

const FORM_DISABLEABLE = new Set(['button', 'input', 'select', 'textarea', 'optgroup', 'option', 'fieldset']);
const REQUIRABLE = new Set(['input', 'select', 'textarea']);
/** a user action or the history: never true of a tree at rest */
const STATE = new Set(['hover', 'active', 'focus', 'focus-visible', 'focus-within', 'visited', 'target', 'target-within', 'local-link', 'current', 'past', 'future', 'playing', 'paused', 'user-invalid', 'user-valid']);

function attrMatches(n: HNode, t: AttrSel): boolean {
  if (!(t.name in n.attrs)) return false;
  if (!t.op) return true;
  const f = (x: string) => (t.fold ? x.toLowerCase() : x);
  const have = f(n.attrs[t.name]), want = f(t.value);
  switch (t.op) {
    case '=': return have === want;
    case '~=': return want !== '' && !/\s/.test(want) && have.split(/\s+/).includes(want);
    case '|=': return have === want || have.startsWith(`${want}-`);
    case '^=': return want !== '' && have.startsWith(want);
    case '$=': return want !== '' && have.endsWith(want);
    case '*=': return want !== '' && have.includes(want);
    default: return false;
  }
}

function pseudoMatches(n: HNode, p: Pseudo, t: MatchTree): boolean {
  if (STATE.has(p.name)) return false;
  const sibs = () => t.siblingsOf(n);
  const typed = () => sibs().filter((x) => x.tag === n.tag);
  switch (p.name) {
    case 'not': return !p.list!.some((c) => complexMatches(n, c, t));
    case 'is': case 'where': case 'matches': case '-webkit-any': case '-moz-any': return p.list!.some((c) => complexMatches(n, c, t));
    case 'root': return n.tag === 'html' && t.parentOf(n) === null;
    case 'empty': return n.children.length === 0 && !n.text;
    case 'first-child': return sibs()[0] === n;
    case 'last-child': return sibs()[sibs().length - 1] === n;
    case 'only-child': return sibs().length === 1;
    case 'first-of-type': return typed()[0] === n;
    case 'last-of-type': return typed()[typed().length - 1] === n;
    case 'only-of-type': return typed().length === 1;
    case 'nth-child': case 'nth-last-child': case 'nth-of-type': case 'nth-last-of-type': {
      if (p.arg === null || /\bof\b/i.test(p.arg)) throw new Unsupported(p.name);
      const list = p.name.includes('of-type') ? typed() : sibs();
      const i = list.indexOf(n);
      return nth(p.arg, p.name.includes('last') ? list.length - i : i + 1);
    }
    case 'link': case 'any-link': return (n.tag === 'a' || n.tag === 'area') && 'href' in n.attrs;
    case 'checked': return ((n.tag === 'input' && /^(checkbox|radio)$/i.test(n.attrs.type ?? '')) && 'checked' in n.attrs) || (n.tag === 'option' && 'selected' in n.attrs);
    case 'disabled': return FORM_DISABLEABLE.has(n.tag) && 'disabled' in n.attrs;
    case 'enabled': return FORM_DISABLEABLE.has(n.tag) && !('disabled' in n.attrs);
    case 'required': return REQUIRABLE.has(n.tag) && 'required' in n.attrs;
    case 'optional': return REQUIRABLE.has(n.tag) && !('required' in n.attrs);
    default: throw new Unsupported(p.name);
  }
}

function compoundMatches(n: HNode, c: Compound, t: MatchTree): boolean {
  if (c.pseudoElement) return false;
  if (c.tag !== null && c.tag !== n.tag) return false;
  if (c.ids.some((id) => n.attrs.id !== id)) return false;
  if (c.classes.length) {
    const cls = new Set((n.attrs.class ?? '').split(/\s+/).filter(Boolean));
    if (!c.classes.every((k) => cls.has(k))) return false;
  }
  if (!c.attrs.every((a) => attrMatches(n, a))) return false;
  return c.pseudos.every((p) => pseudoMatches(n, p, t));
}

function complexMatches(n: HNode, x: Complex, t: MatchTree, k = 0): boolean {
  const { compound, combinator } = x.parts[k];
  if (!compoundMatches(n, compound, t)) return false;
  if (k === x.parts.length - 1) return true;
  if (combinator === '>' || combinator === ' ') {
    for (let a = t.parentOf(n); a; a = t.parentOf(a)) {
      if (complexMatches(a, x, t, k + 1)) return true;
      if (combinator === '>') return false;
    }
    return false;
  }
  const sibs = t.siblingsOf(n);
  const i = sibs.indexOf(n);
  if (combinator === '+') return i > 0 && complexMatches(sibs[i - 1], x, t, k + 1);
  for (let j = i - 1; j >= 0; j--) if (complexMatches(sibs[j], x, t, k + 1)) return true;
  return false;
}

/**
 * The specificity of the most specific selector of the list that matches `n`, or null when none
 * does (or the list holds a selector this reader does not evaluate and nothing else matched).
 */
export function matchSpecificity(n: HNode, sel: ParsedSelector, t: MatchTree): Specificity | null {
  let best: Specificity | null = null;
  for (const x of sel.list) {
    let hit: boolean;
    try { hit = complexMatches(n, x, t); } catch (e) { if (e instanceof Unsupported) continue; throw e; }
    if (hit) { const s = complexSpec(x); if (!best || cmp(s, best) > 0) best = s; }
  }
  return best;
}

/** A tree for matching inside one document: a shadow root's template is the top of its tree. */
export function matchTree(top: HNode[]): MatchTree {
  return {
    parentOf: (n) => (n.parent && !isShadowTemplate(n.parent) ? n.parent : null),
    siblingsOf: (n) => (n.parent ? n.parent.children : top),
  };
}

export { cmp as compareSpecificity, type Specificity };
