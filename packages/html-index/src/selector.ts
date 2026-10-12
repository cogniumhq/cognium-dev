/**
 * how many elements of a document a style rule's selector COULD match.
 *
 * Not a selector engine. Only the LAST compound of each selector in the list is read, for its type,
 * id, classes and attribute tests; combinators, pseudo-classes and pseudo-elements are taken as
 * satisfiable, and anything this does not parse constrains nothing. So the count is over-reported by
 * design and its zero is the fact a consumer can rely on: when it is 0, no element of the tree carries
 * the type, id, classes and attributes the rule's subject must have, and the rule styles nothing in
 * this document as built. Class, id and attribute values are compared without case (a quirks-mode
 * document matches classes and ids that way), which only over-reports further.
 *
 * Escapes are decoded (CSS Syntax §4.3.7), because the class Tailwind writes as `.md\:animate-spin`
 * is `md:animate-spin` in the markup.
 */
import type { HNode } from './parse.js';

interface AttrTest { name: string; op: string; value: string }
interface Compound { tag: string | null; id: string | null; classes: string[]; attrs: AttrTest[] }

const blank = (): Compound => ({ tag: null, id: null, classes: [], attrs: [] });
const HEX = /[0-9a-f]/i;
const identChar = (c: string): boolean => /[\w-]/.test(c) || c.charCodeAt(0) >= 0x80;

/** one escape at `i` (the character after the backslash): the decoded text and the index after it */
function escape(s: string, i: number): [string, number] {
  if (i >= s.length) return ['', i];
  if (!HEX.test(s[i])) { const ch = String.fromCodePoint(s.codePointAt(i)!); return [ch, i + ch.length]; }
  let j = i;
  while (j < s.length && j - i < 6 && HEX.test(s[j])) j++;
  const cp = Number.parseInt(s.slice(i, j), 16);
  if (/\s/.test(s[j] ?? '')) j++;   // one white space ends a hex escape and is part of it
  return [cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '�', j];
}

/** an identifier at `i`, escapes decoded */
function ident(s: string, i: number): [string, number] {
  let out = '';
  while (i < s.length) {
    if (s[i] === '\\') { const [t, j] = escape(s, i + 1); out += t; i = j; }
    else if (identChar(s[i])) out += s[i++];
    else break;
  }
  return [out, i];
}

/** the index after the bracket that closes the one at `i`; strings and escapes are skipped */
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
  return s.length;
}

/** `[name]`, `[name op value flag]`; null when it is not read (a namespace, a form this does not know) */
function attrTest(body: string): AttrTest | null {
  let i = 0;
  const ws = () => { while (/\s/.test(body[i] ?? '')) i++; };
  ws();
  const [name, a] = ident(body, i);
  if (!name) return null;
  i = a; ws();
  if (i >= body.length) return { name: name.toLowerCase(), op: '', value: '' };
  const op = /^[~|^$*]?=/.exec(body.slice(i))?.[0];
  if (!op) return null;
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
  if (i < body.length && !/^[is]\s*$/i.test(body.slice(i))) return null;
  return { name: name.toLowerCase(), op, value };
}

/** The last compound of each selector of the list, or an unconstrained one where it could not be read. */
export function lastCompounds(selector: string): Compound[] {
  const out: Compound[] = [];
  let cur = blank();
  let combinator = false;   // a combinator was passed: the next simple selector starts a new compound
  const part = (): Compound => { if (combinator) { cur = blank(); combinator = false; } return cur; };
  const s = selector.replace(/\/\*[\s\S]*?\*\//g, ' ');   // a comment is white space
  for (let i = 0; i < s.length;) {
    const c = s[i];
    if (c === ',') { out.push(cur); cur = blank(); combinator = false; i++; }
    else if (/\s/.test(c) || c === '>' || c === '+' || c === '~') { combinator = true; i++; }
    else if (c === '.') { const [k, j] = ident(s, i + 1); if (k) part().classes.push(k.toLowerCase()); else part(); i = Math.max(j, i + 1); }
    else if (c === '#') { const [k, j] = ident(s, i + 1); if (k) part().id = k.toLowerCase(); else part(); i = Math.max(j, i + 1); }
    else if (c === '[') {
      const j = closing(s, i);
      const t = attrTest(s.slice(i + 1, j - 1));
      if (t) part().attrs.push(t); else part();
      i = j;
    }
    else if (c === ':') {
      // a pseudo-class or pseudo-element, with its arguments: satisfiable, so it constrains nothing
      part();
      i++;
      if (s[i] === ':') i++;
      i = ident(s, i)[1];
      if (s[i] === '(') i = closing(s, i);
    }
    else if (c === '*' || c === '&') { part(); i++; }
    else if (c === '|') { part().tag = null; i++; }   // a namespace prefix: the type is not compared
    else if (c === '\\' || identChar(c)) {
      const [k, j] = ident(s, i);
      // a type selector; one written after a namespace prefix (`svg|a`) is still the element's local name
      part().tag = k.toLowerCase();
      i = Math.max(j, i + 1);
    }
    else { part(); i++; }   // not selector syntax this reads (a keyframe percentage, say): no constraint
  }
  out.push(cur);
  return out;
}

function attrHolds(n: HNode, t: AttrTest): boolean {
  if (!(t.name in n.attrs)) return false;
  if (!t.op) return true;
  const have = n.attrs[t.name].toLowerCase(), want = t.value.toLowerCase();
  switch (t.op) {
    case '=': return have === want;
    case '~=': return have.split(/\s+/).includes(want);
    case '|=': return have === want || have.startsWith(`${want}-`);
    case '^=': return want !== '' && have.startsWith(want);
    case '$=': return want !== '' && have.endsWith(want);
    case '*=': return want !== '' && have.includes(want);
    default: return true;
  }
}

/** A document's elements, indexed once so that every rule of a large sheet is not a walk of the tree. */
export interface SelectorIndex { nodes: HNode[]; classes: Map<HNode, Set<string>>; byClass: Map<string, HNode[]>; byId: Map<string, HNode[]>; byTag: Map<string, HNode[]> }

export function selectorIndex(nodes: HNode[]): SelectorIndex {
  const ix: SelectorIndex = { nodes, classes: new Map(), byClass: new Map(), byId: new Map(), byTag: new Map() };
  const add = (m: Map<string, HNode[]>, k: string, n: HNode) => { const l = m.get(k); if (l) l.push(n); else m.set(k, [n]); };
  for (const n of nodes) {
    const cls = new Set((n.attrs.class ?? '').toLowerCase().split(/\s+/).filter(Boolean));
    ix.classes.set(n, cls);
    for (const k of cls) add(ix.byClass, k, n);
    if (n.attrs.id) add(ix.byId, n.attrs.id.toLowerCase(), n);
    add(ix.byTag, n.tag.toLowerCase(), n);
  }
  return ix;
}

/** How many elements of the indexed document the rule's selector could match (see the file comment). */
export function couldMatchCount(ix: SelectorIndex, selector: string): number {
  const hit = new Set<HNode>();
  for (const c of lastCompounds(selector)) {
    if (c.tag === null && c.id === null && !c.classes.length && !c.attrs.length) return ix.nodes.length;
    const from = c.id !== null ? ix.byId.get(c.id) ?? [] : c.classes.length ? ix.byClass.get(c.classes[0]) ?? [] : c.tag !== null ? ix.byTag.get(c.tag) ?? [] : ix.nodes;
    for (const n of from) {
      if (c.tag !== null && n.tag.toLowerCase() !== c.tag) continue;
      if (c.id !== null && (n.attrs.id ?? '').toLowerCase() !== c.id) continue;
      const cls = ix.classes.get(n)!;
      if (c.classes.every((k) => cls.has(k)) && c.attrs.every((t) => attrHolds(n, t))) hit.add(n);
    }
  }
  return hit.size;
}
