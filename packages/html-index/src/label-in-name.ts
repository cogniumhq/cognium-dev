/**
 * Visible text beside accessible name: the visible text of an element and its accessible name, each
 * reduced to a comparable key by a Unicode text normalisation (below), and what a static reading
 * of the markup cannot know about that text.
 *
 * Facts only. What a consumer compares, and what it makes of the comparison, is the consumer's.
 */
import type { HNode } from './parse.js';

export interface LabelInName {
  /**
   * The visible inner text as the markup alone gives it: the text of the subtree in document order,
   * less the content the markup itself hides (`hidden`, inline display:none / visibility:hidden, a
   * closed dialog) and less what is not text (images, form fields, SVG, script, style).
   * `aria-hidden` content IS visible. A block-level element or `<br>` separates words; an inline
   * element does not.
   */
  visibleText: string;
  /**
   * The words of the visible text and of the accessible name joined by one space, with a space at
   * each end — so "the label's words appear in the name, in order, as whole consecutive words" is
   * `nameKey` containing `labelKey`. Normalisation: text in round brackets removed,
   * lower case, NFKD, every character that is not a letter or a digit read as a space.
   */
  labelKey: string;
  nameKey: string;
  /** the same keys with hyphens deleted instead of read as a space ("non-standard" and "nonstandard" then agree) */
  labelKeyDehyphenated: string;
  nameKeyDehyphenated: string;
  /** letters and digits in the label's words, and how many of them are digits */
  labelWordCharacters: number;
  labelDigits: number;
  /** a word of one string is written short in the other: followed by a full stop, and a proper prefix of a word there ("Ave." / "Avenue") */
  abbreviated: boolean;
  /**
   * What the stylesheets could do to this text that the markup does not say. `kind`: `hides` (a rule
   * that could match and hides, clips or moves content off screen), `font` (a rule that could match
   * and sets a font family: an icon font draws a word as a picture), `unread-stylesheet` (the page
   * links a sheet the subject tree does not hold), `unresolved-entity` (a character reference this
   * package does not decode). `on`: `self`, `descendant` or `ancestor` of the element. A rule "could
   * match" when the last compound of one of its selectors agrees with the element's tag, id and
   * classes and attribute tests; combinators and pseudo-classes are not evaluated, so this over-reports by design.
   */
  styleRisks: { kind: 'hides' | 'font' | 'unread-stylesheet' | 'unresolved-entity'; on: 'self' | 'descendant' | 'ancestor'; detail: string }[];
}

export interface CssRuleLike { media: string; selector: string; declarations: Record<string, string> }

const BLOCK_TAGS = new Set(['address', 'article', 'aside', 'blockquote', 'caption', 'dd', 'details', 'dialog', 'div', 'dl', 'dt', 'fieldset', 'figcaption', 'figure', 'footer', 'form',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hgroup', 'hr', 'legend', 'li', 'main', 'nav', 'ol', 'optgroup', 'option', 'p', 'pre', 'section', 'summary', 'table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr', 'ul']);
/** content the user agent does not render as text of the element */
const NO_TEXT_TAGS = new Set(['script', 'style', 'noscript', 'svg', 'img', 'input', 'select', 'textarea', 'video', 'audio', 'canvas', 'object', 'iframe', 'frame', 'head', 'title', 'meta', 'link']);

/** the character references short interface text commonly carries */
const ENTITIES: Record<string, string> = {
  amp: '&', quot: '"', apos: "'", lt: '<', gt: '>', nbsp: ' ', hellip: '…', times: '×', rarr: '→', larr: '←', raquo: '»', laquo: '«', mdash: '—', ndash: '–',
  middot: '·', bull: '•', copy: '©', reg: '®', trade: '™', rsaquo: '›', lsaquo: '‹', darr: '↓', uarr: '↑', check: '✓', ensp: ' ', emsp: ' ', thinsp: ' ', shy: '', zwnj: '', zwj: '',
};
const UNRESOLVED = /&[a-z][a-z0-9]*;/i;
function decode(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z][a-z0-9]*);/gi, (m, e: string) => {
    if (e[0] === '#') { const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m; }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

const inlineDisplay = (n: HNode): string | null => /(?:^|;)\s*display\s*:\s*([a-z-]+)/i.exec(n.attrs.style ?? '')?.[1].toLowerCase() ?? null;
/** the markup itself keeps `c` from being rendered (`aria-hidden` does not: it hides from the accessibility tree, not the screen) */
export const markupHides = (c: HNode): boolean =>
  'hidden' in c.attrs || (c.tag === 'dialog' && !('open' in c.attrs)) || /display\s*:\s*none/i.test(c.attrs.style ?? '') || /visibility\s*:\s*(hidden|collapse)/i.test(c.attrs.style ?? '');
const isShadowTemplate = (n: HNode): boolean => n.tag === 'template' && 'shadowrootmode' in n.attrs;
const skipped = (c: HNode): boolean => NO_TEXT_TAGS.has(c.tag) || (c.tag === 'template' && !isShadowTemplate(c)) || markupHides(c);

/** Whether the element renders its own content as text (not script, style, an image, a form field, a plain template, …). */
export const rendersText = (n: HNode): boolean => !NO_TEXT_TAGS.has(n.tag) && !(n.tag === 'template' && !isShadowTemplate(n));

/** The visible inner text of a subtree as the markup alone gives it (the visible inner text, without the stylesheets). */
export function visibleInnerText(n: HNode): string {
  const of = (x: HNode): string => {
    const runs = x.runs ?? (x.text ? [{ at: 0, text: x.text }] : []);
    const gaps = new Set(x.gaps ?? []);
    let s = '', r = 0;
    const before = (i: number) => { if (gaps.has(i)) s += ' '; while (r < runs.length && runs[r].at <= i) s += runs[r++].text; };
    x.children.forEach((c, i) => {
      before(i);
      if (c.tag === 'br') { s += '\n'; return; }
      if (skipped(c)) return;
      const d = inlineDisplay(c);
      const block = d === null ? BLOCK_TAGS.has(c.tag) : !/^inline/.test(d) && d !== 'contents';
      s += block ? `\n${of(c)}\n` : of(c);
    });
    before(x.children.length);
    while (r < runs.length) s += runs[r++].text;
    return s;
  };
  return decode(of(n)).replace(/\s+/g, ' ').trim();
}

/** The words of a string: round-bracketed text removed, lower case, NFKD, every non-letter non-digit a space. */
export function labelWords(s: string, dehyphenate = false): string[] {
  let t = s;
  for (let prev = ''; prev !== t;) { prev = t; t = t.replace(/\([^()]*\)/g, ' '); }
  if (dehyphenate) t = t.replace(/[-‐-―­]/g, '');
  return t.toLowerCase().normalize('NFKD').replace(/[^\p{L}\p{N}]+/gu, ' ').trim().split(' ').filter(Boolean);
}
const keyOf = (w: string[]): string => (w.length ? ` ${w.join(' ')} ` : '');

/** a word (with a letter in it: a number before a full stop is not an abbreviation) followed by a full stop in `a` that is a proper prefix of a word of `b` */
function abbreviates(a: string, b: string[]): boolean {
  for (const m of a.toLowerCase().normalize('NFKD').matchAll(/((?=[\p{N}]*\p{L})[\p{L}\p{N}]+)\./gu)) if (b.some((w) => w.length > m[1].length && w.startsWith(m[1]))) return true;
  return false;
}

/** declarations that hide, clip or move content off screen */
const HIDING: [string, RegExp][] = [
  ['display', /^none\b/i], ['visibility', /^(hidden|collapse)\b/i], ['opacity', /^(0|0?\.0\d*)\s*(!|$)/], ['clip', /rect/i], ['clip-path', /^(?!none)/i],
  ['font-size', /^0[a-z%]*\s*(!|$)/i], ['text-indent', /^-|^\d{3,}/], ['width', /^[01](px)?\s*(!|$)/i], ['height', /^[01](px)?\s*(!|$)/i], ['max-height', /^0/], ['max-width', /^0/],
  ['left', /^-\d{3,}/], ['top', /^-\d{3,}/], ['margin-left', /^-\d{3,}/], ['content-visibility', /^hidden/i], ['color', /^transparent/i], ['transform', /scale[XY]?\(\s*0\s*[,)]/i],
];

interface Compound { tag: string | null; id: string | null; classes: string[]; attrs: { name: string; op: string; value: string; fold: boolean }[]; pseudoElement: boolean }

/** The last compound selector of each selector of a rule, read for tag, id, classes and attribute tests. */
function lastCompounds(selector: string): Compound[] {
  const out: Compound[] = [];
  const parts: string[] = [];
  let depth = 0, cur = '';
  for (const ch of selector) {
    if (ch === '(' || ch === '[') depth++;
    if (ch === ')' || ch === ']') depth--;
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; } else cur += ch;
  }
  parts.push(cur);
  for (const part of parts) {
    let d = 0, last = '';
    for (const ch of part.trim()) {
      if (ch === '(' || ch === '[') d++;
      if (ch === ')' || ch === ']') d--;
      if (d === 0 && /[\s>+~]/.test(ch)) last = ''; else last += ch;
    }
    if (!last) continue;
    // attribute tests of the compound itself (those inside :not(), :is() … are not read: the pseudo-class is taken as satisfiable)
    const top = last.replace(/:[a-z-]+\((?:[^()]|\([^()]*\))*\)/gi, '');
    const attrs = [...top.matchAll(/\[\s*([\w-]+)\s*(?:([~|^$*]?=)\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]*))\s*([is])?\s*)?\]/g)]
      .map((m) => ({ name: m[1].toLowerCase(), op: m[2] ?? '', value: m[3] ?? m[4] ?? m[5] ?? '', fold: m[6] === 'i' }));
    const bare = top.replace(/\[[^\]]*\]/g, '').replace(/::?[a-z-]+/gi, '');
    out.push({
      tag: /^[a-z][a-z0-9-]*/i.exec(bare)?.[0].toLowerCase() ?? null,
      id: /#([\w-]+)/.exec(bare)?.[1] ?? null,
      classes: [...bare.matchAll(/\.([\w-]+)/g)].map((m) => m[1]),
      attrs,
      pseudoElement: /::|:(before|after|first-line|first-letter)\b/i.test(last),
    });
  }
  return out;
}

function attrHolds(n: HNode, t: Compound['attrs'][number]): boolean {
  if (!(t.name in n.attrs)) return false;
  if (!t.op) return true;
  const fold = (x: string) => (t.fold ? x.toLowerCase() : x);
  const have = fold(n.attrs[t.name]), want = fold(t.value);
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

function couldMatch(n: HNode, selector: string): boolean {
  const classes = new Set((n.attrs.class ?? '').split(/\s+/).filter(Boolean));
  return lastCompounds(selector).some((c) => !c.pseudoElement && (c.tag === null || c.tag === n.tag) && (c.id === null || c.id === n.attrs.id)
    && c.classes.every((k) => classes.has(k)) && c.attrs.every((t) => attrHolds(n, t)));
}

const printOnly = (media: string): boolean => /\bprint\b/i.test(media) && !/\bscreen\b|\ball\b/i.test(media);

/**
 * `unreadSheets`: how many stylesheets the page links that the subject tree does not hold (an
 * absolute URL, a missing file). `accName`: the element's computed accessible name.
 */
export function labelInName(n: HNode, accName: string, rules: CssRuleLike[], unreadSheets: number): LabelInName {
  const visibleText = visibleInnerText(n);
  const label = labelWords(visibleText), name = labelWords(accName);
  const risks: LabelInName['styleRisks'] = [];
  const seen = new Set<string>();
  const add = (kind: LabelInName['styleRisks'][number]['kind'], on: LabelInName['styleRisks'][number]['on'], detail: string) => {
    const k = `${kind}|${on}|${detail}`;
    if (!seen.has(k) && risks.length < 24) { seen.add(k); risks.push({ kind, on, detail }); }
  };
  const subtree: HNode[] = [];
  const collect = (x: HNode) => { for (const c of x.children) { if (skipped(c)) continue; subtree.push(c); collect(c); } };
  collect(n);
  const ancestors: HNode[] = [];
  for (let a = n.parent; a; a = a.parent) ancestors.push(a);
  const screen = rules.filter((r) => !printOnly(r.media));
  const scan = (x: HNode, on: 'self' | 'descendant' | 'ancestor') => {
    for (const r of screen) {
      const hiding = HIDING.filter(([prop, re]) => r.declarations[prop] !== undefined && re.test(r.declarations[prop].trim()));
      const font = on === 'ancestor' ? undefined : r.declarations['font-family'] ?? (/^(inherit|initial|unset)$/i.test(r.declarations.font ?? '') ? undefined : r.declarations.font);
      if (!hiding.length && font === undefined) continue;
      if (!couldMatch(x, r.selector)) continue;
      for (const [prop] of hiding) add('hides', on, `${r.selector} { ${prop}: ${r.declarations[prop]} }`.slice(0, 120));
      if (font !== undefined) add('font', on, font.slice(0, 120));
    }
    // an inline style can set the font too (and can clip: a visually-hidden pattern written inline)
    const st = x.attrs.style ?? '';
    const inlineFont = /(?:^|;)\s*font(?:-family)?\s*:\s*([^;]+)/i.exec(st)?.[1];
    if (inlineFont && on !== 'ancestor') add('font', on, inlineFont.trim().slice(0, 120));
    if (/(?:^|;)\s*(clip|clip-path|opacity|font-size|text-indent|width|height|left|top)\s*:/i.test(st)) {
      for (const m of st.matchAll(/(?:^|;)\s*([a-z-]+)\s*:\s*([^;]+)/gi)) {
        const h = HIDING.find(([prop, re]) => prop === m[1].toLowerCase() && prop !== 'display' && prop !== 'visibility' && re.test(m[2].trim()));
        if (h) add('hides', on, `style="${m[1]}: ${m[2].trim()}"`.slice(0, 120));
      }
    }
  };
  scan(n, 'self');
  for (const d of subtree) scan(d, 'descendant');
  for (const a of ancestors) scan(a, 'ancestor');
  if (unreadSheets > 0) add('unread-stylesheet', subtree.length ? 'descendant' : 'self', `${unreadSheets} linked stylesheet(s) not in the subject tree`);
  if (UNRESOLVED.test(visibleText)) add('unresolved-entity', 'self', UNRESOLVED.exec(visibleText)![0]);
  const chars = label.join('');
  return {
    visibleText,
    labelKey: keyOf(label), nameKey: keyOf(name),
    labelKeyDehyphenated: keyOf(labelWords(visibleText, true)), nameKeyDehyphenated: keyOf(labelWords(accName, true)),
    labelWordCharacters: [...chars].length, labelDigits: [...chars].filter((c) => /\p{N}/u.test(c)).length,
    abbreviated: abbreviates(visibleText, name) || abbreviates(accName, label),
    styleRisks: risks,
  };
}
