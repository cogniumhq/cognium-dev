/**
 * Capability `html-index`: one observation per built HTML page (`PageObservation`). Facts only;
 * no verdicts.
 *
 * Catalog tables (ARIA 1.2 and ARIA-in-HTML views) arrive as data. The algorithms are W3C ones:
 *  - role: the first role token the user agent recognises (ARIA 1.2 §7.1), else the implicit role
 *    of the element's ARIA-in-HTML row; presentational role conflict resolution (ARIA 1.2 §9.3);
 *  - ownership: descend until a nested composite; `aria-owns` re-parents;
 *  - accessible name: AccName 1.2 step order with HTML-AAM sources, name from content only for
 *    roles that allow it (step 2F), children's text alternatives included;
 *  - the IDREF graph, with table structure for `headers`.
 */
import { readFileSync } from 'node:fs';
import { dirname, extname, join, normalize } from 'node:path';
import postcss from 'postcss';
import { inOrder, parseHtml, type HNode, type PageIndex, type ParseError } from './parse.js';
import { isUnder, isUnderReal } from './path.js';
import { decode, labelInName, markupHides, rendersText, visibleInnerText, type LabelInName } from './label-in-name.js';
import { couldMatchCount, selectorIndex } from './selector.js';
import { compareSpecificity, matchSpecificity, matchTree, parseSelector, type Specificity } from './cascade.js';

export interface HtmlAriaViews {
  'row-match': { key: string; tag: string; all: Record<string, unknown>[] }[];
  'tag-row': Record<string, string>;
  'implicit-role-by-row': Record<string, string>;
  'implicit-role-by-tag-default': Record<string, string>;
}

export interface AriaViews {
  'required-owned': Record<string, string[]>;
  'role-names': string[];
  'global-attributes': string[];
  'name-from-contents': string[];
}

export interface HtmlIndexParams {
  idrefAttributes?: string[];
  /** the framework handler table `elements[].markupHandlers` reads (schema 0.3); none, and every element has none */
  markupHandlers?: MarkupHandlerRule[];
}

// ---------------------------------------------------------------- row matching

const INPUT_TYPES = new Set(['button', 'checkbox', 'color', 'date', 'datetime-local', 'email', 'file', 'hidden', 'image', 'month',
  'number', 'password', 'radio', 'range', 'reset', 'search', 'submit', 'tel', 'text', 'time', 'url', 'week']);

function pred(n: HNode, p: Record<string, unknown>): boolean {
  const [k, v] = Object.entries(p)[0] as [string, any];
  const a = n.attrs;
  switch (k) {
    case 'has': return v in a;
    case 'lacks': return !(v in a);
    case 'eq': return v[0] in a && (a[v[0]] ?? '').toLowerCase() === String(v[1]).toLowerCase();
    case 'gt': return v[0] in a && Number(a[v[0]]) > v[1];
    case 'not-gt': return !(v[0] in a) || !(Number(a[v[0]]) > v[1]);
    case 'any-of': return (v as Record<string, unknown>[]).some((q) => pred(n, q));
    case 'nonempty-attr': return (a[v] ?? '').trim() !== '';
    case 'type-in-or-default': {
      const t = (a.type ?? '').trim().toLowerCase();
      return (v as string[]).includes(t) || (!INPUT_TYPES.has(t) && (v as string[]).includes('text'));
    }
    case 'not-first-child-of': return !(n.parent !== null && n.parent.tag === v && n.parent.children[0] === n);
    case 'parent-not': return n.parent?.tag !== v;
    default: throw new Error(`html-index: unknown row-match predicate ${k}`);
  }
}

export function hostRow(n: HNode, v: HtmlAriaViews): string | null {
  for (const m of v['row-match']) if (m.tag === n.tag && m.all.every((p) => pred(n, p))) return m.key;
  if (v['row-match'].some((m) => m.tag === n.tag)) return null; // a multi-row tag no predicate matched: unknown
  return v['tag-row'][n.tag] ?? null;
}

// ---------------------------------------------------------------- HTML facts (syntax and platform semantics)

/** HTML labelable elements (HTML §4.10.2). */
const LABELABLE = new Set(['button', 'input', 'meter', 'output', 'progress', 'select', 'textarea']);
/** labelable elements whose own content is not a label a user reads (a value, options, a gauge) */
const FIELD = new Set(['input', 'meter', 'output', 'progress', 'select', 'textarea']);

/** HTML focusable-by-default elements (sequential focus navigation), plus [tabindex] and contenteditable. */
function focusable(n: HNode): boolean {
  const a = n.attrs;
  if ('disabled' in a && ['button', 'input', 'select', 'textarea'].includes(n.tag)) return false;
  if ('tabindex' in a && a.tabindex.trim() !== '' && !Number.isNaN(Number(a.tabindex))) return true;
  if ('contenteditable' in a && a.contenteditable.toLowerCase() !== 'false') return true;
  if ((n.tag === 'a' || n.tag === 'area') && 'href' in a) return true;
  if (n.tag === 'input') return (a.type ?? '').toLowerCase() !== 'hidden';
  if (['button', 'select', 'textarea', 'iframe'].includes(n.tag)) return true;
  if (n.tag === 'summary') return true;
  if ((n.tag === 'audio' || n.tag === 'video') && 'controls' in a) return true;
  return false;
}

/**
 * Not rendered, so not in the accessibility tree: aria-hidden, the `hidden` attribute and inline
 * display:none / visibility:hidden, on the element or an ancestor — and a closed `<dialog>`, which
 * the user agent stylesheet hides as it hides `[hidden]` (HTML Living Standard, Rendering:
 * `dialog:not([open]) { display: none; }`). A dialog opened by `showModal()` or `show()` carries `open` in the built
 * DOM, so the as-built pass still sees it.
 */
function hiddenNode(n: HNode): boolean {
  for (let c: HNode | null = n; c; c = c.parent) if (hidesItself(c)) return true;
  return false;
}

/** `hiddenNode`'s test on one node, without its ancestors. */
function hidesItself(c: HNode): boolean {
  if ((c.attrs['aria-hidden'] ?? '').toLowerCase() === 'true') return true;
  if ('hidden' in c.attrs) return true;
  if (c.tag === 'dialog' && !('open' in c.attrs)) return true;
  if (/display\s*:\s*none/i.test(c.attrs.style ?? '')) return true;
  if (/visibility\s*:\s*hidden/i.test(c.attrs.style ?? '')) return true;
  return false;
}

/**
 * The viewport meta translation (CSS Device Adaptation, "translate a meta viewport"): a value is a
 * number, or yes → 1, no → 0.1, device-width / device-height → 10, anything else → 0.1.
 * user-scalable is "no" when the translated value lies in (-1, 1); negative scales are ignored.
 */
function translate(v: string): number {
  if (v === 'yes') return 1;
  if (v === 'no') return 0.1;
  if (v === 'device-width' || v === 'device-height') return 10;
  const n = Number.parseFloat(v);
  return Number.isNaN(n) ? 0.1 : n;
}
function parseViewport(content: string | null) {
  if (content === null) return { present: false, content: null, userScalable: null, maximumScale: null };
  const kv: Record<string, string> = {};
  for (const part of content.toLowerCase().split(/[,;]/)) {
    const [k, v] = part.split('=').map((s) => s?.trim());
    if (k) kv[k] = v ?? '';
  }
  const us = kv['user-scalable'];
  const userScalable = us === undefined ? null : Math.abs(translate(us)) >= 1;
  const ms = kv['maximum-scale'] === undefined ? null : translate(kv['maximum-scale']);
  return { present: true, content, userScalable, maximumScale: ms !== null && ms > 0 ? ms : null };
}

const ANGLE: Record<string, number> = { deg: 1, rad: 180 / Math.PI, turn: 360, grad: 0.9 };
function angle(v: string): number | null {
  const m = /^(-?[\d.]+)(deg|rad|turn|grad)$/.exec(v.trim());
  return m ? Number(m[1]) * ANGLE[m[2]] : null;
}
/** Net rotation in degrees of a `transform` or `rotate` value (rotate, rotateZ, matrix, matrix3d), or null. */
export function rotationOf(decls: Record<string, string>): number | null {
  let total: number | null = null;
  const add = (d: number | null) => { if (d !== null) total = (total ?? 0) + d; };
  if (decls.rotate) add(angle(decls.rotate.split(/\s+/).pop()!));
  for (const m of (decls.transform ?? '').matchAll(/(rotate|rotateZ|matrix|matrix3d)\(([^)]*)\)/g)) {
    const args = m[2].split(',').map((x) => x.trim());
    if (m[1] === 'rotate' || m[1] === 'rotateZ') { if (args.length === 1) add(angle(args[0])); }
    else { const a = Number(args[0]), b = Number(args[1]); if (!Number.isNaN(a) && !Number.isNaN(b)) add((Math.atan2(b, a) * 180) / Math.PI); }
  }
  return total === null ? null : Math.round((((total % 360) + 360) % 360) * 1000) / 1000;
}

/** the subject-tree file a stylesheet link names, when the tree holds it (the same test `cssRulesOf` reads by) */
function sheetInTree(p: PageIndex, root: string, rawHref: string): boolean {
  if (/^[a-z]+:\/\//i.test(rawHref) || rawHref.startsWith('//')) return false;
  const href = rawHref.split(/[?#]/)[0];
  const f = normalize(href.startsWith('/') ? join(root, href) : join(root, dirname(p.path), href));
  return isUnder(root, f) && isUnderReal(root, f);
}

/**
 * One style rule, and whose it is. a rule styles the document (or the shadow tree) its
 * sheet sits in and nothing else — a frame's sheet does not reach the page that frames it, a shadow
 * tree's sheet does not reach the light DOM, and the page's sheets do not reach into a shadow tree
 * (CSS Scoping) — so every rule says which one that is.
 */
export interface CssRuleObs {
  file: string; line: number; media: string; selector: string; declarations: Record<string, string>; rotation: number | null;
  /** null for a rule of the page's own document; the frame chain (as on an element) for a rule of a nested frame document */
  frame: string | null;
  /** null for a document-level rule; the id (in `elements`) of the host whose declarative shadow root holds the sheet */
  shadowHost: number | null;
  /**
   * How many elements of the rule's OWN document its selector could match: the last
   * compound of each selector agrees with the element's type, id, classes and attribute tests
   * (`selector.ts`; combinators and pseudo-classes are not evaluated, so it is over-reported by
   * design). 0 says no element of the tree as it was read can be the rule's subject.
   */
  couldMatch: number;
}

/** the host of the innermost declarative shadow root `n` sits in, or null */
function shadowHostOf(n: HNode): HNode | null {
  for (let a = n.parent; a; a = a.parent) if (a.tag === 'template' && 'shadowrootmode' in a.attrs) return a.parent;
  return null;
}

/**
 * One stylesheet a document loads, with its rules (the same rows as `cssRules`, in the same order).
 * `kind` `linked` is a `<link rel="stylesheet">`, `inline` a `<style>` block. `resolved` is false
 * for a linked sheet the root does not hold (a missing file, an absolute URL, a path out of the
 * root): its `rules` are empty, and `cssRules` has no trace of it.
 */
export interface StylesheetObs {
  /** the file under the root (`css/site.css`), `<page>#style@<line>` for a `<style>` block, null when the href names no file under the root */
  file: string | null;
  /** the `href` as written; null for a `<style>` block */
  href: string | null;
  kind: 'linked' | 'inline';
  /** the line of the `<link>` or `<style>` start tag */
  line: number;
  /** the element's `media` attribute as written, `""` when it has none */
  media: string;
  resolved: boolean;
  /** the sheet was read and parsed; false when it did not resolve or did not parse */
  parsed: boolean;
  /** as on its rules: the frame chain of a nested frame document's sheet, else null */
  frame: string | null;
  /** as on its rules: the host of the declarative shadow root holding the sheet, else null */
  shadowHost: number | null;
  rules: CssRuleObs[];
}

/** a rule as read, with every declaration in source order (the `declarations` map keeps the last of each property) */
interface RuleRead { obs: CssRuleObs; decls: { prop: string; value: string; important: boolean }[]; inKeyframes: boolean; sheetMedia: string }

function readSheets(p: PageIndex, root: string, idOf: Map<HNode, number>, frame: string | null): { sheets: StylesheetObs[]; rules: RuleRead[] } {
  const index = selectorIndex(p.nodes);
  const sheets: StylesheetObs[] = [];
  const rules: RuleRead[] = [];
  for (const n of p.nodes) {
    const host = shadowHostOf(n);
    const shadowHost = host ? idOf.get(host) ?? null : null;
    let sheet: StylesheetObs | null = null;
    let text: string | null = null;
    if (n.tag === 'link' && /(^|\s)stylesheet(\s|$)/i.test(n.attrs.rel ?? '') && n.attrs.href) {
      const absolute = /^[a-z]+:\/\//i.test(n.attrs.href);
      const href = n.attrs.href.split(/[?#]/)[0];
      const f = normalize(href.startsWith('/') ? join(root, href) : join(root, dirname(p.path), href));
      // inside the root lexically and after following symlinks; isUnderReal is false for a missing file
      const resolved = !absolute && isUnder(root, f) && isUnderReal(root, f);
      if (resolved) text = readFileSync(f, 'utf8');
      sheet = { file: !absolute && isUnder(root, f) ? f.slice(root.length + 1) : null, href: n.attrs.href, kind: 'linked', line: n.line, media: n.attrs.media ?? '', resolved, parsed: false, frame, shadowHost, rules: [] };
    }
    if (n.tag === 'style') {
      text = n.text;
      sheet = { file: `${p.path}#style@${n.line}`, href: null, kind: 'inline', line: n.line, media: n.attrs.media ?? '', resolved: true, parsed: false, frame, shadowHost, rules: [] };
    }
    if (!sheet) continue;
    sheets.push(sheet);
    if (text === null) continue;
    let ast: postcss.Root;
    try { ast = postcss.parse(text); } catch { continue; }
    sheet.parsed = true;
    const s = sheet;
    ast.walkRules((r) => {
      const media: string[] = [];
      let inKeyframes = false;
      for (let a: postcss.Node | undefined = r.parent as postcss.Node | undefined; a && a.type !== 'root'; a = a.parent as postcss.Node | undefined) {
        if (a.type === 'atrule' && (a as postcss.AtRule).name === 'media') media.push((a as postcss.AtRule).params);
        if (a.type === 'atrule' && /keyframes$/i.test((a as postcss.AtRule).name)) inKeyframes = true;
      }
      const declarations: Record<string, string> = {};
      const decls: RuleRead['decls'] = [];
      r.walkDecls((d) => { declarations[d.prop.toLowerCase()] = d.value; if (d.parent === r) decls.push({ prop: d.prop.toLowerCase(), value: d.value, important: !!d.important }); });
      const obs: CssRuleObs = { file: s.file!, line: r.source?.start?.line ?? 0, media: media.join(' and '), selector: r.selector, declarations, rotation: rotationOf(declarations), frame, shadowHost: s.shadowHost, couldMatch: couldMatchCount(index, r.selector) };
      s.rules.push(obs);
      rules.push({ obs, decls, inKeyframes, sheetMedia: s.media });
    });
  }
  return { sheets, rules };
}

/** One author declaration that matches an element at rest, and where it was written. */
export interface CssDeclarationObs {
  property: string;
  /** the value as written, without `!important` (as in `cssRules[].declarations`) */
  value: string;
  important: boolean;
  /** the rule's `@media` conditions, as `cssRules[].media` */
  media: string;
  /** the `media` attribute of the `<link>` or `<style>` that loads the sheet; `""` for an inline style */
  sheetMedia: string;
  /** declared in the element's own `style` attribute */
  inline: boolean;
  /** the rule (`cssRules` row) it came from; for an inline style, the page and the element's line, selector null */
  source: { file: string; line: number; selector: string | null };
}

/** A `cursor` declaration (schema 0.3): a `CssDeclarationObs`, and whose it is. */
export interface CursorDeclarationObs extends CssDeclarationObs {
  /** declared on an ancestor and inherited (`cursor` is an inherited property), not on the element itself */
  inherited: boolean;
  /** the id (in `elements`) of the element the declaration matches: the element itself, or the ancestor it inherits from */
  from: number;
}

/** The author declarations of three property families that match the element, lowest precedence first. */
export interface ElementCssObs {
  /** `animation` and `animation-*` (and their vendor-prefixed forms) */
  animation: CssDeclarationObs[];
  /** `text-decoration` and `text-decoration-*` (and their vendor-prefixed forms) */
  textDecoration: CssDeclarationObs[];
  /**
   * `cursor` (schema 0.3): the element's own declarations; when it has none, those of the nearest
   * ancestor that has any, each marked `inherited`. Empty when no author rule reaches it: the user
   * agent's own cursors (a link's pointer, a text field's I-beam) are not listed.
   */
  cursor: CursorDeclarationObs[];
}

const FAMILIES: [keyof ElementCssObs, RegExp][] = [
  ['animation', /^(-[a-z]+-)?animation(-|$)/],
  ['textDecoration', /^(-[a-z]+-)?text-decoration(-|$)/],
  ['cursor', /^cursor$/],
];
const familyOf = (prop: string): keyof ElementCssObs | null => FAMILIES.find(([, re]) => re.test(prop))?.[0] ?? null;

/** the declarations of a `style` attribute, in source order */
function inlineDeclarations(style: string): RuleRead['decls'] {
  if (!style.trim()) return [];
  const out: RuleRead['decls'] = [];
  try { postcss.parse(`x{${style}}`).walkDecls((d) => { out.push({ prop: d.prop.toLowerCase(), value: d.value, important: !!d.important }); }); } catch { return []; }
  return out;
}

// ---------------------------------------------------------------- page observation

export interface ElementObs {
  id: number; tag: string; attrs: Record<string, string>; line: number;
  ancestorIds: number[]; ancestorTags: string[]; hostRow: string | null;
  roleTokens: string[]; explicitRole: string | null; effectiveRole: string | null;
  ownedRoles: string[]; ancestorRoles: string[]; contextRole: string | null;
  childElementCount: number; ariaAttrs: string[]; name: string; nameSource: string | null; visibleLabel: boolean;
  hidden: boolean; focusable: boolean; inSvg: boolean; pointerHandlers: string[]; keyHandlers: string[]; tabindex: number | null;
  /** the subtree holds text a user can perceive, as name from content reads it (whatever the role) */
  hasText: boolean;
  /**
   * null for an element of the page itself; for one of a document nested in it (an
   * iframe's `srcdoc`, or a same-origin `src` in the subject tree), the chain of frames it sits in,
   * outermost first, joined by ` >>> ` — e.g. `iframe[src="./_mid.html"]@14 >>> iframe[srcdoc]@12`.
   * `line` is then a line of THAT document.
   */
  frame: string | null;
  /** inside a declarative shadow root (`<template shadowrootmode>`) */
  inShadow: boolean;
  /**
   * null unless the element carries `aria-label` or `aria-labelledby`; then its visible
   * text beside its accessible name, each as a normalised key (see `LabelInName`).
   */
  labelInName: LabelInName | null;
  /**
   * The element's 1-based position among its parent's children of the same tag — the
   * `n` of CSS `:nth-of-type(n)` — or null when it is the only child of its tag (a selector
   * written for a person leaves the index out there too). Read off the parsed tree.
   */
  nthOfType: number | null;
  /** the same for each ancestor, parallel to `ancestorTags` (nearest first) */
  ancestorNthOfType: (number | null)[];
  /**
   * The text a sighted user reads as the element's label, as the markup gives it (beside `name`,
   * which is what assistive technology reads). For a form field (`input`, `select`, `textarea`,
   * `meter`, `progress`, `output`): the visible text of its `<label>`s, else of the `aria-labelledby`
   * targets that are rendered. For a submit, reset or button input: its `value` (the default
   * `Submit` / `Reset` when it has none). For anything else: its own visible text, else its labels',
   * else its rendered `aria-labelledby` targets'. Visible text is `labelInName.visibleText`'s:
   * `aria-hidden` text counts, text under `hidden` does not, and `alt`, `title`, `aria-label` and
   * `placeholder` are never visible label text. White space collapsed, case kept. `""` when nothing
   * is visible, or when the element itself is not rendered.
   */
  visibleLabelText: string;
  /**
   * The language in force on the element: the `lang` of the element or its nearest ancestor that has
   * one, trimmed, in the author's case. `""` is a language declared unknown (and is inherited);
   * null means no `lang` on the element or any ancestor in its document.
   */
  lang: string | null;
  /** the id of the element whose `lang` that is; null when `lang` is null */
  langFrom: number | null;
  /**
   * Every author declaration of the `animation` and `text-decoration` families that matches the
   * element at rest, lowest precedence first: normal declarations before `!important` ones, an
   * inline style after the stylesheets within each, then specificity, then source order. Conditions
   * are reported, not evaluated: a declaration under `@media` or from a sheet with a `media`
   * attribute is listed with it. A selector that needs a user action (`:hover`, `:focus` …) or
   * styles a pseudo-element is not listed; no user-agent default is listed.
   */
  css: ElementCssObs;
  /**
   * Every event handler content attribute on the element (schema 0.3), in source order: an `on*`
   * attribute HTML defines for every element (`GlobalEventHandlers`, with what the Pointer Events,
   * Touch Events, CSS Animations, CSS Transitions and Selection API specifications add) or, on
   * `<body>` and `<frameset>`, for the window. An `on*` attribute no specification defines is not
   * listed. Each with its event type and `handlerFamily`. A handler a script attaches is not in the markup.
   */
  inlineHandlers: InlineHandlerObs[];
  /**
   * The framework handler attributes on the element (schema 0.3), in source order, as the caller's
   * table (`HtmlIndexParams.markupHandlers`) recognises them: only what survives into the built
   * markup (a prerendered or declarative attribute), never a handler a framework compiled away.
   */
  markupHandlers: MarkupHandlerObs[];
}

/** one row per iframe/frame of a document, nested ones included, and whether its document was read. */
export interface FrameObs {
  elementId: number; line: number; frame: string; src: string | null; srcdoc: boolean;
  /** the subject-tree file read for a `src` frame (null for srcdoc, or when nothing was read) */
  file: string | null;
  examined: boolean;
  /** why the frame's document was not examined; null when it was */
  reason: string | null;
}

/** one row per rendered element with a text run of its own; `text` is its subtree's perceivable text. */
export interface TextObs { elementId: number; line: number; text: string }

/** Elements whose own text is not something the page says to a reader: code, the document title, a field's default value. */
const NOT_PROSE = new Set(['script', 'style', 'template', 'title', 'textarea']);

/** The character references a serialized attribute carries (HTML §13.3: `&amp;` and `&quot;` at least). */
const NAMED: Record<string, string> = { amp: '&', quot: '"', apos: "'", lt: '<', gt: '>', nbsp: ' ' };
export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === '#') { const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m; }
    return NAMED[e.toLowerCase()] ?? m;
  });
}

/**
 * A name's white space: ASCII white space collapsed to one space and trimmed (HTML's "strip and
 * collapse ASCII whitespace"). A no-break space is not ASCII white space and is kept (WPT accname
 * `comp_text_node`, `comp_label`).
 */
const tidy = (s: string): string => s.replace(/[\t\n\f\r ]+/g, ' ').replace(/^ | $/g, '');
/** an attribute value as a name reads it: character references decoded, white space tidied */
const attrText = (v: string | undefined): string => tidy(decode(v ?? ''));

/**
 * HTML's text-level (phrasing) elements that render inline by default: name from content joins
 * their text to their neighbours' with no space, as the rendered text does ("one<b>two</b>" is
 * "onetwo"). Every other element is joined with a space either side, as in 0.2.
 */
const INLINE_TAGS = new Set(['a', 'abbr', 'b', 'bdi', 'bdo', 'big', 'cite', 'code', 'data', 'del', 'dfn', 'em', 'font', 'i', 'ins', 'kbd', 'label', 'mark', 'nobr',
  'q', 's', 'samp', 'small', 'span', 'strike', 'strong', 'sub', 'sup', 'time', 'tt', 'u', 'var']);

/** the ARIA range roles (AccName 1.2 §4.3.2 step 2C, "range") */
const RANGE = new Set(['meter', 'progressbar', 'scrollbar', 'slider', 'spinbutton']);

/** How deep frames are followed, and the documents already open on this chain (a page framing itself). */
interface NestCtx { depth: number; chain: string[]; frame: string | null }
const MAX_FRAME_DEPTH = 6;

/**
 * The document an iframe/frame shows, when the subject tree holds it: `srcdoc` first (it
 * wins over `src` in the user agent, and a page the browser built carries its frames' documents
 * there), else a `src` that is a path inside the subject tree. An absolute URL, a scheme, a file
 * the tree does not hold or a frame chain that loops is not examined, with the reason.
 */
function nestedDocument(n: HNode, p: PageIndex, root: string, ctx: NestCtx):
  { page: PageIndex | null; file: string | null; label: string; reason: string | null } {
  const tag = n.tag;
  const raw = (n.attrs.src ?? '').trim();
  // named by its `src` when it has one: a page the browser built carries a `src` frame's document
  // in `srcdoc` (a serialized, hydrated DOM), and the src is what a person can find in the page
  const label = raw ? `${tag}[src="${raw.length > 60 ? `${raw.slice(0, 60)}…` : raw}"]@${n.line}` : `${tag}[srcdoc]@${n.line}`;
  if ('srcdoc' in n.attrs) {
    return { page: parseHtml(decodeEntities(n.attrs.srcdoc), `${p.path}#srcdoc@${n.line}`), file: null, label, reason: null };
  }
  if (!raw || /^about:blank$/i.test(raw)) return { page: null, file: null, label, reason: 'no document: the frame has no src or is about:blank' };
  if (/^[a-z][a-z0-9+.-]*:/i.test(raw) || raw.startsWith('//')) {
    return { page: null, file: null, label, reason: 'an absolute URL: whether it is same-origin, and what it serves, is not in the subject tree' };
  }
  let href = raw.split(/[?#]/)[0];
  try { href = decodeURIComponent(href); } catch { /* keep it as written */ }
  if (href.endsWith('/') || href === '') href += 'index.html';
  const f = normalize(href.startsWith('/') ? join(root, href) : join(root, dirname(p.path), href));
  if (!(isUnder(root, f) && isUnderReal(root, f))) return { page: null, file: null, label, reason: 'the subject tree does not hold this document' };
  const ext = extname(f).toLowerCase();
  if (ext !== '.html' && ext !== '.htm') return { page: null, file: null, label, reason: 'not an HTML document' };
  const rel = f.slice(root.length + 1);
  if (ctx.chain.includes(rel) || rel === p.path) return { page: null, file: rel, label, reason: 'the frame shows a document already open on this frame chain (a loop)' };
  return { page: parseHtml(readFileSync(f, 'utf8'), rel), file: rel, label, reason: null };
}

const POINTER = ['onclick', 'onmousedown', 'onmouseup', 'ondblclick', 'onpointerdown', 'onpointerup'];
const KEY = ['onkeydown', 'onkeyup', 'onkeypress'];

/** What kind of user input an event answers: `pointer`, `key`, `focus`, `input` (a form value or submission), `other`. */
export type HandlerFamily = 'pointer' | 'key' | 'focus' | 'input' | 'other';

/**
 * The event handler content attributes of HTML elements: HTML §8.1.8.2 `GlobalEventHandlers`, with
 * the members the Pointer Events, Touch Events, CSS Animations, CSS Transitions and Selection API
 * specifications add to it. `WINDOW_HANDLERS` (§8.1.8.2 `WindowEventHandlers`) are handlers on
 * `<body>` and `<frameset>` only.
 */
const GLOBAL_HANDLERS = ['abort', 'animationcancel', 'animationend', 'animationiteration', 'animationstart', 'auxclick', 'beforeinput', 'beforematch', 'beforetoggle',
  'blur', 'cancel', 'canplay', 'canplaythrough', 'change', 'click', 'close', 'command', 'contextlost', 'contextmenu', 'contextrestored', 'copy', 'cuechange', 'cut',
  'dblclick', 'drag', 'dragend', 'dragenter', 'dragleave', 'dragover', 'dragstart', 'drop', 'durationchange', 'emptied', 'ended', 'error', 'focus', 'formdata',
  'gotpointercapture', 'input', 'invalid', 'keydown', 'keypress', 'keyup', 'load', 'loadeddata', 'loadedmetadata', 'loadstart', 'lostpointercapture',
  'mousedown', 'mouseenter', 'mouseleave', 'mousemove', 'mouseout', 'mouseover', 'mouseup', 'paste', 'pause', 'play', 'playing',
  'pointercancel', 'pointerdown', 'pointerenter', 'pointerleave', 'pointermove', 'pointerout', 'pointerover', 'pointerrawupdate', 'pointerup',
  'progress', 'ratechange', 'reset', 'resize', 'scroll', 'scrollend', 'securitypolicyviolation', 'seeked', 'seeking', 'select', 'selectionchange', 'selectstart',
  'slotchange', 'stalled', 'submit', 'suspend', 'timeupdate', 'toggle', 'touchcancel', 'touchend', 'touchmove', 'touchstart',
  'transitioncancel', 'transitionend', 'transitionrun', 'transitionstart', 'volumechange', 'waiting',
  'webkitanimationend', 'webkitanimationiteration', 'webkitanimationstart', 'webkittransitionend', 'wheel'];
const WINDOW_HANDLERS = ['afterprint', 'beforeprint', 'beforeunload', 'hashchange', 'languagechange', 'message', 'messageerror', 'offline', 'online',
  'pagehide', 'pagereveal', 'pageshow', 'pageswap', 'popstate', 'rejectionhandled', 'storage', 'unhandledrejection', 'unload'];
const GLOBAL_SET = new Set(GLOBAL_HANDLERS);
const WINDOW_SET = new Set(WINDOW_HANDLERS);
/** the event type a handler attribute listens for, where it is not the attribute name less `on` (HTML §8.1.8.2) */
const EVENT_TYPE: Record<string, string> = { webkitanimationend: 'webkitAnimationEnd', webkitanimationiteration: 'webkitAnimationIteration', webkitanimationstart: 'webkitAnimationStart', webkittransitionend: 'webkitTransitionEnd' };

const FAMILY_OF_EVENT: Record<string, HandlerFamily> = {};
for (const e of ['click', 'auxclick', 'dblclick', 'contextmenu', 'wheel', 'drag', 'dragend', 'dragenter', 'dragleave', 'dragover', 'dragstart', 'drop', 'gotpointercapture', 'lostpointercapture']) FAMILY_OF_EVENT[e] = 'pointer';
for (const e of ['keydown', 'keyup', 'keypress']) FAMILY_OF_EVENT[e] = 'key';
for (const e of ['focus', 'blur', 'focusin', 'focusout']) FAMILY_OF_EVENT[e] = 'focus';
for (const e of ['input', 'beforeinput', 'change', 'invalid', 'submit', 'reset', 'formdata', 'select']) FAMILY_OF_EVENT[e] = 'input';
/**
 * The family of an event type: a click, a mouse, pointer, touch, wheel or drag event is `pointer`;
 * a key event `key`; focus and blur `focus`; a form value or submission event `input`; anything else
 * `other`. An unknown or null event is `other`.
 */
export function handlerFamily(event: string | null): HandlerFamily {
  if (event === null) return 'other';
  const e = event.toLowerCase();
  return FAMILY_OF_EVENT[e] ?? (/^(mouse|pointer|touch)/.test(e) ? 'pointer' : 'other');
}

/** One event handler content attribute on an element. */
export interface InlineHandlerObs { attr: string; event: string; handlerFamily: HandlerFamily }

/** the element's event handler content attributes, in source order */
function inlineHandlersOf(n: HNode): InlineHandlerObs[] {
  const out: InlineHandlerObs[] = [];
  const windowTarget = n.tag === 'body' || n.tag === 'frameset';
  for (const attr of Object.keys(n.attrs)) {
    if (!attr.startsWith('on')) continue;
    const name = attr.slice(2);
    if (!GLOBAL_SET.has(name) && !(windowTarget && WINDOW_SET.has(name))) continue;
    const event = EVENT_TYPE[name] ?? name;
    out.push({ attr, event, handlerFamily: handlerFamily(event) });
  }
  return out;
}

/**
 * One row of the framework handler table a caller passes (`HtmlIndexParams.markupHandlers`). The
 * engine knows no framework: what a framework's handler markup looks like is this data.
 *  - `attr`: a regular expression (source text) the whole attribute name must match, case-insensitive
 *    (attribute names are read lower case);
 *  - `event`: where the event type comes from — `{ group: n }` the n-th capture group of `attr`;
 *    `{ value: re, group?: n }` every match of `re` in the attribute's value, capture group `n`
 *    (default 1), one row each; `{ fixed: type }` the type itself. Omitted: the event is not in the
 *    markup (null).
 */
export interface MarkupHandlerRule {
  framework: string;
  attr: string;
  event?: { group: number } | { value: string; group?: number } | { fixed: string };
}

/** One framework handler in the markup, as a `MarkupHandlerRule` recognised it. */
export interface MarkupHandlerObs { attr: string; framework: string; event: string | null; handlerFamily: HandlerFamily }

interface CompiledMarkupRule { rule: MarkupHandlerRule; attr: RegExp; value: RegExp | null }

/** the table's patterns, compiled once; a pattern that does not compile is refused with its row */
export function compileMarkupHandlers(rules: MarkupHandlerRule[]): CompiledMarkupRule[] {
  return rules.map((rule, i) => {
    const re = (src: string, flags: string): RegExp => {
      try { return new RegExp(src, flags); } catch (e) { throw new Error(`html-index: markupHandlers[${i}] (${rule.framework}): ${(e as Error).message}`, { cause: e }); }
    };
    const value = rule.event && 'value' in rule.event ? re(rule.event.value, 'g') : null;
    return { rule, attr: re(`^(?:${rule.attr})$`, 'i'), value };
  });
}

/** the element's framework handler attributes, in source order; an attribute is recognised by the first row that matches it */
function markupHandlersOf(n: HNode, table: CompiledMarkupRule[]): MarkupHandlerObs[] {
  const out: MarkupHandlerObs[] = [];
  if (!table.length) return out;
  for (const [attr, raw] of Object.entries(n.attrs)) {
    for (const { rule, attr: re, value } of table) {
      const m = re.exec(attr);
      if (!m) continue;
      const row = (event: string | null) => out.push({ attr, framework: rule.framework, event, handlerFamily: handlerFamily(event) });
      const ev = rule.event;
      if (!ev) row(null);
      else if ('fixed' in ev) row(ev.fixed);
      else if ('group' in ev && !('value' in ev)) row(m[ev.group] ?? null);
      else {
        const events = [...decodeEntities(raw).matchAll(value!)].map((x) => x[(ev as { group?: number }).group ?? 1]).filter((x): x is string => !!x);
        if (events.length) for (const e of events) row(e); else row(null);
      }
      break;
    }
  }
  return out;
}
const PRESENTATIONAL = new Set(['none', 'presentation']);

/** a declarative shadow root: its contents are the host's shadow tree, rendered (unlike a plain `<template>`'s) */
const isShadowTemplate = (n: HNode): boolean => n.tag === 'template' && 'shadowrootmode' in n.attrs;

export interface PageObservation {
  path: string; malformed: boolean; lang: string | null; title: string | null;
  viewport: ReturnType<typeof parseViewport>;
  elements: ElementObs[];
  idrefs: { elementId: number; attr: string; token: string; resolves: boolean; targetDuplicated: boolean; targetTag: string | null; sameTable: boolean; selfReference: boolean; tableRole: string | null }[];
  media: { elementId: number; tag: string; line: number; tracks: { kind: string; srclang: string | null }[]; autoplay: boolean; muted: boolean; controls: boolean }[];
  langAttributes: { elementId: number; line: number; value: string; governsText: boolean }[];
  cssRules: CssRuleObs[];
  frames: FrameObs[];
  /**
   * What the page SAYS, block by block: one row per rendered element that holds text of its
   * own (a text run directly inside it), with the perceivable text of its subtree as `hasText`
   * reads it. A collection of its own, so no `elements` row changes.
   */
  texts: TextObs[];
  /** what set `malformed` in this document (a nested frame document's are not listed); empty exactly when `malformed` is false */
  parseErrors: ParseError[];
  /**
   * One edge per IDREF token (the same rows, in the same order, as `idrefs`), with both ends: `to` is
   * the first element holding the id, as `idrefs` resolves it; `targets` how many elements hold it.
   */
  idrefEdges: { from: number; fromLine: number; attr: string; token: string; to: number | null; toLine: number | null; dangling: boolean; duplicate: boolean; targets: number; selfReference: boolean }[];
  /** every id held by two or more elements of one document, in the order the id first appears */
  duplicateIds: { id: string; count: number; elementIds: number[]; lines: number[] }[];
  /**
   * Every stylesheet the documents load, in the order `cssRules` reads them: its `rules` flattened
   * in order are `cssRules`. A linked sheet the root does not hold is listed, with no rules.
   */
  stylesheets: StylesheetObs[];
}

export function pageObservation(p: PageIndex, root: string, html: HtmlAriaViews, aria: AriaViews, params: HtmlIndexParams = {}, nest: NestCtx = { depth: 0, chain: [], frame: null }): PageObservation {
  const idOf = new Map<HNode, number>(p.nodes.map((n, i) => [n, i]));
  const markupTable = compileMarkupHandlers(params.markupHandlers ?? []);
  const byId = new Map<string, HNode[]>();
  for (const n of p.nodes) if (n.attrs.id) byId.set(n.attrs.id, [...(byId.get(n.attrs.id) ?? []), n]);
  const roles = new Set(aria['role-names']);
  const globals = new Set(aria['global-attributes']);
  const nameFromContents = new Set(aria['name-from-contents']);

  // aria-owns re-parents (ARIA 1.2 §6.6.4): owner of an element referenced by aria-owns
  const owner = new Map<HNode, HNode>();
  for (const n of p.nodes) for (const id of (n.attrs['aria-owns'] ?? '').trim().split(/\s+/).filter(Boolean)) for (const t of byId.get(id) ?? []) if (!owner.has(t)) owner.set(t, n);
  const parentOf = (n: HNode): HNode | null => owner.get(n) ?? n.parent;

  const rowOf = new Map<HNode, string | null>();
  const tokensOf = new Map<HNode, string[]>();
  const explicitOf = new Map<HNode, string | null>();
  const roleOf = new Map<HNode, string | null>();
  for (const n of p.nodes) {
    const row = hostRow(n, html);
    rowOf.set(n, row);
    const implicit = row ? html['implicit-role-by-row'][row] ?? null : html['implicit-role-by-tag-default'][n.tag] ?? null;
    const tokens = (n.attrs.role ?? '').trim().toLowerCase().split(/\s+/).filter(Boolean);
    tokensOf.set(n, tokens);
    const explicit = tokens.find((t) => roles.has(t)) ?? null; // the first token the UA recognises
    explicitOf.set(n, explicit);
    let effective = explicit ?? implicit;
    // presentational role conflict: ignored on a focusable element or one with a global ARIA attribute
    if (explicit && PRESENTATIONAL.has(explicit) && (focusable(n) || Object.keys(n.attrs).some((k) => globals.has(k)))) effective = implicit;
    roleOf.set(n, effective);
  }

  // the page's own rules, and how many sheets it links that the subject tree does not hold. Read
  // before any name: whether a child is joined to its neighbours with a space is its `display`.
  const sheetsRead = readSheets(p, root, idOf, nest.frame);
  const pageRules = sheetsRead.rules.map((r) => r.obs);
  // the rules that declare a property read here, with their selectors parsed once; a keyframe step styles no element
  const tree = matchTree(p.root.children);
  const LAYOUT = new Set(['display', 'position', 'float']);
  const read = (prop: string): boolean => familyOf(prop) !== null || LAYOUT.has(prop);
  const styleRules = sheetsRead.rules.map((r, order) => ({ r, order }))
    .filter(({ r }) => !r.inKeyframes && r.decls.some((d) => read(d.prop)))
    .map(({ r, order }) => ({ r, order, sel: parseSelector(r.obs.selector) }));
  /** the author declarations of the properties `want` admits that match `n` at rest, lowest precedence first */
  function declarationsOn(n: HNode, want: (prop: string) => boolean): CssDeclarationObs[] {
    const host = shadowHostOf(n);
    const hostId = host ? idOf.get(host) ?? null : null;
    const hits: { d: CssDeclarationObs; important: number; inline: number; spec: Specificity; order: number; i: number }[] = [];
    for (const { r, order, sel } of styleRules) {
      if (!sel || r.obs.shadowHost !== hostId) continue;   // a rule styles its own document or shadow tree only
      if (!r.decls.some((d) => want(d.prop))) continue;
      const spec = matchSpecificity(n, sel, tree);
      if (!spec) continue;
      r.decls.forEach((d, i) => {
        if (!want(d.prop)) return;
        hits.push({ d: { property: d.prop, value: d.value, important: d.important, media: r.obs.media, sheetMedia: r.sheetMedia, inline: false, source: { file: r.obs.file, line: r.obs.line, selector: r.obs.selector } }, important: d.important ? 1 : 0, inline: 0, spec, order, i });
      });
    }
    inlineDeclarations(n.attrs.style ?? '').forEach((d, i) => {
      if (!want(d.prop)) return;
      hits.push({ d: { property: d.prop, value: d.value, important: d.important, media: '', sheetMedia: '', inline: true, source: { file: p.path, line: n.line, selector: null } }, important: d.important ? 1 : 0, inline: 1, spec: [0, 0, 0], order: 0, i });
    });
    hits.sort((a, b) => a.important - b.important || a.inline - b.inline || compareSpecificity(a.spec, b.spec) || a.order - b.order || a.i - b.i);
    return hits.map((h) => h.d);
  }
  const ownCss = new Map<HNode, ElementCssObs>();
  function ownElementCss(n: HNode): ElementCssObs {
    let out = ownCss.get(n);
    if (!out) {
      out = { animation: [], textDecoration: [], cursor: [] };
      for (const d of declarationsOn(n, (prop) => familyOf(prop) !== null)) {
        const f = familyOf(d.property)!;
        if (f === 'cursor') out.cursor.push({ ...d, inherited: false, from: idOf.get(n)! });
        else out[f].push(d);
      }
      ownCss.set(n, out);
    }
    return out;
  }
  /**
   * `css` as observed: the element's own declarations; and for `cursor`, an inherited property,
   * when the element declares none, those of the nearest ancestor that does, marked `inherited`.
   */
  function elementCss(n: HNode): ElementCssObs {
    const own = ownElementCss(n);
    if (own.cursor.length) return own;
    for (let a = n.parent; a; a = a.parent) {
      const up = ownElementCss(a).cursor;
      if (up.length) return { ...own, cursor: up.map((d) => ({ ...d, inherited: true })) };
    }
    return own;
  }
  /**
   * The `display`, `position` and `float` the author gives the element at rest: for each, the
   * declaration of highest precedence with no condition (`@media`, a sheet's `media`), lower case.
   */
  const layouts = new Map<HNode, Record<string, string>>();
  function authorLayout(n: HNode): Record<string, string> {
    let l = layouts.get(n);
    if (!l) {
      l = {};
      for (const d of declarationsOn(n, (prop) => LAYOUT.has(prop))) if (!d.media && !d.sheetMedia) l[d.property] = d.value.trim().toLowerCase();
      layouts.set(n, l);
    }
    return l;
  }
  /**
   * The element sits inline in its parent's text: not floated or absolutely positioned (either
   * makes it a block, CSS 2.1 §9.7), and an inline `display` when the author sets one, else an
   * inline-by-default tag.
   */
  const joinsInline = (n: HNode): boolean => {
    const l = authorLayout(n);
    if (l.position === 'absolute' || l.position === 'fixed' || (l.float !== undefined && l.float !== 'none')) return false;
    return l.display === undefined ? INLINE_TAGS.has(n.tag) : l.display === 'inline' || l.display === 'contents';
  };

  // label association: <label for> and wrapping <label>, labelable elements only (HTML §4.10.4).
  // The label's text leaves out the control it labels: a control is embedded in the label of
  // ANOTHER widget only (AccName 1.2 step 2C), so a text field does not name itself by its value.
  const labelText = new Map<HNode, string>();
  for (const l of p.nodes.filter((n) => n.tag === 'label')) {
    const f = (l.attrs.for ?? '').trim();
    let target: HNode | undefined;
    if (f) { const t = byId.get(f)?.[0]; if (t && LABELABLE.has(t.tag)) target = t; }
    else {
      const stack = [...l.children];
      while (stack.length) {
        const c = stack.shift()!;
        if (LABELABLE.has(c.tag) && !(c.tag === 'input' && (c.attrs.type ?? '').toLowerCase() === 'hidden')) { target = c; break; }
        stack.push(...c.children);
      }
    }
    if (!target || labelText.has(target)) continue;
    const text = contentName(l, new Set([target]));
    if (text) labelText.set(target, text);
  }

  /**
   * The text alternative a subtree contributes to a name (AccName 1.2 steps 2C–2G): text runs with
   * their character references decoded, each child's own text alternative, and the value of each
   * control embedded in it. Text-level children join their neighbours with no space (`joinsInline`);
   * any other child, a `<br>` and white space between tags are a word boundary. Hidden content is
   * skipped as in `nameFromContent`.
   */
  function contentName(n: HNode, seen: Set<HNode>, includeHidden = false): string {
    return tidy(contentFlow(n, seen, includeHidden));
  }
  function contentFlow(n: HNode, seen: Set<HNode>, includeHidden: boolean): string {
    if (seen.has(n)) return '';
    seen.add(n);
    const runs = n.runs ?? (n.text ? [{ at: 0, text: n.text }] : []);
    const gaps = new Set(n.gaps ?? []);
    let s = '', r = 0;
    const before = (i: number) => { if (gaps.has(i)) s += ' '; while (r < runs.length && runs[r].at <= i) s += decode(runs[r++].text); };
    n.children.forEach((c, i) => {
      before(i);
      if (c.tag === 'br') { s += ' '; return; }
      const part = childAlternative(c, seen, includeHidden);
      s += joinsInline(c) ? part : ` ${part} `;
    });
    before(n.children.length);
    return s;
  }
  function childAlternative(c: HNode, seen: Set<HNode>, includeHidden: boolean): string {
    if (seen.has(c) || c.tag === 'script' || c.tag === 'style' || (c.tag === 'template' && !isShadowTemplate(c))) return '';
    if (!includeHidden && hidesItself(c)) return '';
    const ev = embeddedValue(c, seen);
    if (ev !== null) return ev;
    const al = attrText(c.attrs['aria-label']);
    if (al) return al;
    if (c.tag === 'img' || c.tag === 'area') return accName(c, roleOf.get(c) ?? null).name;
    if (c.tag === 'input' && ['button', 'submit', 'reset'].includes((c.attrs.type ?? '').toLowerCase())) return attrText(c.attrs.value);
    if (c.tag === 'svg') { const t = c.children.find((x) => x.tag === 'title'); return t ? tidy(decode(t.text)) : ''; }
    return contentFlow(c, seen, includeHidden);
  }

  /** a `<select>`'s chosen options (HTML §4.10.7 selectedness): those marked `selected`, else the first option of a drop-down */
  function optionText(o: HNode): string { return attrText(o.attrs.label) || contentName(o, new Set(), true); }
  function chosenOptions(sel: HNode): HNode[] {
    const options: HNode[] = [];
    const walk = (x: HNode) => { for (const c of x.children) { if (c.tag === 'option') options.push(c); else if (c.tag === 'optgroup') walk(c); } };
    walk(sel);
    const marked = options.filter((o) => 'selected' in o.attrs);
    const multiple = 'multiple' in sel.attrs;
    const dropDown = !multiple && !(Number(sel.attrs.size) > 1);
    if (marked.length) return multiple ? marked : [marked[marked.length - 1]];
    return dropDown && options.length ? [options[0]] : [];
  }
  /** the `aria-selected` options inside an ARIA listbox or combobox */
  function ariaChosen(x: HNode): HNode[] {
    const out: HNode[] = [];
    const walk = (y: HNode) => { for (const c of y.children) { if (roleOf.get(c) === 'option' && (c.attrs['aria-selected'] ?? '').toLowerCase() === 'true') out.push(c); else walk(c); } };
    walk(x);
    return out;
  }
  /**
   * AccName 1.2 step 2C: what a control embedded in the label of another widget contributes — a
   * text box its value, a combo box or list box its chosen option(s), a range its `aria-valuetext`,
   * else `aria-valuenow`, else its native value; and a menu nothing (WPT accname, embedded menu).
   * An ARIA combo box with no chosen option contributes its text. null when `c` is not such a
   * control, or is a text box whose value is its content (a `textarea`, an ARIA `textbox`).
   */
  function embeddedValue(c: HNode, seen: Set<HNode>): string | null {
    const role = roleOf.get(c) ?? null;
    const a = c.attrs;
    if (role === 'textbox' || role === 'searchbox') return c.tag === 'input' ? attrText(a.value) : null;
    if (role === 'combobox' || role === 'listbox') {
      if (c.tag === 'select') return chosenOptions(c).map(optionText).join(' ');
      if (c.tag === 'input') return attrText(a.value);
      const chosen = ariaChosen(c);
      if (chosen.length) return chosen.map((o) => contentName(o, new Set(seen))).join(' ');
      return role === 'listbox' ? '' : contentName(c, seen);   // an ARIA combo box's value is its text
    }
    if (role && RANGE.has(role)) {
      const vt = attrText(a['aria-valuetext']);
      if (vt) return vt;
      const vn = attrText(a['aria-valuenow']);
      if (vn) return vn;
      if (c.tag === 'input' && (a.type ?? '').toLowerCase() === 'range' && !('value' in a)) {
        // the default value of a range control: the midpoint of min and max (HTML §4.10.5.1.13)
        const min = Number.parseFloat(a.min ?? ''), max = Number.parseFloat(a.max ?? '');
        const lo = Number.isFinite(min) ? min : 0, hi = Number.isFinite(max) ? max : 100;
        return String(hi < lo ? lo : lo + (hi - lo) / 2);
      }
      return ['input', 'progress', 'meter'].includes(c.tag) ? attrText(a.value) : '';
    }
    if (role === 'menu') return '';
    return null;
  }

  /**
   * Text of a subtree as 0.2 read it, kept for `hasText` and `texts` (which are not names): text,
   * and each child's own text alternative.
   */
  // Hidden content is skipped node by node as the traversal descends: what hides a node is its OWN
  // attributes, because an ancestor inside the subtree was already skipped on the way down and one
  // above it is not the traversal's business. That matters for aria-labelledby, whose referenced
  // node may sit in a hidden region or a closed dialog and still names (AccName 1.2 step 2B).
  // `includeHidden`: the referenced node is itself hidden, so its hidden content counts too (2A).
  function nameFromContent(n: HNode, seen: Set<HNode>, includeHidden = false): string {
    if (seen.has(n)) return '';
    seen.add(n);
    // in document order: a text run goes before the child it preceded in the source
    return inOrder(n, (c) => {
      if (c.tag === 'script' || c.tag === 'style' || (c.tag === 'template' && !isShadowTemplate(c))) return '';
      if (!includeHidden && hidesItself(c)) return '';
      const al = (c.attrs['aria-label'] ?? '').trim();
      if (al) return al;
      if (c.tag === 'img' || c.tag === 'area') return accName(c, roleOf.get(c) ?? null).name;
      if (c.tag === 'input' && ['button', 'submit', 'reset'].includes((c.attrs.type ?? '').toLowerCase())) return (c.attrs.value ?? '').trim();
      if (c.tag === 'svg') { const t = c.children.find((x) => x.tag === 'title'); return t ? t.text : ''; }
      return nameFromContent(c, seen, includeHidden);
    }).replace(/\s+/g, ' ').trim();
  }

  /**
   * The text of the elements an `aria-labelledby` of `self` names (AccName 1.2 step 2B): each one's
   * embedded-control value (unless it is `self`), else its `aria-label`, else its `<label>`, else its content.
   */
  const refText = (ids: string, self: HNode | null = null): { text: string; visible: boolean } => {
    const parts = ids.trim().split(/\s+/).map((x) => byId.get(x)?.[0]).filter((x): x is HNode => !!x);
    const one = (x: HNode): string => (x !== self ? embeddedValue(x, new Set()) : null) || attrText(x.attrs['aria-label']) || labelText.get(x) || contentName(x, new Set(), hiddenNode(x));
    return { text: tidy(parts.map(one).join(' ')), visible: parts.some((x) => !hiddenNode(x)) };
  };

  /** AccName 1.2 step order with HTML-AAM sources. */
  function accName(n: HNode, role: string | null): { name: string; source: string | null } {
    const lb = (n.attrs['aria-labelledby'] ?? '').trim();
    if (lb) { const r = refText(lb, n); if (r.text) return { name: r.text, source: 'aria-labelledby' }; }
    const al = attrText(n.attrs['aria-label']);
    if (al) return { name: al, source: 'aria-label' };
    if (labelText.has(n)) return { name: labelText.get(n)!, source: 'label' };
    const type = (n.attrs.type ?? '').toLowerCase();
    if ((n.tag === 'img' || n.tag === 'area' || (n.tag === 'input' && type === 'image')) && 'alt' in n.attrs) {
      if (n.attrs.alt === '') return { name: '', source: 'alt-empty' };   // declared decorative: exactly empty
      const alt = attrText(n.attrs.alt);
      if (alt) return { name: alt, source: 'alt' };
    }
    const value = attrText(n.attrs.value);
    if (n.tag === 'input' && ['button', 'submit', 'reset'].includes(type) && value) return { name: value, source: 'value' };
    if (n.tag === 'input' && (type === 'submit' || type === 'reset')) return { name: type === 'submit' ? 'Submit' : 'Reset', source: 'default' };
    if (n.tag === 'svg') {
      const t = n.children.find((c) => c.tag === 'title');
      const tt = t ? tidy(decode(t.text)) : '';
      if (tt) return { name: tt, source: 'svg-title' };
    } else if (role && nameFromContents.has(role)) {
      const s = contentName(n, new Set());
      if (s) return { name: s, source: 'contents' };
    }
    const title = attrText(n.attrs.title);
    if (title) return { name: title, source: 'title-fallback' };
    const ph = attrText(n.attrs.placeholder);
    if (ph && (n.tag === 'input' || n.tag === 'textarea')) return { name: ph, source: 'placeholder' };
    return { name: '', source: null };
  }

  const owned = (n: HNode): string[] => {
    const found = new Set<string>();
    const stack = [...n.children.filter((c) => !owner.has(c) || owner.get(c) === n)];
    for (const id of (n.attrs['aria-owns'] ?? '').trim().split(/\s+/).filter(Boolean)) for (const t of byId.get(id) ?? []) stack.push(t);
    while (stack.length) {
      const c = stack.pop()!;
      if (hiddenNode(c)) continue;
      const r = roleOf.get(c) ?? null;
      if (r) found.add(r);
      if (!aria['required-owned'][r ?? '']) stack.push(...c.children);
    }
    return [...found].sort();
  };

  /** meaningful: a role that is not generic/none/presentation, or any role with a global ARIA attribute */
  const meaningful = (a: HNode): boolean => {
    const r = roleOf.get(a);
    if (!r) return Object.keys(a.attrs).some((k) => globals.has(k));
    return !(r === 'generic' || PRESENTATIONAL.has(r)) || Object.keys(a.attrs).some((k) => globals.has(k));
  };

  const tableOf = (n: HNode): HNode | null => { for (let a = n.parent; a; a = a.parent) if (a.tag === 'table') return a; return null; };

  // position among the same-tag children of the DOM parent (not the aria-owns owner:
  // `:nth-of-type` is a fact of the tree a person searches)
  const nthOf = new Map<HNode, number | null>();
  const nthOfType = (n: HNode): number | null => {
    if (!nthOf.has(n)) {
      const same = (n.parent ?? p.root).children.filter((c) => c.tag === n.tag);
      nthOf.set(n, same.length > 1 ? same.indexOf(n) + 1 : null);
    }
    return nthOf.get(n)!;
  };

  // every <label> of a labelable element (HTML §4.10.4), in document order, with or without text
  const labelsOf = new Map<HNode, HNode[]>();
  for (const l of p.nodes.filter((n) => n.tag === 'label')) {
    const f = (l.attrs.for ?? '').trim();
    let target: HNode | undefined;
    if (f) { const t = byId.get(f)?.[0]; if (t && LABELABLE.has(t.tag)) target = t; }
    else {
      const stack = [...l.children];
      while (stack.length) {
        const c = stack.shift()!;
        if (LABELABLE.has(c.tag) && !(c.tag === 'input' && (c.attrs.type ?? '').toLowerCase() === 'hidden')) { target = c; break; }
        stack.push(...c.children);
      }
    }
    if (target) labelsOf.set(target, [...(labelsOf.get(target) ?? []), l]);
  }
  /** nothing in the markup keeps the element or an ancestor off the screen (`aria-hidden` does not) */
  const rendered = (x: HNode): boolean => { for (let c: HNode | null = x; c; c = c.parent) if (markupHides(c)) return false; return true; };
  const shown = (x: HNode): string => (rendered(x) && rendersText(x) ? visibleInnerText(x) : '');
  const joined = (xs: HNode[]): string => xs.map(shown).filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
  function visibleLabelText(n: HNode): string {
    if (!rendered(n)) return '';
    const type = (n.attrs.type ?? '').toLowerCase();
    if (n.tag === 'input' && ['submit', 'reset', 'button'].includes(type)) {
      const v = (n.attrs.value ?? '').replace(/\s+/g, ' ').trim();
      return v || (type === 'submit' ? 'Submit' : type === 'reset' ? 'Reset' : '');
    }
    if (!FIELD.has(n.tag)) { const own = shown(n); if (own) return own; }
    const labels = joined(labelsOf.get(n) ?? []);
    if (labels) return labels;
    const lb = (n.attrs['aria-labelledby'] ?? '').trim();
    return lb ? joined(lb.split(/\s+/).map((x) => byId.get(x)?.[0]).filter((x): x is HNode => !!x)) : '';
  }
  /** the nearest `lang` on the element or an ancestor of its document */
  function langOf(n: HNode): { lang: string | null; langFrom: number | null } {
    for (let c: HNode | null = n; c; c = c.parent) if ('lang' in c.attrs) return { lang: c.attrs.lang.trim(), langFrom: idOf.get(c)! };
    return { lang: null, langFrom: null };
  }

  const unreadSheets = p.nodes.filter((n) => n.tag === 'link' && /(^|\s)stylesheet(\s|$)/i.test(n.attrs.rel ?? '') && n.attrs.href && !sheetInTree(p, root, n.attrs.href)).length;
  const elements: ElementObs[] = p.nodes.map((n) => {
    const ancestors: HNode[] = [];
    for (let a = parentOf(n); a && ancestors.length < 200; a = parentOf(a)) ancestors.push(a);
    const role = roleOf.get(n)!;
    const { name, source } = accName(n, role);
    const lb = (n.attrs['aria-labelledby'] ?? '').trim();
    const ti = n.attrs.tabindex;
    const tiN = ti === undefined || ti.trim() === '' ? null : Number(ti);
    const ctx = ancestors.find(meaningful);
    return {
      id: idOf.get(n)!, tag: n.tag, attrs: n.attrs, line: n.line,
      ancestorIds: ancestors.map((a) => idOf.get(a)!), ancestorTags: ancestors.map((a) => a.tag),
      hostRow: rowOf.get(n)!, roleTokens: tokensOf.get(n)!, explicitRole: explicitOf.get(n)!, effectiveRole: role,
      ownedRoles: owned(n), ancestorRoles: ancestors.map((a) => roleOf.get(a)).filter((x): x is string => !!x),
      contextRole: ctx ? roleOf.get(ctx) ?? null : null,
      childElementCount: n.children.length,
      ariaAttrs: Object.keys(n.attrs).filter((k) => k.startsWith('aria-')),
      name, nameSource: source,
      visibleLabel: labelText.has(n) || (!!lb && (() => { const r = refText(lb, n); return !!r.text && r.visible; })()),
      hidden: hiddenNode(n), focusable: focusable(n), inSvg: n.inSvg,
      pointerHandlers: POINTER.filter((h) => h in n.attrs), keyHandlers: KEY.filter((h) => h in n.attrs),
      tabindex: tiN !== null && !Number.isNaN(tiN) ? tiN : null,
      hasText: nameFromContent(n, new Set()) !== '',
      frame: nest.frame,
      inShadow: (() => { for (let a = n.parent; a; a = a.parent) if (isShadowTemplate(a)) return true; return false; })(),
      labelInName: ('aria-label' in n.attrs || 'aria-labelledby' in n.attrs) && !n.inSvg ? labelInName(n, name, pageRules, unreadSheets) : null,
      nthOfType: nthOfType(n), ancestorNthOfType: ancestors.map(nthOfType),
      visibleLabelText: visibleLabelText(n),
      ...langOf(n),
      css: elementCss(n),
      inlineHandlers: inlineHandlersOf(n),
      markupHandlers: markupHandlersOf(n, markupTable),
    };
  });

  const IDREF = params.idrefAttributes ?? [];
  const SINGLE = new Set(['aria-activedescendant', 'for', 'form', 'list']);
  const idrefs: PageObservation['idrefs'] = [];
  const idrefEdges: PageObservation['idrefEdges'] = [];
  for (const n of p.nodes) {
    for (const k of IDREF) {
      const raw = n.attrs[k];
      if (raw === undefined || raw.trim() === '') continue;
      if (k === 'for' && n.tag !== 'label' && n.tag !== 'output') continue;
      for (const token of SINGLE.has(k) ? [raw.trim()] : raw.trim().split(/\s+/)) {
        const t = byId.get(token) ?? [];
        const tbl = tableOf(n);
        idrefs.push({
          elementId: idOf.get(n)!, attr: k, token, resolves: t.length > 0, targetDuplicated: t.length > 1,
          targetTag: t[0]?.tag ?? null, sameTable: !!t[0] && tbl !== null && tableOf(t[0]) === tbl, selfReference: t[0] === n,
          tableRole: tbl ? roleOf.get(tbl) ?? null : null,
        });
        idrefEdges.push({
          from: idOf.get(n)!, fromLine: n.line, attr: k, token, to: t[0] ? idOf.get(t[0])! : null, toLine: t[0]?.line ?? null,
          dangling: t.length === 0, duplicate: t.length > 1, targets: t.length, selfReference: t[0] === n,
        });
      }
    }
  }

  const media: PageObservation['media'] = p.nodes.filter((n) => n.tag === 'video' || n.tag === 'audio').map((n) => ({
    elementId: idOf.get(n)!, tag: n.tag, line: n.line,
    tracks: n.children.filter((c) => c.tag === 'track').map((t) => ({ kind: (t.attrs.kind ?? 'subtitles').toLowerCase(), srclang: t.attrs.srclang ?? null })),
    autoplay: 'autoplay' in n.attrs, muted: 'muted' in n.attrs, controls: 'controls' in n.attrs,
  }));

  /** an element with lang governs text: its subtree has visible text not under a nested lang */
  const notRendered = (x: HNode): boolean => { for (let c: HNode | null = x; c; c = c.parent) { if ('hidden' in c.attrs || /display\s*:\s*none/i.test(c.attrs.style ?? '')) return true; } return false; };
  const governsText = (n: HNode): boolean => {
    if (notRendered(n)) return false;
    const walk = (x: HNode): boolean => {
      if (x.text.trim()) return true;
      if ((x.tag === 'img' || x.tag === 'area') && (x.attrs.alt ?? '').trim()) return true;
      return x.children.some((c) => !('lang' in c.attrs) && c.tag !== 'script' && c.tag !== 'style' && !notRendered(c) && walk(c));
    };
    return walk(n);
  };

  // the text a reader meets, by the element that holds it. Only an element with a text run
  // of its own gets a row, so a wrapper is not a second copy of its children; the row's text is
  // the element's whole subtree (an inline child's text belongs to the sentence it sits in), read
  // as name from content reads it: document order, hidden children skipped, whitespace collapsed.
  const texts: TextObs[] = [];
  for (const n of p.nodes) {
    if (!n.text.trim() || (NOT_PROSE.has(n.tag) && !isShadowTemplate(n)) || hiddenNode(n)) continue;
    let inRaw = false;
    for (let a = n.parent; a; a = a.parent) if (NOT_PROSE.has(a.tag) && !isShadowTemplate(a)) { inRaw = true; break; }
    if (inRaw) continue;
    const text = nameFromContent(n, new Set());
    if (text) texts.push({ elementId: idOf.get(n)!, line: n.line, text });
  }

  const langAttributes = p.nodes.filter((n) => n.tag !== 'html' && 'lang' in n.attrs).map((n) => ({ elementId: idOf.get(n)!, line: n.line, value: n.attrs.lang, governsText: governsText(n) }));

  // the documents this one nests. A page is what the user meets, and the
  // user meets a frame's content as part of the page. Each nested document is observed on its own
  // (its ids, labels and IDREFs resolve inside it, as the user agent resolves them) and its rows are
  // APPENDED after this document's, ids offset, every row carrying `frame` — so the page's own ids
  // are unchanged and a nested element is named by the frame it sits in. Its `lang`, `title` and
  // `viewport` are its own. its stylesheets are appended to `cssRules` the same way,
  // each rule carrying the `frame` it belongs to (and `shadowHost`, offset like every element id),
  // so a rule of a frame's sheet is never read as a rule of the page that frames it.
  // this document's own rules were read above (pageRules, for `labelInName`'s style risks); nested sheets are appended to a copy
  const cssRules = [...pageRules];
  const stylesheets = [...sheetsRead.sheets];
  const duplicateIds: PageObservation['duplicateIds'] = [...byId].filter(([, l]) => l.length > 1).map(([id, l]) => ({ id, count: l.length, elementIds: l.map((x) => idOf.get(x)!), lines: l.map((x) => x.line) }));
  const frames: FrameObs[] = [];
  for (const n of p.nodes) {
    if (n.tag !== 'iframe' && n.tag !== 'frame') continue;
    const d = nest.depth < MAX_FRAME_DEPTH ? nestedDocument(n, p, root, nest) : { page: null, file: null, label: `${n.tag}@${n.line}`, reason: `nested more than ${MAX_FRAME_DEPTH} frames deep` };
    const frame = nest.frame ? `${nest.frame} >>> ${d.label}` : d.label;
    frames.push({ elementId: idOf.get(n)!, line: n.line, frame, src: n.attrs.src ?? null, srcdoc: 'srcdoc' in n.attrs, file: d.file, examined: d.page !== null, reason: d.reason });
    if (!d.page) continue;
    const inner = pageObservation(d.page, root, html, aria, params, { depth: nest.depth + 1, chain: [...nest.chain, p.path], frame });
    const off = elements.length;
    const frameHidden = hiddenNode(n);
    for (const e of inner.elements) elements.push({ ...e, id: e.id + off, ancestorIds: e.ancestorIds.map((x) => x + off), hidden: e.hidden || frameHidden, langFrom: e.langFrom === null ? null : e.langFrom + off, css: { ...e.css, cursor: e.css.cursor.map((d) => ({ ...d, from: d.from + off })) } });
    for (const r of inner.idrefs) idrefs.push({ ...r, elementId: r.elementId + off });
    for (const r of inner.idrefEdges) idrefEdges.push({ ...r, from: r.from + off, to: r.to === null ? null : r.to + off });
    for (const d of inner.duplicateIds) duplicateIds.push({ ...d, elementIds: d.elementIds.map((x) => x + off) });
    for (const m of inner.media) media.push({ ...m, elementId: m.elementId + off });
    for (const l of inner.langAttributes) langAttributes.push({ ...l, elementId: l.elementId + off });
    for (const f of inner.frames) frames.push({ ...f, elementId: f.elementId + off });
    if (!frameHidden) for (const t of inner.texts) texts.push({ ...t, elementId: t.elementId + off });
    // the same row objects in both views, so `stylesheets[].rules` flattened stays `cssRules`
    const moved = new Map(inner.cssRules.map((r) => [r, { ...r, shadowHost: r.shadowHost === null ? null : r.shadowHost + off }]));
    for (const r of inner.cssRules) cssRules.push(moved.get(r)!);
    for (const sh of inner.stylesheets) stylesheets.push({ ...sh, shadowHost: sh.shadowHost === null ? null : sh.shadowHost + off, rules: sh.rules.map((r) => moved.get(r)!) });
  }

  const htmlEl = p.nodes.find((n) => n.tag === 'html');
  const vp = p.nodes.find((n) => n.tag === 'meta' && (n.attrs.name ?? '').toLowerCase() === 'viewport');
  const titleEl = p.nodes.find((n) => n.tag === 'title');
  return {
    path: p.path,
    malformed: p.malformed,
    lang: (htmlEl?.attrs.lang ?? '').trim() || null,
    title: titleEl ? titleEl.text.trim() || null : null,
    viewport: parseViewport(vp ? vp.attrs.content ?? '' : null),
    elements,
    idrefs,
    media,
    langAttributes,
    cssRules,
    frames,
    texts,
    parseErrors: p.parseErrors,
    idrefEdges,
    duplicateIds,
    stylesheets,
  };
}
