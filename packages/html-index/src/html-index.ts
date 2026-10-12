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
import { inOrder, parseHtml, type HNode, type PageIndex } from './parse.js';
import { isUnder, isUnderReal } from './path.js';
import { labelInName, type LabelInName } from './label-in-name.js';
import { couldMatchCount, selectorIndex } from './selector.js';

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

function cssRulesOf(p: PageIndex, root: string, idOf: Map<HNode, number>, frame: string | null): CssRuleObs[] {
  const out: CssRuleObs[] = [];
  const index = selectorIndex(p.nodes);
  const sheets: { file: string; text: string; shadowHost: number | null }[] = [];
  for (const n of p.nodes) {
    const host = shadowHostOf(n);
    const shadowHost = host ? idOf.get(host) ?? null : null;
    if (n.tag === 'link' && /(^|\s)stylesheet(\s|$)/i.test(n.attrs.rel ?? '') && n.attrs.href && !/^[a-z]+:\/\//i.test(n.attrs.href)) {
      const href = n.attrs.href.split(/[?#]/)[0];
      const f = normalize(href.startsWith('/') ? join(root, href) : join(root, dirname(p.path), href));
      // inside the root lexically and after following symlinks; isUnderReal is false for a missing file
      if (isUnder(root, f) && isUnderReal(root, f)) sheets.push({ file: f.slice(root.length + 1), text: readFileSync(f, 'utf8'), shadowHost });
    }
    if (n.tag === 'style') sheets.push({ file: `${p.path}#style@${n.line}`, text: n.text, shadowHost });
  }
  for (const s of sheets) {
    let ast: postcss.Root;
    try { ast = postcss.parse(s.text); } catch { continue; }
    ast.walkRules((r) => {
      const media: string[] = [];
      for (let a: postcss.Node | undefined = r.parent as postcss.Node | undefined; a && a.type !== 'root'; a = a.parent as postcss.Node | undefined) {
        if (a.type === 'atrule' && (a as postcss.AtRule).name === 'media') media.push((a as postcss.AtRule).params);
      }
      const declarations: Record<string, string> = {};
      r.walkDecls((d) => { declarations[d.prop.toLowerCase()] = d.value; });
      out.push({ file: s.file, line: r.source?.start?.line ?? 0, media: media.join(' and '), selector: r.selector, declarations, rotation: rotationOf(declarations), frame, shadowHost: s.shadowHost, couldMatch: couldMatchCount(index, r.selector) });
    });
  }
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
}

export function pageObservation(p: PageIndex, root: string, html: HtmlAriaViews, aria: AriaViews, params: HtmlIndexParams = {}, nest: NestCtx = { depth: 0, chain: [], frame: null }): PageObservation {
  const idOf = new Map<HNode, number>(p.nodes.map((n, i) => [n, i]));
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

  // label association: <label for> and wrapping <label>, labelable elements only (HTML §4.10.4)
  const labelText = new Map<HNode, string>();
  const textAlt = (n: HNode): string => nameFromContent(n, new Set());
  for (const l of p.nodes.filter((n) => n.tag === 'label')) {
    const text = textAlt(l);
    if (!text) continue;
    const f = (l.attrs.for ?? '').trim();
    if (f) { const t = byId.get(f)?.[0]; if (t && LABELABLE.has(t.tag) && !labelText.has(t)) labelText.set(t, text); continue; }
    const stack = [...l.children];
    while (stack.length) {
      const c = stack.shift()!;
      if (LABELABLE.has(c.tag) && !(c.tag === 'input' && (c.attrs.type ?? '').toLowerCase() === 'hidden')) { if (!labelText.has(c)) labelText.set(c, text); break; }
      stack.push(...c.children);
    }
  }

  /** text of a subtree as name from content sees it: text, and each child's own text alternative */
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

  const refText = (ids: string): { text: string; visible: boolean } => {
    const parts = ids.trim().split(/\s+/).map((x) => byId.get(x)?.[0]).filter((x): x is HNode => !!x);
    return { text: parts.map((x) => (x.attrs['aria-label'] ?? '').trim() || nameFromContent(x, new Set(), hiddenNode(x))).join(' ').trim(), visible: parts.some((x) => !hiddenNode(x)) };
  };

  /** AccName 1.2 step order with HTML-AAM sources. */
  function accName(n: HNode, role: string | null): { name: string; source: string | null } {
    const lb = (n.attrs['aria-labelledby'] ?? '').trim();
    if (lb) { const r = refText(lb); if (r.text) return { name: r.text, source: 'aria-labelledby' }; }
    const al = (n.attrs['aria-label'] ?? '').trim();
    if (al) return { name: al, source: 'aria-label' };
    if (labelText.has(n)) return { name: labelText.get(n)!, source: 'label' };
    const type = (n.attrs.type ?? '').toLowerCase();
    if ((n.tag === 'img' || n.tag === 'area' || (n.tag === 'input' && type === 'image')) && 'alt' in n.attrs) {
      if (n.attrs.alt === '') return { name: '', source: 'alt-empty' };   // declared decorative: exactly empty
      if (n.attrs.alt.trim()) return { name: n.attrs.alt.trim(), source: 'alt' };
    }
    if (n.tag === 'input' && ['button', 'submit', 'reset'].includes(type) && (n.attrs.value ?? '').trim()) return { name: n.attrs.value.trim(), source: 'value' };
    if (n.tag === 'input' && (type === 'submit' || type === 'reset')) return { name: type === 'submit' ? 'Submit' : 'Reset', source: 'default' };
    if (n.tag === 'svg') {
      const t = n.children.find((c) => c.tag === 'title');
      if (t && t.text.trim()) return { name: t.text.trim(), source: 'svg-title' };
    } else if (role && nameFromContents.has(role)) {
      const s = nameFromContent(n, new Set());
      if (s) return { name: s, source: 'contents' };
    }
    const title = (n.attrs.title ?? '').trim();
    if (title) return { name: title, source: 'title-fallback' };
    const ph = (n.attrs.placeholder ?? '').trim();
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

  // the page's own rules, and how many sheets it links that the subject tree does not hold
  const pageRules = cssRulesOf(p, root, idOf, nest.frame);
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
      visibleLabel: labelText.has(n) || (!!lb && (() => { const r = refText(lb); return !!r.text && r.visible; })()),
      hidden: hiddenNode(n), focusable: focusable(n), inSvg: n.inSvg,
      pointerHandlers: POINTER.filter((h) => h in n.attrs), keyHandlers: KEY.filter((h) => h in n.attrs),
      tabindex: tiN !== null && !Number.isNaN(tiN) ? tiN : null,
      hasText: nameFromContent(n, new Set()) !== '',
      frame: nest.frame,
      inShadow: (() => { for (let a = n.parent; a; a = a.parent) if (isShadowTemplate(a)) return true; return false; })(),
      labelInName: ('aria-label' in n.attrs || 'aria-labelledby' in n.attrs) && !n.inSvg ? labelInName(n, name, pageRules, unreadSheets) : null,
      nthOfType: nthOfType(n), ancestorNthOfType: ancestors.map(nthOfType),
    };
  });

  const IDREF = params.idrefAttributes ?? [];
  const SINGLE = new Set(['aria-activedescendant', 'for', 'form', 'list']);
  const idrefs: PageObservation['idrefs'] = [];
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
    for (const e of inner.elements) elements.push({ ...e, id: e.id + off, ancestorIds: e.ancestorIds.map((x) => x + off), hidden: e.hidden || frameHidden });
    for (const r of inner.idrefs) idrefs.push({ ...r, elementId: r.elementId + off });
    for (const m of inner.media) media.push({ ...m, elementId: m.elementId + off });
    for (const l of inner.langAttributes) langAttributes.push({ ...l, elementId: l.elementId + off });
    for (const f of inner.frames) frames.push({ ...f, elementId: f.elementId + off });
    if (!frameHidden) for (const t of inner.texts) texts.push({ ...t, elementId: t.elementId + off });
    for (const r of inner.cssRules) cssRules.push({ ...r, shadowHost: r.shadowHost === null ? null : r.shadowHost + off });
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
  };
}
