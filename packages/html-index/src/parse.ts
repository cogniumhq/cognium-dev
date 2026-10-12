/**
 * Forgiving HTML tokenizer + tree builder for the static tier.
 *
 * Deliberately not a spec-conformant parser: it exists to answer structural questions
 * (what roles are declared, which IDREFs resolve, which controls carry a label) over a
 * checkout, without a browser. Where it cannot answer honestly it says so — an
 * unbalanced document sets `malformed`, and rules that depend on tree shape skip it
 * rather than assert against a tree they do not trust.
 *
 * The rendered tier (render.ts) is the authority on anything computed. This tier never
 * guesses at computed values.
 */
import { readFileSync, readdirSync, realpathSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import { walkEntry } from './path.js';
/** HTML §13.1.2 void elements: never have children or a closing tag (syntax, not a rule). */
const VOID_ELEMENTS = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr']);

export interface HNode {
  tag: string;
  attrs: Record<string, string>;
  children: HNode[];
  parent: HNode | null;
  /** 1-based line of the start tag in the source file. */
  line: number;
  text: string;
  /**
   * The same text, run by run, each with the number of element children that precede it, so a
   * traversal can put text and children back in document order. `text` is their join.
   */
  runs?: { at: number; text: string }[];
  /** the child positions (as `runs[].at`) at which white space alone stood in the source. */
  gaps?: number[];
  /** true when this node is inside an <svg> subtree — different AAM applies. */
  inSvg: boolean;
}

export interface PageIndex {
  /** path relative to the site root */
  path: string;
  nodes: HNode[];
  root: HNode;
  raw: string;
  malformed: boolean;
  /** raw <!doctype ...> if present */
  doctype: string | null;
}

export interface SiteIndex {
  root: string;
  pages: PageIndex[];
  /** every css file found, by relative path */
  css: Record<string, string>;
  /** CI workflow / config files found at the repo root, by relative path */
  ci: Record<string, string>;
  /** every file path in the checkout, relative — used by bundle-artifact rules */
  files: string[];
}

const TAG_RE = /<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<!(doctype)[^>]*>|<\/([a-zA-Z][-\w:]*)\s*>|<([a-zA-Z][-\w:]*)((?:\s+[^\s/>"'=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'>]+))?)*)\s*(\/?)>/gi;
const ATTR_RE = /([^\s/>"'=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;

function parseAttrs(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!s) return out;
  ATTR_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ATTR_RE.exec(s))) {
    const name = m[1].toLowerCase();
    out[name] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return out;
}

/** Elements whose content is not markup — we must not tokenize inside them. */
const RAW_TEXT = new Set(['script', 'style', 'textarea', 'title']);

export function parseHtml(raw: string, path: string): PageIndex {
  const root: HNode = { tag: '#root', attrs: {}, children: [], parent: null, line: 0, text: '', inSvg: false };
  const nodes: HNode[] = [];
  const stack: HNode[] = [root];
  let doctype: string | null = null;
  let malformed = false;
  let lastIndex = 0;

  // line lookup without scanning the whole string per token
  const lineStarts: number[] = [0];
  for (let i = 0; i < raw.length; i++) if (raw.charCodeAt(i) === 10) lineStarts.push(i + 1);
  const lineAt = (off: number): number => {
    let lo = 0, hi = lineStarts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= off) lo = mid; else hi = mid - 1; }
    return lo + 1;
  };

  TAG_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = TAG_RE.exec(raw))) {
    const whole = m[0];
    // text between the previous tag and this one belongs to the currently open element
    if (m.index > lastIndex) {
      const t = raw.slice(lastIndex, m.index);
      if (t.trim()) { const top = stack[stack.length - 1]; top.text += t; (top.runs ??= []).push({ at: top.children.length, text: t }); }
      // white space alone between two tags is not text of the element, and is still a
      // word boundary between its inline children. `text` and `runs` are unchanged by it.
      else if (t.length) { const top = stack[stack.length - 1]; (top.gaps ??= []).push(top.children.length); }
    }
    lastIndex = m.index + whole.length;

    if (whole.startsWith('<!--') || whole.startsWith('<![CDATA[')) continue;
    if (m[1]) { doctype = whole; continue; }

    if (m[2]) {
      const close = m[2].toLowerCase();
      // unwind to the nearest matching open element; anything skipped was left unclosed
      let depth = -1;
      for (let i = stack.length - 1; i > 0; i--) if (stack[i].tag === close) { depth = i; break; }
      if (depth === -1) { malformed = true; continue; }
      if (depth !== stack.length - 1) malformed = true;
      stack.length = depth;
      continue;
    }

    const tag = (m[3] ?? '').toLowerCase();
    if (!tag) continue;
    const parent = stack[stack.length - 1];
    const node: HNode = {
      tag,
      attrs: parseAttrs(m[4] ?? ''),
      children: [],
      parent: parent === root ? null : parent,
      line: lineAt(m.index),
      text: '',
      inSvg: parent.inSvg || tag === 'svg',
    };
    parent.children.push(node);
    nodes.push(node);

    const selfClosed = m[5] === '/' || VOID_ELEMENTS.has(tag);
    if (selfClosed) continue;

    if (RAW_TEXT.has(tag)) {
      // skip to the matching close tag without tokenizing the contents
      const closeRe = new RegExp(`</${tag}\\s*>`, 'i');
      const rest = raw.slice(lastIndex);
      const cm = closeRe.exec(rest);
      if (cm) {
        node.text = rest.slice(0, cm.index);
        lastIndex += cm.index + cm[0].length;
        TAG_RE.lastIndex = lastIndex;
      } else {
        malformed = true;
      }
      continue;
    }
    stack.push(node);
  }
  if (stack.length !== 1) malformed = true;

  return { path, nodes, root, raw, malformed, doctype };
}

/** Concatenated text of a node's subtree, as a name computation would see it. */
export function subtreeText(n: HNode): string {
  return inOrder(n, (c) => {
    if (c.tag === 'script' || c.tag === 'style') return '';
    if ((c.attrs['aria-hidden'] ?? '').toLowerCase() === 'true') return '';
    return subtreeText(c);
  }).replace(/\s+/g, ' ').trim();
}

/**
 * A node's own text and its children's contributions, in document order: each text run goes
 * before the child it preceded in the source. A node built without `runs` keeps its text first.
 */
export function inOrder(n: HNode, child: (c: HNode) => string): string {
  const runs = n.runs ?? (n.text ? [{ at: 0, text: n.text }] : []);
  let s = '';
  let r = 0;
  n.children.forEach((c, i) => {
    while (r < runs.length && runs[r].at <= i) s += ' ' + runs[r++].text;
    s += ' ' + child(c);
  });
  while (r < runs.length) s += ' ' + runs[r++].text;
  return s;
}

/** Explicit `role` token (first token wins, per ARIA's fallback list). */
export function explicitRole(n: HNode): string | null {
  const r = (n.attrs['role'] ?? '').trim().toLowerCase();
  if (!r) return null;
  return r.split(/\s+/)[0] ?? null;
}

function walkFiles(dir: string, root: string, out: string[], depth = 0, ancestors?: Set<string>): void {
  if (depth > 12) return;
  if (!ancestors) { try { ancestors = new Set([realpathSync(dir)]); } catch { return; } }
  let entries: string[];
  try { entries = readdirSync(dir); } catch { return; }
  for (const e of entries) {
    if (e === 'node_modules' || e === '.git' || e === 'dist' || e === '.next') continue;
    const full = join(dir, e);
    // a page reached through a link out of the root is not a page of the tree
    const w = walkEntry(root, full, ancestors);
    if (w.kind === 'dir') { ancestors.add(w.real); walkFiles(full, root, out, depth + 1, ancestors); ancestors.delete(w.real); }
    else if (w.kind === 'file') out.push(relative(root, full));
  }
}

const CI_HINTS = [
  '.github/workflows', '.gitlab-ci.yml', 'azure-pipelines.yml', '.circleci/config.yml',
  'Jenkinsfile', '.pre-commit-config.yaml', 'package.json', 'lighthouserc.json', 'lighthouserc.js',
  '.pa11yci', 'pa11yci.json', 'playwright.config.ts', 'playwright.config.js',
];

export function buildSiteIndex(root: string, pageGlobPrefixes?: string[]): SiteIndex {
  const files: string[] = [];
  walkFiles(root, root, files);

  const wanted = (p: string): boolean =>
    !pageGlobPrefixes || pageGlobPrefixes.length === 0 || pageGlobPrefixes.some((g) => p.startsWith(g));

  const pages: PageIndex[] = [];
  for (const f of files) {
    if (extname(f).toLowerCase() !== '.html' && extname(f).toLowerCase() !== '.htm') continue;
    if (!wanted(f)) continue;
    pages.push(parseHtml(readFileSync(join(root, f), 'utf8'), f));
  }
  if (pages.length === 0) {
    throw new Error(`html-index: no HTML pages found under ${root} — refusing to index an empty tree`);
  }

  const css: Record<string, string> = {};
  for (const f of files) {
    if (extname(f).toLowerCase() === '.css') css[f] = readFileSync(join(root, f), 'utf8');
  }
  const ci: Record<string, string> = {};
  for (const f of files) {
    if (CI_HINTS.some((h) => f === h || f.startsWith(h + '/') || f.startsWith(h))) {
      try { ci[f] = readFileSync(join(root, f), 'utf8'); } catch { /* unreadable, skip */ }
    }
  }
  return { root, pages, css, ci, files };
}
