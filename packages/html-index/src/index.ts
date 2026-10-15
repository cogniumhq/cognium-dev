/**
 * `@cognium/html-index`: a static index of built HTML.
 *
 *  - `html-index`: one observation per HTML page under a root — elements with roles, accessible
 *    names, labels, focusability and hidden-ness; the IDREF graph; media; `lang`; the viewport
 *    meta; parsed CSS rules; nested frame documents and declarative shadow trees; text blocks.
 *  - `file-index`: one observation per tree — every file with its sha256 and size, the text of
 *    files matching a path pattern, and pattern matches with line and excerpt.
 *  - `route-index`: one observation per site, read off the pages' `html-index` observations — each
 *    navigation block and each link of a repeated component (navigation, banner, contentinfo) lined
 *    up with the same on the first page that has it.
 *
 * Observations only: facts about the markup, never a verdict. The ARIA and ARIA-in-HTML tables
 * the role and name algorithms read are inputs passed by the caller; none ships in this package.
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, realpathSync } from 'node:fs';
import { join, relative } from 'node:path';
import { buildSiteIndex } from './parse.js';
import { walkEntry } from './path.js';
import { pageObservation, type AriaViews, type HtmlAriaViews, type HtmlIndexParams } from './html-index.js';
import { routeIndexOf, type RouteIndexParams } from './route-index.js';

/** The version of the observation shape. A consumer pins it and refuses any other. */
export const SCHEMA_VERSION = '0.2' as const;

/** Identity of this index, carried on every result and in the environment digest. */
export const DRIVER = { id: 'html-index', family: 'static', version: '0.2.0' } as const;

export function capabilities(): string[] {
  return ['html-index', 'file-index', 'route-index'];
}

export interface AnchorObservation {
  /** page path for `html-index`; `site` for `file-index` and `route-index` */
  anchor: string;
  observation: unknown;
  /** content hash of exactly what this anchor's observation read */
  inputDigest: string;
}

export interface RunResult {
  driver: typeof DRIVER;
  schemaVersion: typeof SCHEMA_VERSION;
  capability: string;
  anchors: AnchorObservation[];
  environmentDigest: string;
}

const sha = (s: string | Buffer): string => `sha256:${createHash('sha256').update(s).digest('hex')}`;

/** The index runs in-process; its environment is the Node runtime and this package. */
const environmentDigest = (): string => sha(`node ${process.version} ${process.platform}/${process.arch} ${DRIVER.id}@${DRIVER.version}`);

export function runHtmlIndex(root: string, views: { html: HtmlAriaViews; aria: AriaViews }, params: HtmlIndexParams = {}): RunResult {
  const site = buildSiteIndex(root);
  const anchors = site.pages
    .sort((a, b) => a.path.localeCompare(b.path))
    .map((p) => {
      const observation = pageObservation(p, root, views.html, views.aria, params);
      const sheets = [...new Set(observation.cssRules.map((r) => r.file).filter((f) => !f.includes('#style@')))].sort();
      // a nested frame document the tree holds is read too, so it is part of the digest
      const framed = [...new Set(observation.frames.filter((f) => f.examined && f.file).map((f) => f.file!))];
      const input = sha([p.raw, ...sheets.map((f) => readFileSync(join(root, f), 'utf8')), ...(framed.length ? ['frames', ...framed.map((f) => readFileSync(join(root, f), 'utf8'))] : [])].join('\u0000'));
      return { anchor: p.path, observation, inputDigest: input };
    });
  return { driver: DRIVER, schemaVersion: SCHEMA_VERSION, capability: 'html-index', anchors, environmentDigest: environmentDigest() };
}

/**
 * Capability `route-index`: ONE site observation over the html-index observations of
 * `pageAnchors` — the pages a run evaluates, which the caller has already indexed. Its input
 * digest covers exactly those pages' input digests and the parameters.
 */
export function routeIndexRun(pageAnchors: AnchorObservation[], params: RouteIndexParams = {}): RunResult {
  const sorted = [...pageAnchors].sort((a, b) => a.anchor.localeCompare(b.anchor));
  const observation = routeIndexOf(sorted, params);
  const inputDigest = sha([`origins ${JSON.stringify([...(params.origins ?? [])].sort())}`, ...sorted.map((a) => `${a.anchor}:${a.inputDigest}`)].join('\n'));
  return { driver: DRIVER, schemaVersion: SCHEMA_VERSION, capability: 'route-index', anchors: [{ anchor: 'site', observation, inputDigest }], environmentDigest: environmentDigest() };
}

/** `route-index` over a tree: html-index (default parameters) over its pages, or over `pages` only, then the site observation. */
export function runRouteIndex(root: string, views: { html: HtmlAriaViews; aria: AriaViews }, params: RouteIndexParams = {}, pages?: string[]): RunResult {
  const all = runHtmlIndex(root, views).anchors;
  return routeIndexRun(pages ? all.filter((a) => pages.includes(a.anchor)) : all, params);
}

export interface FileIndexParams {
  patterns?: string[];
  pathPattern?: string;
}

function walk(dir: string, root: string, out: string[] = [], ancestors = new Set([realpathSync(dir)])): string[] {
  for (const e of readdirSync(dir).sort()) {
    if (e === 'node_modules' || e === '.git') continue;
    const p = join(dir, e);
    // a link that leaves the root, dangles or loops is skipped, not read or thrown on
    const w = walkEntry(root, p, ancestors);
    if (w.kind === 'dir') { ancestors.add(w.real); walk(p, root, out, ancestors); ancestors.delete(w.real); }
    else if (w.kind === 'file') out.push(relative(root, p));
  }
  return out;
}

/** Capability `file-index`: files with hashes; text and pattern matches for files matching pathPattern. */
export function runFileIndex(root: string, params: FileIndexParams = {}): RunResult {
  const re = params.pathPattern ? new RegExp(params.pathPattern) : null;
  const patterns = (params.patterns ?? []).map((p) => p.toLowerCase());
  const files: { path: string; sha256: string; size: number; text: string | null }[] = [];
  const matches: { pattern: string; path: string; line: number; excerpt: string }[] = [];
  for (const path of walk(root, root)) {
    const buf = readFileSync(join(root, path));
    const selected = !!re && re.test(path) && buf.length <= 2_000_000;
    const text = selected ? buf.toString('utf8') : null;
    files.push({ path, sha256: sha(buf), size: buf.length, text });
    if (text && patterns.length) {
      const lines = text.split('\n');
      lines.forEach((l, i) => {
        const low = l.toLowerCase();
        for (const pat of patterns) if (low.includes(pat)) matches.push({ pattern: pat, path, line: i + 1, excerpt: l.trim().slice(0, 160) });
      });
    }
  }
  const observation = { fileCount: files.length, files, matches };
  return {
    driver: DRIVER, schemaVersion: SCHEMA_VERSION, capability: 'file-index',
    anchors: [{ anchor: 'site', observation, inputDigest: sha(files.filter((f) => f.text !== null).map((f) => `${f.path}:${f.sha256}`).join('\n')) }],
    environmentDigest: environmentDigest(),
  };
}

export { buildSiteIndex, parseHtml } from './parse.js';
export { decodeEntities, hostRow, pageObservation } from './html-index.js';
export type { AriaViews, CssDeclarationObs, CssRuleObs, ElementCssObs, ElementObs, FrameObs, HtmlAriaViews, HtmlIndexParams, PageObservation, StylesheetObs, TextObs } from './html-index.js';
export type { HNode, PageIndex, ParseError, SiteIndex } from './parse.js';
export { destinationOf, normaliseName, routeIndexOf } from './route-index.js';
export type { IdentificationRow, NavigationRow, RouteIndexObservation, RouteIndexParams, RoutePage } from './route-index.js';
export { labelInName, labelWords, visibleInnerText, type LabelInName } from './label-in-name.js';
export { isUnder, isUnderReal } from './path.js';
