/**
 * Capability `route-index`: ONE observation for the site (anchor `site`), built from the
 * `html-index` observations of the pages a run indexes: what the site's repeated components hold,
 * page by page, so a consumer can compare navigations and component links ACROSS pages.
 *
 * Facts only. Two pages' navigations are lined up, and the index says which destinations they share
 * and in what order each page puts them; two pages' footer links to one destination are lined up, and
 * the index says which names each page gives it. Whether a difference matters is the consumer's
 * decision, never this file's.
 *
 * What a DESTINATION is: a link's `href` resolved against its page (or the page's `<base href>`),
 * the fragment dropped, path and query kept, and a final `index.html` / `index.htm` and a missing
 * trailing slash on an extensionless path read as the directory (`/about`, `/about/` and
 * `/about/index.html` are one destination, as a static file server maps them to one file). Only the
 * site's own origin is compared: a relative or root-relative URL, or an absolute one whose origin
 * the caller names in `origins`. Another origin, a non-HTTP scheme (`mailto:`, `tel:`,
 * `javascript:`) and an in-page link (`#…`) are not destinations here, and are counted.
 */
import type { PageObservation, ElementObs } from './html-index.js';

export interface RouteIndexParams {
  /** absolute origins that are the site's own (`https://example.com`); a relative URL always is */
  origins?: string[];
}

/** One page's place in the index. */
export interface RoutePage {
  path: string;
  /** the tree shape is not trusted (html-index `malformed`): the page is read, and not compared */
  malformed: boolean;
  /** navigation blocks on the page that are not hidden */
  navigations: number;
  /** links compared for identification: in a navigation, banner or contentinfo, to a destination of the site */
  componentLinks: number;
}

/** One navigation block on one page, lined up with the same block on the first page that has it. */
export interface NavigationRow {
  /** how the block is told apart across pages: `navigation "<name>"`, or `navigation (unnamed #n)` */
  block: string;
  name: string;
  /** 1-based position among the page's unnamed navigations; null for a named one */
  index: number | null;
  page: string;
  elementId: number;
  line: number;
  /** the links' destinations in document order, each once */
  destinations: string[];
  /** how many compared pages hold this block */
  pagesWithBlock: number;
  /** the first page (in path order) that holds this block */
  reference: string;
  /** destinations this page and the reference page both hold in the block */
  sharedWithReference: number;
  /** the shared destinations in THIS page's order */
  pageOrder: string[];
  /** the same destinations in the REFERENCE page's order */
  referenceOrder: string[];
  /** pageOrder and referenceOrder differ */
  orderDiffers: boolean;
}

/** One destination linked from one kind of repeated component on one page. */
export interface IdentificationRow {
  /** the nearest landmark of the link among navigation, banner and contentinfo */
  component: string;
  destination: string;
  page: string;
  /** the accessible names the page gives the links, normalised (case, white space), distinct, sorted; an unnamed link adds none */
  names: string[];
  /** the names as the page gives them, first spelling of each normalised name */
  shownNames: string[];
  elementIds: number[];
  lines: number[];
  /** how many compared pages link this destination from this kind of component */
  pagesWithDestination: number;
  /** the first page (in path order) that does */
  reference: string;
  referenceNames: string[];
  /** names on this page and not on the reference page */
  onlyHere: string[];
  /** names on the reference page and not on this page */
  onlyOnReference: string[];
}

export interface RouteIndexObservation {
  pageCount: number;
  pagesCompared: number;
  /** navigation blocks (by `block`) held by 2 or more compared pages */
  repeatedNavigations: number;
  /** (component, destination) pairs linked from 2 or more compared pages */
  repeatedComponentLinks: number;
  /** links in a navigation, banner or contentinfo whose destination is not the site's (another origin, another scheme) */
  linksOffSite: number;
  pages: RoutePage[];
  navigations: NavigationRow[];
  identifications: IdentificationRow[];
}

const BASE = 'http://route-index.invalid';
const COMPONENTS = ['navigation', 'banner', 'contentinfo'];

/** The accessible name as it is compared: Unicode-compatible, lower case, white space collapsed. */
export function normaliseName(s: string): string {
  return s.normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim();
}

/**
 * A link's destination as a path of the site, or null when it is not one of the site's (and why).
 * `page` is the page's path in the tree; `base` its `<base href>`, if any.
 */
export function destinationOf(href: string, page: string, base: string | null, origins: string[] = []): { destination: string } | { off: 'in-page' | 'other-origin' | 'scheme' | 'unparsable' } {
  const h = href.trim();
  if (h === '' || h.startsWith('#')) return { off: 'in-page' };
  const own = new Set(origins.map((o) => { try { return new URL(o).origin; } catch { return o; } }));
  let u: URL;
  try {
    const pageUrl = new URL(page.split('/').map(encodeURIComponent).join('/'), `${BASE}/`);
    const baseUrl = base ? new URL(base, pageUrl) : pageUrl;
    u = new URL(h, baseUrl);
  } catch { return { off: 'unparsable' }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { off: 'scheme' };
  if (u.origin !== BASE && !own.has(u.origin)) return { off: 'other-origin' };
  let p = u.pathname;
  try { p = decodeURI(p); } catch { /* an escape that is not one stands as written */ }
  p = p.replace(/\/index\.html?$/i, '/');
  const last = p.split('/').pop() ?? '';
  if (last !== '' && !/\.[a-z0-9]+$/i.test(last)) p += '/';
  return { destination: p + u.search };
}

interface PageInput { anchor: string; observation: unknown }

/** The route index of these pages' html-index observations (in path order). */
export function routeIndexOf(pageObservations: PageInput[], params: RouteIndexParams = {}): RouteIndexObservation {
  const origins = params.origins ?? [];
  const sorted = [...pageObservations].sort((a, b) => a.anchor.localeCompare(b.anchor));
  const pages: RoutePage[] = [];
  let linksOffSite = 0;
  // block → page → row (without the cross-page fields)
  const navs = new Map<string, Map<string, Omit<NavigationRow, 'pagesWithBlock' | 'reference' | 'sharedWithReference' | 'pageOrder' | 'referenceOrder' | 'orderDiffers'>>>();
  // component|destination → page → names
  const idents = new Map<string, Map<string, { component: string; destination: string; names: Map<string, string>; elementIds: number[]; lines: number[] }>>();

  for (const { anchor, observation } of sorted) {
    const o = observation as PageObservation;
    // a nested frame document's rows resolve against that document, not the page: not read here
    const own = o.elements.filter((e) => e.frame === null);
    const byId = new Map<number, ElementObs>(own.map((e) => [e.id, e]));
    const row: RoutePage = { path: anchor, malformed: !!o.malformed, navigations: 0, componentLinks: 0 };
    pages.push(row);
    if (o.malformed) continue;
    const baseEl = own.find((e) => e.tag === 'base' && typeof e.attrs.href === 'string');
    const base = baseEl ? baseEl.attrs.href : null;

    // the page's navigation blocks, each with its cross-page identity
    const blockOf = new Map<number, { block: string; name: string; index: number | null; el: ElementObs }>();
    let unnamed = 0;
    for (const e of own) {
      if (e.effectiveRole !== 'navigation' || e.hidden) continue;
      const name = normaliseName(e.name ?? '');
      const index = name ? null : ++unnamed;
      const block = name ? `navigation "${name}"` : `navigation (unnamed #${index})`;
      blockOf.set(e.id, { block, name, index, el: e });
      row.navigations++;
    }
    const pageNavs = new Map<string, { b: { block: string; name: string; index: number | null; el: ElementObs }; destinations: string[] }>();
    for (const b of blockOf.values()) if (!pageNavs.has(b.block)) pageNavs.set(b.block, { b, destinations: [] });

    for (const e of own) {
      if (e.hidden || (e.tag !== 'a' && e.tag !== 'area') || typeof e.attrs.href !== 'string') continue;
      // the nearest navigation / banner / contentinfo ancestor
      let component: ElementObs | null = null;
      for (const id of e.ancestorIds) {
        const a = byId.get(id);
        if (a && !a.hidden && a.effectiveRole && COMPONENTS.includes(a.effectiveRole)) { component = a; break; }
      }
      if (!component) continue;
      const d = destinationOf(e.attrs.href, anchor, base, origins);
      if (!('destination' in d)) { if (d.off !== 'in-page') linksOffSite++; continue; }
      row.componentLinks++;
      // navigation order: the link's NEAREST navigation, whatever landmark sits between
      for (const id of e.ancestorIds) {
        const b = blockOf.get(id);
        if (!b) continue;
        const pn = pageNavs.get(b.block)!;
        if (!pn.destinations.includes(d.destination)) pn.destinations.push(d.destination);
        break;
      }
      // identification: the names this page gives the destination from this kind of component
      const key = `${component.effectiveRole}|${d.destination}`;
      const byPage = idents.get(key) ?? idents.set(key, new Map()).get(key)!;
      const slot = byPage.get(anchor) ?? byPage.set(anchor, { component: component.effectiveRole!, destination: d.destination, names: new Map(), elementIds: [], lines: [] }).get(anchor)!;
      const shown = (e.name ?? '').replace(/\s+/g, ' ').trim();
      const n = normaliseName(shown);
      if (n && !slot.names.has(n)) slot.names.set(n, shown);
      slot.elementIds.push(e.id);
      slot.lines.push(e.line);
    }
    for (const [block, { b, destinations }] of pageNavs) {
      const m = navs.get(block) ?? navs.set(block, new Map()).get(block)!;
      m.set(anchor, { block, name: b.name, index: b.index, page: anchor, elementId: b.el.id, line: b.el.line, destinations });
    }
  }

  const navigations: NavigationRow[] = [];
  for (const byPage of navs.values()) {
    const rows = [...byPage.values()];
    const ref = rows[0];
    for (const r of rows) {
      const shared = r.destinations.filter((d) => ref.destinations.includes(d));
      const referenceOrder = ref.destinations.filter((d) => shared.includes(d));
      navigations.push({
        ...r, pagesWithBlock: rows.length, reference: ref.page, sharedWithReference: shared.length,
        pageOrder: shared, referenceOrder, orderDiffers: shared.some((d, i) => d !== referenceOrder[i]),
      });
    }
  }
  const identifications: IdentificationRow[] = [];
  for (const byPage of idents.values()) {
    const rows = [...byPage.entries()];
    const [refPage, ref] = rows[0];
    const referenceNames = [...ref.names.keys()].sort();
    for (const [page, s] of rows) {
      const names = [...s.names.keys()].sort();
      identifications.push({
        component: s.component, destination: s.destination, page, names, shownNames: [...s.names.values()],
        elementIds: s.elementIds, lines: s.lines, pagesWithDestination: rows.length, reference: refPage, referenceNames,
        onlyHere: names.filter((n) => !referenceNames.includes(n)), onlyOnReference: referenceNames.filter((n) => !names.includes(n)),
      });
    }
  }
  return {
    pageCount: pages.length,
    pagesCompared: pages.filter((p) => !p.malformed).length,
    repeatedNavigations: [...navs.values()].filter((m) => m.size >= 2).length,
    repeatedComponentLinks: [...idents.values()].filter((m) => m.size >= 2).length,
    linksOffSite,
    pages, navigations, identifications,
  };
}
