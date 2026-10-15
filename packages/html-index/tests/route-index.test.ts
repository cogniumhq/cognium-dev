/** route-index: navigations and component links lined up across the pages of a site. Facts, never verdicts. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { capabilities, destinationOf, normaliseName, routeIndexRun, runHtmlIndex, runRouteIndex, SCHEMA_VERSION, type RouteIndexObservation } from '../src/index.js';
import { views } from './fixtures/views.js';

const SITE = join(dirname(fileURLToPath(import.meta.url)), 'fixtures/route-site');
const observe = (params = {}, pages?: string[]) => {
  const r = runRouteIndex(SITE, views, params, pages);
  assert.equal(r.capability, 'route-index');
  assert.equal(r.schemaVersion, SCHEMA_VERSION);
  assert.deepEqual(r.anchors.map((a) => a.anchor), ['site']);
  return { r, o: r.anchors[0].observation as RouteIndexObservation };
};

test('capabilities: route-index beside html-index and file-index', () => {
  assert.deepEqual(capabilities(), ['html-index', 'file-index', 'route-index']);
});

test('destinationOf: one path for /x, /x/ and /x/index.html; fragments dropped; queries kept; only the site\'s own origins', () => {
  const d = (h: string, page = 'shop/cart.html', base: string | null = null, origins: string[] = []) => destinationOf(h, page, base, origins);
  assert.deepEqual(d('../help/'), { destination: '/help/' });
  assert.deepEqual(d('../help'), { destination: '/help/' });
  assert.deepEqual(d('/help/index.htm'), { destination: '/help/' });
  assert.deepEqual(d('pay.html?step=2#top'), { destination: '/shop/pay.html?step=2' });
  assert.deepEqual(d('pay.html', 'shop/cart.html', '/checkout/'), { destination: '/checkout/pay.html' });
  assert.deepEqual(d('  '), { off: 'in-page' });
  assert.deepEqual(d('#basket'), { off: 'in-page' });
  assert.deepEqual(d('tel:+3200000000'), { off: 'scheme' });
  assert.deepEqual(d('javascript:void(0)'), { off: 'scheme' });
  assert.deepEqual(d('https://shop.example/help'), { off: 'other-origin' });
  assert.deepEqual(d('https://shop.example/help', 'shop/cart.html', null, ['https://shop.example/']), { destination: '/help/' });
  assert.deepEqual(d('http://shop.example/help', 'shop/cart.html', null, ['https://shop.example']), { off: 'other-origin' });
  assert.equal(normaliseName('  Ｏpening\tHOURS '), 'opening hours');
});

test('pages: every page is listed; a malformed page is listed and not compared', () => {
  const { o } = observe({ origins: ['https://example.com'] });
  assert.deepEqual(o.pages.map((p) => [p.path, p.malformed, p.navigations, p.componentLinks]), [
    ['about/index.html', false, 1, 3],
    ['contact.html', false, 1, 5],
    ['draft.html', true, 0, 0],
    ['index.html', false, 1, 6],
    ['menu/index.html', false, 2, 8],
    ['visit.html', false, 1, 7],
  ]);
  assert.deepEqual([o.pageCount, o.pagesCompared, o.repeatedNavigations, o.repeatedComponentLinks], [6, 5, 1, 6]);
  // a social link, a mail link and another origin's page; a hidden navigation is not read at all
  assert.equal(o.linksOffSite, 3);
});

test('navigations: one block across pages by its normalised name; shared destinations in this page\'s order and the reference\'s', () => {
  const { o } = observe();
  const rows = o.navigations.filter((r) => r.block === 'navigation "primary"');
  assert.deepEqual(rows.map((r) => r.page), ['about/index.html', 'contact.html', 'index.html', 'menu/index.html', 'visit.html']);
  assert.ok(rows.every((r) => r.reference === 'about/index.html' && r.pagesWithBlock === 5));
  // <base href="/"> resolves the reference page's relative links against the root
  assert.deepEqual(rows[0].destinations, ['/', '/about/', '/visit.html']);
  assert.deepEqual(rows.map((r) => [r.page, r.pageOrder, r.orderDiffers]), [
    ['about/index.html', ['/', '/about/', '/visit.html'], false],
    ['contact.html', ['/visit.html', '/'], true],
    ['index.html', ['/', '/visit.html', '/about/'], true],
    // `../about` and `../visit.html#map` from a subfolder; a destination the reference lacks is not an order change
    ['menu/index.html', ['/', '/about/', '/visit.html'], false],
    ['visit.html', ['/', '/visit.html', '/about/'], true],
  ]);
  assert.deepEqual(rows[2].referenceOrder, ['/', '/about/', '/visit.html']);
  const crumbs = o.navigations.filter((r) => r.block === 'navigation (unnamed #1)');
  assert.deepEqual(crumbs.map((r) => [r.page, r.index, r.destinations, r.pagesWithBlock]), [['menu/index.html', 1, ['/', '/menu/'], 1]]);
});

test('identifications: the names each page gives one destination from one kind of component, against the reference page', () => {
  const { o } = observe({ origins: ['https://example.com'] });
  const row = (component: string, destination: string, page: string) => o.identifications.find((r) => r.component === component && r.destination === destination && r.page === page)!;
  // the footer link to the contact page: the absolute URL is the site's own once its origin is named
  assert.deepEqual(row('contentinfo', '/contact.html', 'contact.html').shownNames, ['Contact']);
  assert.deepEqual([row('contentinfo', '/contact.html', 'menu/index.html').onlyHere, row('contentinfo', '/contact.html', 'menu/index.html').onlyOnReference], [['write to us'], ['contact']]);
  assert.deepEqual([row('contentinfo', '/contact.html', 'visit.html').names, row('contentinfo', '/contact.html', 'visit.html').shownNames], [['contact'], ['CONTACT']]);
  assert.equal(row('contentinfo', '/contact.html', 'index.html').pagesWithDestination, 4);
  // the logo in the banner, named by its image
  assert.deepEqual(row('banner', '/', 'menu/index.html').onlyHere, ['corner bakery home']);
  assert.equal(row('banner', '/', 'menu/index.html').reference, 'contact.html');
  // the content link "See the menu" is not indexed
  assert.equal(o.identifications.some((r) => r.names.includes('see the menu')), false);
  const without = observe().o;
  assert.equal(without.linksOffSite, 4);
  assert.equal(without.identifications.some((r) => r.page === 'contact.html' && r.component === 'contentinfo'), false);
});

test('a run over some pages reads those only; the input digest covers their digests and the origins', () => {
  const one = observe({}, ['index.html']);
  assert.deepEqual([one.o.pageCount, one.o.repeatedNavigations, one.o.repeatedComponentLinks], [1, 0, 0]);
  const anchors = runHtmlIndex(SITE, views).anchors;
  const a = routeIndexRun(anchors, {});
  const b = routeIndexRun([...anchors].reverse(), {});
  assert.equal(JSON.stringify(a), JSON.stringify(b));
  assert.notEqual(routeIndexRun(anchors, { origins: ['https://example.com'] }).anchors[0].inputDigest, a.anchors[0].inputDigest);
  assert.equal(JSON.stringify(observe().r), JSON.stringify(observe().r));
});
