/** Same input, same bytes; element ids are positions in document order; the result names its schema. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSiteIndex, capabilities, DRIVER, labelWords, parseHtml, runFileIndex, runHtmlIndex, SCHEMA_VERSION, visibleInnerText } from '../src/index.js';
import { explicitRole, subtreeText } from '../src/parse.js';
import { lastCompounds } from '../src/selector.js';
import { views } from './fixtures/views.js';

function tree(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'hi-det-'));
  for (const [f, body] of Object.entries(files)) { mkdirSync(join(dir, f, '..'), { recursive: true }); writeFileSync(join(dir, f), body); }
  return dir;
}

const SITE = {
  'index.html': '<!doctype html><html lang="en"><head><title>Home</title><meta name="viewport" content="width=device-width, user-scalable=no"><link rel="stylesheet" href="a.css"></head>'
    + '<body><nav aria-label="Main"><ul><li><a href="b/page.html">Next</a></li></ul></nav><video controls><track kind="captions" srclang="en"></video>'
    + '<iframe src="b/page.html"></iframe><label for="q">Query</label><input id="q" list="l"><p lang="fr">bonjour</p></body></html>',
  'b/page.html': '<!doctype html><html><body><h1>Second</h1><button onclick="go()" onkeydown="go()" tabindex="0">Go</button></body></html>',
  'a.css': '@media print { nav { display: none } } .spin { transform: rotate(90deg) }',
  'notes.txt': 'first line\nan Overlay widget\n',
};

test('two runs over the same tree give the same bytes, and the envelope carries the schema version', () => {
  const dir = tree(SITE);
  try {
    const params = { idrefAttributes: ['for', 'list', 'aria-labelledby'] };
    const a = runHtmlIndex(dir, views, params);
    const b = runHtmlIndex(dir, views, params);
    assert.equal(JSON.stringify(a), JSON.stringify(b));
    assert.equal(a.schemaVersion, SCHEMA_VERSION);
    assert.equal(a.schemaVersion, '0.2');
    assert.deepEqual(a.driver, DRIVER);
    assert.deepEqual(a.anchors.map((x) => x.anchor), ['b/page.html', 'index.html']);
    assert.ok(a.anchors.every((x) => /^sha256:[0-9a-f]{64}$/.test(x.inputDigest)));
    // the schema version rides on the envelope, never inside an observation
    assert.ok(a.anchors.every((x) => !('schemaVersion' in (x.observation as object))));
    const f1 = runFileIndex(dir, { pathPattern: '\\.txt$', patterns: ['Overlay'] });
    const f2 = runFileIndex(dir, { pathPattern: '\\.txt$', patterns: ['Overlay'] });
    assert.equal(JSON.stringify(f1), JSON.stringify(f2));
    assert.equal(f1.schemaVersion, '0.2');
    const obs = f1.anchors[0].observation as any;
    assert.deepEqual(obs.files.map((f: any) => f.path), ['a.css', 'b/page.html', 'index.html', 'notes.txt']);
    assert.deepEqual(obs.matches, [{ pattern: 'overlay', path: 'notes.txt', line: 2, excerpt: 'an Overlay widget' }]);
    assert.deepEqual(obs.files.map((f: any) => f.text === null), [true, true, true, false]);
    assert.deepEqual(capabilities(), ['html-index', 'file-index', 'route-index']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('element ids are document-order positions; a framed document is appended with ids offset', () => {
  const dir = tree(SITE);
  try {
    const o = runHtmlIndex(dir, views).anchors.find((a) => a.anchor === 'index.html')!.observation as any;
    assert.deepEqual(o.elements.map((e: any) => e.id), o.elements.map((_: any, i: number) => i));
    const own = o.elements.filter((e: any) => e.frame === null);
    assert.ok(own.every((e: any, i: number) => i === 0 || e.line >= own[i - 1].line));
    assert.ok(o.elements.some((e: any) => e.frame === 'iframe[src="b/page.html"]@1' && e.tag === 'h1'));
    assert.deepEqual([o.lang, o.title, o.malformed], ['en', 'Home', false]);
    assert.deepEqual(o.viewport, { present: true, content: 'width=device-width, user-scalable=no', userScalable: false, maximumScale: null });
    assert.deepEqual(o.media, [{ elementId: o.elements.find((e: any) => e.tag === 'video').id, tag: 'video', line: 1, tracks: [{ kind: 'captions', srclang: 'en' }], autoplay: false, muted: false, controls: true }]);
    assert.deepEqual(o.cssRules.map((r: any) => [r.selector, r.media, r.rotation, r.couldMatch]), [['nav', 'print', null, 1], ['.spin', '', 90, 0]]);
    const btn = o.elements.find((e: any) => e.tag === 'button');
    assert.deepEqual([btn.pointerHandlers, btn.keyHandlers, btn.tabindex, btn.focusable], [['onclick'], ['onkeydown'], 0, true]);
    const input = o.elements.find((e: any) => e.tag === 'input');
    assert.deepEqual([input.hostRow, input.effectiveRole, input.name, input.nameSource], ['input[list]', 'combobox', 'Query', 'label']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the parser: an unbalanced tree is malformed, raw-text elements are not tokenized, and an empty tree is refused', () => {
  assert.equal(parseHtml('<div><span>a</div>', 'x.html').malformed, true);
  assert.equal(parseHtml('<p>a</p></section>', 'x.html').malformed, true);
  assert.equal(parseHtml('<script>if (a < b) {}', 'x.html').malformed, true);
  const p = parseHtml('<!DOCTYPE html><!-- c --><title>a <b> c</title><p CLASS=x data-n=\'1\' hidden>t<br/>u</p>', 'x.html');
  assert.equal(p.malformed, false);
  assert.equal(p.doctype, '<!DOCTYPE html>');
  assert.deepEqual(p.nodes.map((n) => n.tag), ['title', 'p', 'br']);
  assert.deepEqual(p.nodes[1].attrs, { class: 'x', 'data-n': '1', hidden: '' });
  assert.equal(p.nodes[0].text, 'a <b> c');
  assert.equal(subtreeText(parseHtml('<p>one <b>two</b> three<i aria-hidden="true">x</i><script>y</script></p>', 'x.html').nodes[0]), 'one two three');
  assert.equal(explicitRole(parseHtml('<p role=" Tab  button">', 'x.html').nodes[0]), 'tab');
  assert.equal(explicitRole(parseHtml('<p>', 'x.html').nodes[0]), null);
  const dir = tree({ 'readme.txt': 'no pages here' });
  try {
    assert.throws(() => buildSiteIndex(dir), /no HTML pages found/);
    assert.throws(() => runHtmlIndex(dir, views), /no HTML pages found/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('text keys and selector reading, directly', () => {
  assert.deepEqual(labelWords('Next (page 2) — Café-bar'), ['next', 'cafe', 'bar']);
  assert.deepEqual(labelWords('non-standard', true), ['nonstandard']);
  assert.equal(visibleInnerText(parseHtml('<p>a<br>b <img alt="x"> <span hidden>c</span>&amp;</p>', 'x.html').nodes[0]), 'a b &');
  const c = lastCompounds('svg|a[href$=".pdf" i], ul > li.Item#x:hover /* c */, [ns|x], [a=b c], *');
  assert.deepEqual(c.map((x) => [x.tag, x.id, x.classes, x.attrs.length]), [['a', null, [], 1], ['li', 'x', ['item'], 0], [null, null, [], 0], [null, null, [], 0], [null, null, [], 0]]);
});
