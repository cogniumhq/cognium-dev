/** The observation fields added in schema 0.2, on pages written for these tests. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseHtml, runHtmlIndex, type ElementObs, type PageObservation } from '../src/index.js';
import { views } from './fixtures/views.js';

const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), 'fixtures/fields-0.2');

function page(body: string, head = '', htmlAttrs = ' lang="en"') {
  const dir = mkdtempSync(join(tmpdir(), 'hi02-'));
  try {
    writeFileSync(join(dir, 'index.html'), `<!doctype html>\n<html${htmlAttrs}>\n<head><title>t</title>${head}</head>\n<body>\n${body}\n</body>\n</html>\n`);
    const o = runHtmlIndex(dir, views, { idrefAttributes: ['aria-labelledby', 'aria-describedby', 'aria-controls', 'for', 'list'] }).anchors[0].observation as PageObservation;
    const by = (id: string): ElementObs => o.elements.find((e) => e.attrs.id === id)!;
    return { o, by };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ---------------------------------------------------------------- visible label text

test('visibleLabelText: the text on the element, not its accessible name; images, titles and placeholders are not visible text', () => {
  const { by } = page(`<a id="more" href="/x" aria-label="More about pricing">More</a>
<button id="icon" aria-label="Search"><svg><title>magnifier</title></svg></button>
<button id="arrow">Next &rarr;</button>
<a id="pic" href="/"><img src="a.png" alt="Logo"> Start</a>
<button id="sr">Buy <span aria-hidden="true">now</span><span style="display:none"> today</span></button>
<input id="tip" type="text" title="Postcode" placeholder="e.g. 1000">
<div id="empty"></div>`);
  assert.equal(by('more').visibleLabelText, 'More');
  assert.equal(by('more').name, 'More about pricing');
  assert.equal(by('icon').visibleLabelText, '');
  assert.equal(by('arrow').visibleLabelText, 'Next →');
  assert.equal(by('pic').visibleLabelText, 'Start');
  assert.equal(by('sr').visibleLabelText, 'Buy now');   // aria-hidden text is on the screen; display:none text is not
  assert.equal(by('tip').visibleLabelText, '');
  assert.equal(by('empty').visibleLabelText, '');
});

test('visibleLabelText: a form field reads its <label>s, then its rendered aria-labelledby targets; a button input its value', () => {
  const { by } = page(`<label for="qty">Quantity</label><label for="qty">(max 9)</label><input id="qty" type="number" aria-label="Amount">
<label>Remember me <input id="remember" type="checkbox"></label>
<h2 id="h">Delivery</h2><span id="gone" hidden>Address</span>
<input id="street" type="text" aria-labelledby="h gone">
<input id="ghost" type="text" aria-labelledby="gone">
<select id="size" aria-labelledby="h"><option>Small</option></select>
<input id="go" type="submit" value="  Place   order "><input id="def" type="reset"><input id="plain" type="button">
<label for="cta">Also</label><button id="cta">Order</button>
<label for="bare">Bare</label><button id="bare"></button>
<div hidden><label for="hid">Hidden label</label><input id="hid" type="text"></div>`);
  assert.equal(by('qty').visibleLabelText, 'Quantity (max 9)');
  assert.equal(by('qty').name, 'Amount');
  assert.equal(by('remember').visibleLabelText, 'Remember me');
  assert.equal(by('street').visibleLabelText, 'Delivery');   // the hidden target names the field and labels nothing visibly
  assert.equal(by('ghost').visibleLabelText, '');
  assert.equal(by('size').visibleLabelText, 'Delivery');     // a select's options are not its label
  assert.equal(by('go').visibleLabelText, 'Place order');
  assert.equal(by('def').visibleLabelText, 'Reset');
  assert.equal(by('plain').visibleLabelText, '');
  assert.equal(by('cta').visibleLabelText, 'Order');         // a button's own text comes before a <label>
  assert.equal(by('bare').visibleLabelText, 'Bare');
  assert.equal(by('hid').visibleLabelText, '');              // the field itself is not rendered
});

// ---------------------------------------------------------------- inherited lang

test('lang: the nearest lang on the element or an ancestor, trimmed; "" is declared unknown and inherited; null is never declared', () => {
  const { o, by } = page(`<div id="a"><p id="b" lang=" nl ">Hallo <em id="c">wereld</em></p><p id="d" lang=""><b id="e">?</b></p></div>`, '', ' id="top" lang="EN-us"');
  const top = by('top').id;
  assert.deepEqual([by('top').lang, by('top').langFrom], ['EN-us', top]);
  assert.deepEqual([by('a').lang, by('a').langFrom], ['EN-us', top]);
  assert.deepEqual([by('b').lang, by('b').langFrom], ['nl', by('b').id]);
  assert.deepEqual([by('c').lang, by('c').langFrom], ['nl', by('b').id]);
  assert.deepEqual([by('e').lang, by('e').langFrom], ['', by('d').id]);
  // the 0.1 fields are untouched: langAttributes keeps the value as written
  assert.equal(o.langAttributes.find((l) => l.elementId === by('b').id)!.value, ' nl ');
  const none = page('<p id="x">no language</p>', '', '');
  assert.deepEqual([none.by('x').lang, none.by('x').langFrom], [null, null]);
});

test('lang and ids inside a frame document: its own lang, ids offset like every other row', () => {
  const { o, by } = page(`<iframe id="f" srcdoc="&lt;p id=&quot;in&quot; lang=&quot;fr&quot;&gt;Salut &lt;b id=&quot;deep&quot;&gt;!&lt;/b&gt;&lt;/p&gt;&lt;span id=&quot;x&quot; aria-describedby=&quot;in nope&quot;&gt;x&lt;/span&gt;"></iframe>`);
  const inner = o.elements.filter((e) => e.frame !== null);
  const p = inner.find((e) => e.attrs.id === 'in')!, b = inner.find((e) => e.attrs.id === 'deep')!;
  assert.deepEqual([b.lang, b.langFrom], ['fr', p.id]);
  assert.equal(by('f').lang, 'en');
  const edges = o.idrefEdges.filter((e) => e.from === inner.find((x) => x.attrs.id === 'x')!.id);
  assert.deepEqual(edges.map((e) => [e.token, e.to, e.dangling]), [['in', p.id, false], ['nope', null, true]]);
});

// ---------------------------------------------------------------- IDREF edges and duplicate ids

test('idrefEdges: one per token with both ends, as idrefs reads them; duplicateIds lists every shared id', () => {
  const { o, by } = page(`<h2 id="t">Title</h2>
<section id="s" aria-labelledby="t t2" aria-describedby="note">Body</section>
<p id="note">One</p>
<p id="note">Two</p>
<p id="note">Three</p>
<label id="l" for="missing">Lost</label>
<div id="me" aria-controls="me"></div>
<div id="blank" aria-labelledby="  "></div>
<input id="q" list="opts"><datalist id="opts"></datalist>
<span id="dup2"></span><span id="dup2"></span>`);
  assert.equal(o.idrefEdges.length, o.idrefs.length);
  o.idrefEdges.forEach((e, i) => {
    const r = o.idrefs[i];
    assert.deepEqual([e.from, e.attr, e.token, !e.dangling, e.duplicate, e.selfReference], [r.elementId, r.attr, r.token, r.resolves, r.targetDuplicated, r.selfReference]);
  });
  const rows = o.idrefEdges.map((e) => [o.elements[e.from].attrs.id, e.fromLine, e.attr, e.token, e.to === null ? null : o.elements[e.to].attrs.id, e.toLine, e.dangling, e.duplicate, e.targets, e.selfReference]);
  assert.deepEqual(rows, [
    ['s', 6, 'aria-labelledby', 't', 't', 5, false, false, 1, false],
    ['s', 6, 'aria-labelledby', 't2', null, null, true, false, 0, false],
    ['s', 6, 'aria-describedby', 'note', 'note', 7, false, true, 3, false],
    ['l', 10, 'for', 'missing', null, null, true, false, 0, false],
    ['me', 11, 'aria-controls', 'me', 'me', 11, false, false, 1, true],
    ['q', 13, 'list', 'opts', 'opts', 13, false, false, 1, false],
  ]);
  assert.deepEqual(o.duplicateIds, [
    { id: 'note', count: 3, elementIds: o.elements.filter((e) => e.attrs.id === 'note').map((e) => e.id), lines: [7, 8, 9] },
    { id: 'dup2', count: 2, elementIds: o.elements.filter((e) => e.attrs.id === 'dup2').map((e) => e.id), lines: [14, 14] },
  ]);
  assert.equal(by('blank').attrs['aria-labelledby'], '  ');
});

// ---------------------------------------------------------------- parse errors

test('parseErrors: what set malformed, each with its line, code, tag and the elements left open (outermost first)', () => {
  const clean = parseHtml('<!doctype html><html><body><ul><li>a</li></ul><br><img src=x></body></html>', 'a.html');
  assert.deepEqual([clean.malformed, clean.parseErrors], [false, []]);
  const p = parseHtml(['<html>', '<body>', '</em>', '<table><tr><td>x</table>', '<dl><dt>a<dd>b</dl>', '<article><h3>t', '</body>', '</html>'].join('\n'), 'b.html');
  assert.equal(p.malformed, true);
  assert.deepEqual(p.parseErrors, [
    { line: 3, code: 'stray-end-tag', tag: 'em', unclosed: [] },
    { line: 4, code: 'misnested-end-tag', tag: 'table', unclosed: ['tr', 'td'] },
    { line: 5, code: 'misnested-end-tag', tag: 'dl', unclosed: ['dt', 'dd'] },
    { line: 7, code: 'misnested-end-tag', tag: 'body', unclosed: ['article', 'h3'] },
  ]);
  const open = parseHtml('<html>\n<body>\n<main>\n<p>never closed', 'c.html');
  assert.deepEqual(open.parseErrors, [{ line: 4, code: 'unclosed-at-end', tag: 'p', unclosed: ['html', 'body', 'main', 'p'] }]);
  const raw = parseHtml('<html><body>\n<style>p{}\n<p>after</p></body></html>', 'd.html');
  assert.deepEqual(raw.parseErrors, [{ line: 2, code: 'unclosed-raw-text', tag: 'style', unclosed: [] }]);
  // the observation carries the parser's list
  const { o } = page('<div><span>x</div>');
  assert.equal(o.malformed, true);
  assert.deepEqual(o.parseErrors, [{ line: 5, code: 'misnested-end-tag', tag: 'div', unclosed: ['span'] }]);
});

// ---------------------------------------------------------------- stylesheets and per-element CSS

function fixture() {
  const o = runHtmlIndex(FIXTURE, views).anchors[0].observation as PageObservation;
  const by = (id: string): ElementObs => o.elements.find((e) => e.attrs.id === id)!;
  const brief = (ds: ElementObs['css']['animation']) => ds.map((d) => [d.property, d.value, d.important, d.media, d.sheetMedia, d.inline, d.source.file, d.source.line, d.source.selector]);
  return { o, by, brief };
}

test('stylesheets: every sheet the page loads, in document order, with its media, line and whether it resolved; rules flattened are cssRules', () => {
  const { o } = fixture();
  assert.deepEqual(o.stylesheets.map((s) => [s.file, s.href, s.kind, s.line, s.media, s.resolved, s.parsed, s.rules.length]), [
    ['styles/base.css', 'styles/base.css', 'linked', 6, '', true, true, 9],
    ['styles/screen.css', 'styles/screen.css', 'linked', 7, 'screen and (min-width: 30em)', true, true, 2],
    ['styles/gone.css', 'styles/gone.css', 'linked', 8, '', false, false, 0],
    [null, 'https://cdn.example/theme.css', 'linked', 9, '', false, false, 0],
    ['index.html#style@10', null, 'inline', 10, 'print', true, true, 1],
  ]);
  assert.deepEqual(o.stylesheets.flatMap((s) => s.rules), o.cssRules);
});

test('element css: author declarations of the two families, lowest precedence first, each with its rule and conditions', () => {
  const { by, brief } = fixture();
  assert.deepEqual(brief(by('ticker').css.animation), [
    ['animation', 'scroll 20s linear infinite', false, '', '', false, 'styles/base.css', 1, '.ticker'],
    ['animation-duration', '40s', false, '(min-width: 40em)', '', false, 'styles/base.css', 8, '.ticker'],
    ['animation', 'none', false, '', 'print', false, 'index.html#style@10', 2, '.ticker'],
    // (1,1,0) beats (0,1,0) from any sheet; a vendor-prefixed property is the same family
    ['-webkit-animation', 'none', false, '', 'screen and (min-width: 30em)', false, 'styles/screen.css', 2, '#news .ticker'],
  ]);
  assert.deepEqual(by('ticker').css.textDecoration, []);
  // a child combinator, :not(), and !important after every normal declaration
  assert.deepEqual(brief(by('first').css.textDecoration), [
    ['text-decoration', 'line-through', false, '', 'screen and (min-width: 30em)', false, 'styles/screen.css', 1, 'li'],
    ['text-decoration-line', 'overline', false, '', '', false, 'styles/base.css', 2, '.menu > li'],
    ['text-decoration', 'none', true, '', '', false, 'styles/base.css', 6, 'li:not(.done)'],
  ]);
  assert.deepEqual(brief(by('done').css.textDecoration).map((d) => d[8]), ['li', '.menu > li']);
  // an inline style comes after the sheets' normal declarations, and before their !important ones
  assert.deepEqual(brief(by('plain-li').css.textDecoration), [
    ['text-decoration', 'line-through', false, '', 'screen and (min-width: 30em)', false, 'styles/screen.css', 1, 'li'],
    ['text-decoration', 'underline dotted', false, '', '', true, 'index.html', 17, null],
    ['text-decoration', 'none', true, '', '', false, 'styles/base.css', 6, 'li:not(.done)'],
  ]);
  // a selector list matches through either selector; :focus does not hold at rest
  assert.deepEqual(brief(by('spinner').css.animation).map((d) => [d[0], d[1], d[8]]), [['animation-name', 'spin', '.spinner, .loader'], ['animation-duration', '1s', '.spinner, .loader']]);
  // a pseudo-element's declarations style the pseudo-element, not the element
  assert.deepEqual(by('tag').css, { animation: [], textDecoration: [] });
  assert.deepEqual(by('quiet').css, { animation: [], textDecoration: [] });
});

test('element css: structural pseudo-classes, sibling combinators and attribute tests; an unevaluated selector is not listed', () => {
  const { by } = page(`<ul><li id="i1">a</li><li id="i2" data-k="x y">b</li><li id="i3">c</li></ul><a id="ln" href="/">l</a><a id="nolink">n</a>
<form><input id="cb" type="checkbox" checked disabled><input id="tx" required></form>`,
  `<style>
li:first-child { animation: a1; }
li:nth-child(2n+1) { animation: a2; }
li + li { animation: a3; }
li ~ li:last-of-type { animation: a4; }
[data-k~="y"] { animation: a5; }
a:link { text-decoration: underline; }
a:visited, a:hover { text-decoration: none; }
li:has(b) { animation: a6; }
:is(ul, ol) > li:where(#i3) { animation: a7; }
input:checked:disabled { animation: a8; }
input:required:enabled { animation: a9; }
:root body li:only-of-type { animation: a10; }
</style>`);
  const names = (id: string) => by(id).css.animation.map((d) => d.value);
  assert.deepEqual(names('i1'), ['a1', 'a2']);
  assert.deepEqual(names('i2'), ['a3', 'a5']);
  assert.deepEqual(names('i3'), ['a3', 'a7', 'a2', 'a4']);   // (0,0,2) twice in source order, then (0,1,1), then (0,1,2); :where() adds nothing
  assert.deepEqual(by('ln').css.textDecoration.map((d) => d.value), ['underline']);
  assert.deepEqual(by('nolink').css.textDecoration, []);
  assert.deepEqual(names('cb'), ['a8']);
  assert.deepEqual(names('tx'), ['a9']);
});

test('element css: a shadow tree\'s sheet styles only its tree, and the page\'s sheets do not reach into it', () => {
  const { by } = page(`<div id="host"><template shadowrootmode="open"><style>p { animation: inner; }</style><p id="in">in</p></template></div><p id="out">out</p>`,
    '<style>p { animation: outer; }</style>');
  assert.deepEqual(by('in').css.animation.map((d) => d.value), ['inner']);
  assert.deepEqual(by('out').css.animation.map((d) => d.value), ['outer']);
});
