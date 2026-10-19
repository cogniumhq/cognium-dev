/** The observation fields added in schema 0.3, and the accessible-name fixes, on pages written for these tests. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { handlerFamily, runHtmlIndex, SCHEMA_VERSION, type ElementObs, type HtmlIndexParams, type PageObservation } from '../src/index.js';
import { markupHandlers } from './fixtures/markup-handlers.js';
import { views } from './fixtures/views.js';

const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), 'fixtures/fields-0.3');

function site(root: string, params: HtmlIndexParams = { markupHandlers }) {
  const run = runHtmlIndex(root, views, params);
  const pages = new Map(run.anchors.map((a) => [a.anchor, a.observation as PageObservation]));
  const on = (page: string) => {
    const o = pages.get(page)!;
    return { o, by: (id: string): ElementObs => o.elements.find((e) => e.attrs.id === id)! };
  };
  return { run, on };
}

function page(body: string, head = '') {
  const dir = mkdtempSync(join(tmpdir(), 'hi03-'));
  try {
    writeFileSync(join(dir, 'index.html'), `<!doctype html>\n<html lang="en">\n<head><title>t</title>${head}</head>\n<body>\n${body}\n</body>\n</html>\n`);
    return site(dir).on('index.html');
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

test('schema 0.3', () => {
  assert.equal(SCHEMA_VERSION, '0.3');
  assert.equal(site(FIXTURE).run.schemaVersion, '0.3');
});

// ---------------------------------------------------------------- inline handlers

test('inlineHandlers: every event handler content attribute, in source order, with its event and family; an unknown on* is not one', () => {
  const { by } = site(FIXTURE).on('inline.html');
  const brief = (id: string) => by(id).inlineHandlers.map((h) => [h.attr, h.event, h.handlerFamily]);
  assert.deepEqual(brief('card'), [['onkeydown', 'keydown', 'key'], ['onclick', 'click', 'pointer'], ['onmouseenter', 'mouseenter', 'pointer']]);
  assert.deepEqual(brief('qty'), [['oninput', 'input', 'input'], ['onchange', 'change', 'input'], ['onfocus', 'focus', 'focus'], ['onblur', 'blur', 'focus']]);
  assert.deepEqual(brief('touch'), [['ontouchstart', 'touchstart', 'pointer'], ['onpointerdown', 'pointerdown', 'pointer'], ['ondragstart', 'dragstart', 'pointer']]);
  assert.deepEqual(brief('f'), [['onsubmit', 'submit', 'input'], ['onreset', 'reset', 'input']]);
  assert.deepEqual(brief('pic'), [['onclick', 'click', 'pointer']]);   // an SVG element has the global handlers too
  assert.deepEqual(brief('plain'), []);
  // the 0.2 lists are unchanged beside it
  assert.deepEqual([by('card').pointerHandlers, by('card').keyHandlers], [['onclick'], ['onkeydown']]);
});

test('inlineHandlers: window handlers count on <body> only; a legacy animation handler listens for its own event type', () => {
  const { by } = site(FIXTURE).on('inline.html');
  const body = by('card').ancestorIds.map((i) => site(FIXTURE).on('inline.html').o.elements[i]).find((e) => e.tag === 'body')!;
  assert.deepEqual(body.inlineHandlers.map((h) => [h.attr, h.handlerFamily]), [['onload', 'other'], ['onunload', 'other']]);
  assert.deepEqual(by('anim').inlineHandlers.map((h) => [h.attr, h.event]), [['onwebkitanimationend', 'webkitAnimationEnd'], ['onanimationend', 'animationend']]);
});

test('handlerFamily: by event type, case-insensitive; an unknown or absent event is other', () => {
  assert.deepEqual(['click', 'MouseDown', 'pointermove', 'touchend', 'wheel', 'keypress', 'focusin', 'beforeinput', 'scroll', 'tap', null].map(handlerFamily),
    ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'key', 'focus', 'input', 'other', 'other', 'other']);
});

// ---------------------------------------------------------------- markup handlers

test('markupHandlers: Vue and Alpine handler attributes in a prerender, with the event the name states', () => {
  const vue = site(FIXTURE).on('prerender-vue.html');
  const brief = (e: ElementObs) => e.markupHandlers.map((h) => [h.attr, h.framework, h.event, h.handlerFamily]);
  assert.deepEqual(brief(vue.by('row')), [['@click.prevent', 'vue', 'click', 'pointer'], ['@keyup.enter', 'vue', 'keyup', 'key']]);
  assert.deepEqual(brief(vue.by('item')), [['v-on:click', 'vue', 'click', 'pointer'], ['v-on:keydown.space.prevent', 'vue', 'keydown', 'key']]);
  assert.deepEqual(brief(vue.by('vbind')), []);   // a binding is not a handler
  const alpine = site(FIXTURE).on('alpine.html');
  // `@…` is the Vue row, the first that matches: the table decides, not the engine
  assert.deepEqual(brief(alpine.by('menu')), [['x-on:click.outside', 'alpine', 'click', 'pointer'], ['@keydown.escape.window', 'vue', 'keydown', 'key']]);
  assert.deepEqual(brief(alpine.by('toggle')), [['x-on:click', 'alpine', 'click', 'pointer'], ['x-on:focus', 'alpine', 'focus', 'focus']]);
});

test('markupHandlers: Angular event bindings left in a prerender; property bindings are not handlers', () => {
  const { by } = site(FIXTURE).on('prerender-angular.html');
  assert.deepEqual(by('tile').markupHandlers.map((h) => [h.attr, h.event]), [['(click)', 'click'], ['(keydown.enter)', 'keydown']]);
});

test('markupHandlers: events read from a value (htmx triggers, declarative actions), one row each; none in the value is null', () => {
  const htmx = site(FIXTURE).on('htmx.html');
  assert.deepEqual(htmx.by('search').markupHandlers.map((h) => [h.attr, h.framework, h.event]), [['hx-post', 'htmx', null], ['hx-trigger', 'htmx', 'keyup'], ['hx-trigger', 'htmx', 'search']]);
  assert.deepEqual(htmx.by('more').markupHandlers.map((h) => [h.attr, h.event]), [['hx-get', null]]);
  const act = site(FIXTURE).on('declarative-action.html');
  assert.deepEqual(act.by('dd').markupHandlers.map((h) => [h.attr, h.framework, h.event, h.handlerFamily]), [['data-action', 'stimulus', 'click', 'pointer'], ['data-action', 'stimulus', 'keydown', 'key']]);
  assert.deepEqual(act.by('bare').markupHandlers.map((h) => [h.attr, h.event, h.handlerFamily]), [['data-action', null, 'other']]);
  assert.deepEqual(act.by('other').markupHandlers, []);
});

test('markupHandlers: the engine knows no framework — with no table, no element has any; a pattern that does not compile is refused', () => {
  const { on } = site(FIXTURE, {});
  for (const p of ['prerender-vue.html', 'alpine.html', 'prerender-angular.html', 'htmx.html', 'declarative-action.html']) assert.ok(on(p).o.elements.every((e) => e.markupHandlers.length === 0), p);
  assert.throws(() => site(FIXTURE, { markupHandlers: [{ framework: 'broken', attr: '(' }] }), /markupHandlers\[0\] \(broken\)/);
});

// ---------------------------------------------------------------- declared cursor

test('css.cursor: the element\'s own declarations, lowest precedence first, each with its rule and conditions', () => {
  const { by } = site(FIXTURE).on('cursor.html');
  const brief = (id: string) => by(id).css.cursor.map((d) => [d.value, d.source.selector, d.source.line, d.media, d.sheetMedia, d.inline, d.inherited]);
  // the same sheet linked twice, the second for print: both listed, the condition stated, not evaluated
  assert.deepEqual(brief('c1'), [['pointer', '.card', 1, '', '', false, false], ['pointer', '.card', 1, '', 'print', false, false]]);
  // specificity first: `.card.disabled` outranks `.card`; `:hover` does not hold at rest
  assert.deepEqual(brief('c2').map((d) => [d[0], d[1], d[4]]), [['pointer', '.card', ''], ['pointer', '.card', 'print'], ['not-allowed', '.card.disabled', ''], ['not-allowed', '.card.disabled', 'print']]);
  assert.deepEqual(brief('row'), [['pointer', '.row', 7, '(pointer: fine)', '', false, false], ['pointer', '.row', 7, '(pointer: fine)', 'print', false, false]]);
  assert.deepEqual(brief('inl'), [['help', null, by('inl').line, '', '', true, false]]);
  assert.equal(by('c1').css.cursor[0].source.file, 'styles/cursor.css');
  assert.equal(by('c1').css.cursor[0].from, by('c1').id);
});

test('css.cursor: inherited from the nearest ancestor that declares one, flagged, with the ancestor it comes from; none from the user agent', () => {
  const { by } = site(FIXTURE).on('cursor.html');
  for (const id of ['li1', 'deep']) {
    assert.deepEqual(by(id).css.cursor.map((d) => [d.value, d.source.selector, d.inherited, d.from]), [['pointer', '.list', true, by('list').id], ['pointer', '.list', true, by('list').id]], id);
  }
  assert.deepEqual(by('li2').css.cursor.map((d) => [d.value, d.source.selector, d.inherited]), [['default', '.list .quiet', false], ['default', '.list .quiet', false]]);
  assert.deepEqual(by('link').css.cursor, []);
  assert.deepEqual(by('none').css.cursor, []);
  // the 0.2 families are unchanged beside it
  assert.deepEqual([by('c1').css.animation, by('c1').css.textDecoration], [[], []]);
});

test('css.cursor: an element of a nested frame names its ancestor by its id in the page', () => {
  const { by, o } = page('<iframe id="fr" srcdoc="&lt;style&gt;.z{cursor:pointer}&lt;/style&gt;&lt;div class=&quot;z&quot; id=&quot;outer&quot;&gt;&lt;span id=&quot;inner&quot;&gt;x&lt;/span&gt;&lt;/div&gt;"></iframe>');
  const inner = by('inner'), outer = by('outer');
  assert.ok(inner.frame && outer.id > by('fr').id);
  assert.deepEqual(inner.css.cursor.map((d) => [d.value, d.inherited, d.from]), [['pointer', true, outer.id]]);
  assert.equal(o.elements[inner.css.cursor[0].from].attrs.id, 'outer');
});

// ---------------------------------------------------------------- accessible names (WPT accname fixes)

test('name: a control embedded in another widget\'s label contributes its value (AccName 1.2 step 2C)', () => {
  const { by } = page(`<label><input id="cb" type="checkbox"> Flash the screen <input value="3" aria-label="number of times"> times</label>
<label><input id="cb2" type="checkbox"> Flash <select><option>1</option><option selected>2</option></select> times</label>
<label><input id="cb3" type="checkbox"> Flash <select><option>4</option><option>5</option></select> times</label>
<label><input id="cb4" type="checkbox"> Pick <ul role="listbox"><li role="option">a</li><li role="option" aria-selected="true">b</li></ul></label>
<label><input id="cb5" type="checkbox"> Level <span role="slider" aria-valuenow="7" aria-valuetext="seven">7.0</span></label>
<label><input id="cb6" type="checkbox"> Level <span role="spinbutton" aria-valuenow="7">7.0</span></label>
<label><input id="cb7" type="checkbox"> Level <input type="range" min="0" max="10"></label>
<label><input id="cb8" type="checkbox"> Flash <span role="menu"><span role="menuitem">1</span></span> times</label>
<label><input id="cb9" type="checkbox"> Flash <span role="combobox" aria-label="count">9</span> times</label>`);
  assert.equal(by('cb').name, 'Flash the screen 3 times');     // the value, before the embedded field's own aria-label
  assert.equal(by('cb2').name, 'Flash 2 times');                 // a select's chosen option
  assert.equal(by('cb3').name, 'Flash 4 times');                 // a drop-down with none marked shows its first
  assert.equal(by('cb4').name, 'Pick b');
  assert.equal(by('cb5').name, 'Level seven');
  assert.equal(by('cb6').name, 'Level 7');
  assert.equal(by('cb7').name, 'Level 5');                       // a range's default value is its midpoint
  assert.equal(by('cb8').name, 'Flash times');
  assert.equal(by('cb9').name, 'Flash 9 times');
});

test('name: a label leaves out the control it labels; aria-labelledby reads a referenced control\'s value or label', () => {
  const { by } = page(`<label>Email <input id="em" type="email" value="a@b.c"></label>
<label for="t">Note <textarea id="t">draft text</textarea></label>
<input id="first" value="Ada"><input id="last" value="Lovelace"><img id="who" src="x.png" aria-labelledby="first last">
<label><input id="ok" type="checkbox"> Accept terms</label><button id="b" aria-labelledby="ok">Toggle</button>`);
  assert.equal(by('em').name, 'Email');
  assert.equal(by('t').name, 'Note');
  assert.equal(by('who').name, 'Ada Lovelace');
  assert.equal(by('b').name, 'Accept terms');
});

test('name: character references decoded; a no-break space kept, only ASCII white space collapsed', () => {
  const { by } = page(`<button id="a">Fish&nbsp;&amp;&nbsp;chips</button><button id="b" aria-label="&nbsp;Menu">x</button>
<a id="c" href="/">Two&nbsp;&nbsp;&nbsp;spaces</a><img id="d" src="x.png" alt="line
break">`);
  assert.equal(by('a').name, 'Fish & chips');
  assert.equal(by('b').name, ' Menu');
  assert.equal(by('c').name, 'Two   spaces');
  assert.equal(by('d').name, 'line break');
});

test('name: text-level children join with no space; a block, a <br>, white space between tags, an author display:block or an absolutely positioned child is a word boundary', () => {
  const { by } = page(`<button id="a">one<span>two</span><b>three</b></button>
<button id="b">one<div>two</div>three</button>
<a id="c" href="/">one<br>two</a>
<button id="d"><span>one</span> <span>two</span></button>
<button id="e" class="stack"><span>one</span><span>two</span></button>
<button id="f"><span style="display:inline-block">one</span><span>two</span></button>
<h2 id="g">Price<!-- -->less</h2>
<button id="h">Alerts<span class="badge">3</span></button>
<button id="i">Alerts<span class="tip">3</span></button>`, '<style>.stack > span { display: block } .badge { position: absolute } .tip { position: relative }</style>');
  assert.equal(by('a').name, 'onetwothree');
  assert.equal(by('b').name, 'one two three');
  assert.equal(by('c').name, 'one two');
  assert.equal(by('d').name, 'one two');
  assert.equal(by('e').name, 'one two');
  assert.equal(by('f').name, 'one two');
  assert.equal(by('g').name, 'Priceless');
  assert.equal(by('h').name, 'Alerts 3');     // absolute positioning makes the badge a block (CSS 2.1 §9.7)
  assert.equal(by('i').name, 'Alerts3');
});

test('texts and hasText read as in 0.2: the name fixes do not move them', () => {
  const { o, by } = page('<p id="p">one<b>two</b>&nbsp;three <input value="v"></p>');
  assert.equal(o.texts.find((t) => t.elementId === by('p').id)!.text, 'one two &nbsp;three');
  assert.equal(by('p').hasText, true);
});
