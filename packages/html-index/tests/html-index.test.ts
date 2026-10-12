/** html-index: the W3C algorithms it applies, on small pages. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { decodeEntities, isUnder, runFileIndex, runHtmlIndex } from '../src/index.js';
import { views } from './fixtures/views.js';

function page(body: string) {
  const dir = mkdtempSync(join(tmpdir(), 'hi-'));
  writeFileSync(join(dir, 'index.html'), `<!doctype html><html lang="en"><head><title>t</title></head><body>${body}</body></html>`);
  const o = runHtmlIndex(dir, views, { idrefAttributes: ['aria-labelledby', 'for', 'headers', 'aria-owns'] }).anchors[0].observation as any;
  const by = (id: string) => o.elements.find((e: any) => e.attrs.id === id);
  return { o, by };
}

test('role: first ARIA 1.2 token of a fallback list; none of them valid → implicit role', () => {
  const { by } = page('<span id="a" role="doc-biblioref link">x</span><a id="b" href="#" role="doc-biblioref">y</a>');
  assert.deepEqual([by('a').explicitRole, by('a').effectiveRole], ['link', 'link']);
  assert.deepEqual([by('b').roleTokens, by('b').explicitRole, by('b').effectiveRole], [['doc-biblioref'], null, 'link']);
});

test('presentational role conflict: ignored on a focusable element, kept on a plain one', () => {
  const { by } = page('<button id="a" role="none"></button><img id="b" role="none" src="x.png"><a id="c" href="#" role="none"> </a>');
  assert.equal(by('a').effectiveRole, 'button');
  assert.equal(by('b').effectiveRole, 'none');
  assert.equal(by('c').effectiveRole, 'link');
});

test('accessible name: children\'s alt text, area alt, default submit/reset, placeholder last; alt=" " is not decorative', () => {
  const { by } = page(`<a id="a" href="#"><img src="w.png" alt="WAI"></a><map name="m"><area id="b" href="s.htm" alt="Sun"></map>
    <input id="c" type="reset"><input id="d" placeholder="Search"><img id="e" src="x.png" alt=" "><img id="f" src="x.png" alt="">`);
  assert.deepEqual([by('a').name, by('a').nameSource], ['WAI', 'contents']);
  assert.deepEqual([by('b').name, by('b').nameSource], ['Sun', 'alt']);
  assert.deepEqual([by('c').name, by('c').nameSource], ['Reset', 'default']);
  assert.deepEqual([by('d').name, by('d').nameSource], ['Search', 'placeholder']);
  assert.deepEqual([by('e').name, by('e').nameSource], ['', null]);
  assert.equal(by('f').nameSource, 'alt-empty');
});

test('name from content only for roles that allow it; <label> only labels labelable elements', () => {
  const { by } = page(`<div id="x"></div><select id="a" aria-labelledby="x"><option>England</option></select>
    <label for="b">first name</label><div id="b" role="textbox"></div><label for="c">Email</label><input id="c" type="email">`);
  assert.equal(by('a').name, '');
  assert.equal(by('b').name, '');
  assert.deepEqual([by('c').name, by('c').nameSource, by('c').visibleLabel], ['Email', 'label', true]);
});

test('a closed <dialog> and everything in it is hidden; an open one is not', () => {
  const { by } = page(`<dialog id="a" aria-labelledby="t"><h2 id="t">Seat</h2><button id="b"></button></dialog>
    <dialog id="c" open><button id="d">OK</button></dialog><p>A <dialog id="e"> opened by unescaped prose</p>`);
  assert.deepEqual(['a', 'b', 'e'].map((x) => by(x).hidden), [true, true, true]);
  assert.deepEqual(['c', 'd'].map((x) => by(x).hidden), [false, false]);
  assert.equal(by('a').name, 'Seat');   // the name is still computed; only the hidden fact changes
});

test('hasText: perceivable text in the subtree whatever the role; hidden children and empty boxes have none', () => {
  const { by } = page(`<div id="a" onclick="x()"><span>Search</span></div><div id="b" onclick="x()"></div>
    <div id="c"><span hidden>gone</span><img src="i.png" alt=""></div><div id="d"><img src="i.png" alt="Close"></div>`);
  assert.deepEqual(['a', 'b', 'c', 'd'].map((x) => by(x).hasText), [true, false, false, true]);
  assert.equal(by('a').name, '');   // a generic: no name from content
});

test('context role: the nearest meaningful ancestor; aria-owns re-parents', () => {
  const { by } = page(`<div role="list"><div role="tabpanel"><div id="a" role="listitem">1</div></div></div>
    <div role="list" aria-owns="b"></div><div><div id="b" role="listitem">2</div></div>
    <ul><li id="c">3</li></ul>`);
  assert.equal(by('a').contextRole, 'tabpanel');
  assert.equal(by('b').contextRole, 'list');
  assert.equal(by('c').contextRole, 'list');
});

test('headers IDREFs carry table structure; lang governs text only when it has its own text', () => {
  const { o } = page(`<table><tr><th id="h">P</th></tr></table><table><tr><td id="d" headers="h d">1</td></tr></table>
    <p lang="fr">bonjour</p><div lang="xx"><span lang="en">hello</span></div>`);
  const hs = o.idrefs.filter((r: any) => r.attr === 'headers');
  assert.deepEqual(hs.map((r: any) => [r.token, r.sameTable, r.selfReference]), [['h', false, false], ['d', true, true]]);
  assert.deepEqual(o.langAttributes.map((l: any) => [l.value, l.governsText]), [['fr', true], ['xx', false], ['en', true]]);
});

test('viewport meta translation and CSS rotation angles', async () => {
  const { rotationOf } = await import('../src/html-index.js');
  assert.equal(rotationOf({ transform: 'rotate(1.5708rad)' }), 90);
  assert.equal(rotationOf({ transform: 'matrix3d(0, -1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1)' }), 270);
  assert.equal(rotationOf({ rotate: '90deg' }), 90);
  assert.equal(rotationOf({ transform: 'rotateZ(1turn)' }), 0);
  assert.equal(rotationOf({ transform: 'rotateZ(0, 0, 1, 270deg)' }), null);
  const vp = (c: string) => page(`<meta name="viewport" content="${c}">`).o.viewport;
  assert.deepEqual([vp('user-scalable=0.5').userScalable, vp('user-scalable=invalid').userScalable, vp('user-scalable=yes').userScalable], [false, false, true]);
  assert.deepEqual([vp('maximum-scale=yes').maximumScale, vp('maximum-scale=invalid').maximumScale, vp('maximum-scale=-1').maximumScale, vp('maximum-scale=5.0').maximumScale], [1, 0.1, null, 5]);
});

test('linked stylesheets: read from inside the root only, and a sibling folder sharing its prefix is outside', () => {
  const base = mkdtempSync(join(tmpdir(), 'hi-css-'));
  const root = join(base, 'page');
  mkdirSync(join(root, 'css'), { recursive: true });
  mkdirSync(join(base, 'pageEvil'));
  writeFileSync(join(root, 'css', 'a.css'), '.in { color: red }');
  writeFileSync(join(base, 'pageEvil', 'x.css'), '.out { color: blue }');
  writeFileSync(join(root, 'index.html'), `<!doctype html><html lang="en"><head><title>t</title>
    <link rel="stylesheet" href="css/a.css"><link rel="stylesheet" href="../pageEvil/x.css"><link rel="stylesheet" href="/../pageEvil/x.css">
    </head><body></body></html>`);
  const o = runHtmlIndex(root, views).anchors[0].observation as any;
  assert.deepEqual(o.cssRules.map((r: any) => [r.file, r.selector]), [['css/a.css', '.in']]);
});

test('linked stylesheets: a symlink is followed, and one resolving outside the root or dangling is skipped', () => {
  const base = mkdtempSync(join(tmpdir(), 'hi-css-link-'));
  const root = join(base, 'page');
  mkdirSync(join(root, 'css'), { recursive: true });
  mkdirSync(join(base, 'outside'));
  writeFileSync(join(root, 'css', 'a.css'), '.in { color: red }');
  writeFileSync(join(base, 'outside', 'x.css'), '.out { color: blue }');
  symlinkSync(join(root, 'css', 'a.css'), join(root, 'inside.css'));
  symlinkSync(join(base, 'outside', 'x.css'), join(root, 'out.css'));
  symlinkSync(join(base, 'outside'), join(root, 'outdir'));
  symlinkSync(join(root, 'missing.css'), join(root, 'dangling.css'));
  writeFileSync(join(root, 'index.html'), `<!doctype html><html lang="en"><head><title>t</title>
    <link rel="stylesheet" href="inside.css"><link rel="stylesheet" href="out.css">
    <link rel="stylesheet" href="outdir/x.css"><link rel="stylesheet" href="dangling.css">
    </head><body></body></html>`);
  const o = runHtmlIndex(root, views).anchors[0].observation as any;
  assert.deepEqual(o.cssRules.map((r: any) => [r.file, r.selector]), [['inside.css', '.in']]);
  rmSync(base, { recursive: true, force: true });
});

test('isUnder: a path boundary, not a string prefix', () => {
  assert.equal(isUnder('/tmp/page', '/tmp/page'), true);
  assert.equal(isUnder('/tmp/page', '/tmp/page/a/b.css'), true);
  assert.equal(isUnder('/tmp/page/', '/tmp/page/a.css'), true);
  assert.equal(isUnder('/tmp/page', '/tmp/page/..x.css'), true);
  assert.equal(isUnder('/tmp/page', '/tmp/pageEvil/x.css'), false);
  assert.equal(isUnder('/tmp/page', '/tmp/page/../pageEvil/x.css'), false);
  assert.equal(isUnder('/tmp/page', '/tmp'), false);
  assert.equal(isUnder('/tmp/page', '/etc/passwd'), false);
});

test('directory walks follow a link only inside the root; outside, dangling and looping links are skipped', () => {
  const base = mkdtempSync(join(tmpdir(), 'walk-'));
  try {
    const root = join(base, 'site');
    mkdirSync(join(root, 'sub'), { recursive: true });
    mkdirSync(join(base, 'outside'));
    writeFileSync(join(root, 'index.html'), '<!doctype html><html lang="en"><head><title>home</title></head><body><p>home</p></body></html>');
    writeFileSync(join(root, 'sub', 'a.txt'), 'inside');
    writeFileSync(join(base, 'outside', 'secret.html'), '<!doctype html><title>secret</title><p>secret</p>');
    writeFileSync(join(base, 'outside', 'secret.txt'), 'secret');
    symlinkSync(join(base, 'outside'), join(root, 'out'));            // a folder outside the root
    symlinkSync(join(base, 'missing'), join(root, 'dangling'));        // nothing behind it
    symlinkSync(root, join(root, 'sub', 'loop'));                      // back up the tree
    symlinkSync(join(root, 'sub'), join(root, 'alias'));               // inside: followed

    const files = (runFileIndex(root, { pathPattern: '.' }).anchors[0].observation as any).files.map((f: any) => f.path).sort();
    assert.ok(files.includes('index.html') && files.includes('sub/a.txt'));
    assert.ok(files.includes('alias/a.txt'), 'a link that stays inside the root is followed');
    assert.ok(!files.some((f: string) => f.startsWith('out/')), `nothing outside the root: ${files.join(', ')}`);
    assert.ok(!files.some((f: string) => f.includes('loop/')), 'a link back up the tree does not loop');

    const pages = runHtmlIndex(root, views).anchors.map((a) => a.anchor);
    assert.ok(pages.includes('index.html'));
    assert.ok(!pages.some((p) => p.startsWith('out/')), `no page outside the root: ${pages.join(', ')}`);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('aria-labelledby names from a referenced node inside a hidden region or a closed dialog', () => {
  const { by } = page(
    '<div hidden><span id="l1"><b>Departure date</b></span></div><input id="a" aria-labelledby="l1">' +
    '<dialog><p id="l2"><em>Return date</em></p></dialog><input id="b" aria-labelledby="l2">' +
    '<span id="l3" hidden>Seat <i hidden>choice</i></span><input id="c" aria-labelledby="l3">' +
    '<button id="d">Go <span hidden>now</span></button>',
  );
  assert.equal(by('a').name, 'Departure date');
  assert.equal(by('b').name, 'Return date');
  assert.equal(by('c').name, 'Seat choice', 'a hidden referenced node counts with its hidden content (AccName 2A)');
  assert.equal(by('d').name, 'Go', 'hidden content inside an element named from content is still skipped');
});

test('name from content keeps document order when text and elements interleave', () => {
  const { by } = page('<a id="a" href="#">Read <em>more</em> about fares</a><span id="l"><b>Departure</b> date</span><input id="i" aria-labelledby="l"><button id="b"><img src="x.png" alt="Search"> flights</button>');
  assert.equal(by('a').name, 'Read more about fares');
  assert.equal(by('i').name, 'Departure date');
  assert.equal(by('b').name, 'Search flights');
});

/** a frame's document and a declarative shadow root are part of the page the user meets. */
function site(files: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), 'hi-frames-'));
  for (const [f, body] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), body); }
  const run = runHtmlIndex(dir, views, { idrefAttributes: ['aria-labelledby', 'for'] });
  return { dir, run, obs: (p: string) => run.anchors.find((a) => a.anchor === p)!.observation as any };
}
const DEFECT = '<main><div class="btn" onclick="void 0">Search flights</div><img src="../pixel.png"></main>';

test('frames: srcdoc and a same-origin src the tree holds are observed, nested ones too, each row carrying its frame', () => {
  const { dir, obs, run } = site({
    'd/srcdoc.html': `<!doctype html><html lang="en"><body><h1>Host</h1>\n<iframe title="w" srcdoc="<div class=&quot;btn&quot; onclick=&quot;void 0&quot;>Search flights</div> <img src=&quot;../pixel.png&quot;>"></iframe></body></html>`,
    'd/same.html': '<!doctype html><html lang="en"><body><h1 id="h">Host</h1><iframe title="w" src="./_payload.html"></iframe></body></html>',
    'd/nested.html': '<!doctype html><html lang="en"><body><iframe title="o" src="./_mid.html"></iframe></body></html>',
    'd/_mid.html': '<!doctype html><html lang="en"><body><h1>Mid</h1>\n\n<iframe title="i" src="./_payload.html"></iframe></body></html>',
    'd/_payload.html': `<!doctype html><html lang="en"><body>${DEFECT}</body></html>`,
  });
  try {
    for (const [page, frame] of [['d/srcdoc.html', 'iframe[srcdoc]@2'], ['d/same.html', 'iframe[src="./_payload.html"]@1'], ['d/nested.html', 'iframe[src="./_mid.html"]@1 >>> iframe[src="./_payload.html"]@3']] as const) {
      const o = obs(page);
      const div = o.elements.find((e: any) => e.tag === 'div' && e.pointerHandlers.length);
      const img = o.elements.find((e: any) => e.tag === 'img');
      assert.ok(div && img, `${page}: the frame's elements are in the page's observation`);
      assert.deepEqual([div.frame, img.frame, div.tabindex, img.nameSource], [frame, frame, null, null], page);
      // the page's own rows come first and keep their ids; nested ids follow, ancestors offset with them
      const host = o.elements.filter((e: any) => e.frame === null);
      assert.deepEqual(host.map((e: any) => e.id), host.map((_: any, i: number) => i));
      assert.ok(img.ancestorIds.every((a: number) => o.elements[a].frame === frame), `${page}: ancestors stay inside the frame's document`);
      assert.equal(new Set(o.elements.map((e: any) => e.id)).size, o.elements.length, 'no element twice');
      assert.ok(o.frames.every((f: any) => f.examined), JSON.stringify(o.frames));
    }
    assert.equal(obs('d/same.html').elements.find((e: any) => e.attrs.id === 'h').frame, null);
    // the digest covers the framed file: editing the payload changes the host's input digest
    const before = run.anchors.find((a) => a.anchor === 'd/same.html')!.inputDigest;
    writeFileSync(join(dir, 'd/_payload.html'), `<!doctype html><html lang="en"><body>${DEFECT}<p>x</p></body></html>`);
    assert.notEqual(runHtmlIndex(dir, views).anchors.find((a) => a.anchor === 'd/same.html')!.inputDigest, before);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('frames: an absolute URL, a missing file and a page that frames itself are recorded as not examined, with why', () => {
  const { dir, obs } = site({
    'index.html': '<!doctype html><html lang="en"><body><iframe src="https://example.com/w"></iframe><iframe src="nope.html"></iframe><iframe src="index.html"></iframe><iframe src="b.html"></iframe><iframe hidden srcdoc="<img src=x>"></iframe></body></html>',
    'b.html': '<!doctype html><html lang="en"><body><iframe src="index.html"></iframe></body></html>',
  });
  try {
    const o = obs('index.html');
    const why = o.frames.map((f: any) => [f.frame, f.examined, f.reason && f.reason.split(':')[0]]);
    assert.deepEqual(why.slice(0, 3), [
      ['iframe[src="https://example.com/w"]@1', false, 'an absolute URL'],
      ['iframe[src="nope.html"]@1', false, 'the subject tree does not hold this document'],
      ['iframe[src="index.html"]@1', false, 'the frame shows a document already open on this frame chain (a loop)'],
    ]);
    assert.ok(o.frames.some((f: any) => f.frame === 'iframe[src="b.html"]@1 >>> iframe[src="index.html"]@1' && !f.examined), 'a loop two frames deep stops');
    const img = o.elements.find((e: any) => e.tag === 'img');
    assert.equal(img.hidden, true, 'content of a hidden frame is hidden');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('declarative shadow DOM: the shadow tree is observed, marked inShadow, and names its host from content', () => {
  const { by, o } = page('<p id="l">light</p><x-btn id="host" role="button"><template shadowrootmode="open"><img id="i" src="p.png"><span id="s">Book</span></template></x-btn>');
  assert.deepEqual(['i', 's'].map((x) => by(x).inShadow), [true, true]);
  assert.deepEqual(['l', 'host'].map((x) => by(x).inShadow), [false, false]);
  assert.equal(by('host').name, 'Book');
  assert.equal(by('i').frame, null);
  assert.deepEqual(o.frames, []);
});

test('cssRules: a nested document\'s sheets are indexed, each rule scoped to its own document or shadow tree', () => {
  const { dir, obs, run } = site({
    'd/host.html': '<!doctype html><html lang="en"><head><style>.page { rotate: 90deg }</style></head><body><h1>Host</h1>\n<iframe title="w" src="./_inner.html"></iframe>\n<iframe title="s" srcdoc="<style>.doc { color: red }</style><p class=&quot;doc&quot;>x</p>"></iframe>\n<x-w id="host"><template shadowrootmode="open"><style>.btn { cursor: pointer }</style><div class="btn">Go</div></template></x-w></body></html>',
    'd/_inner.html': '<!doctype html><html lang="en"><head><link rel="stylesheet" href="inner.css"><style>.own { color: blue }</style></head><body><x-i><template shadowrootmode="open"><style>.deep { color: green }</style></template></x-i></body></html>',
    'd/inner.css': '@media (orientation: portrait) { .framed { transform: rotate(90deg) } }',
  });
  try {
    const o = obs('d/host.html');
    const inner = 'iframe[src="./_inner.html"]@2';
    const hostOf = (r: any) => (r.shadowHost === null ? null : o.elements[r.shadowHost].tag);
    assert.deepEqual(o.cssRules.map((r: any) => [r.selector, r.file, r.frame, hostOf(r)]), [
      // the page's own rows first, the shadow sheet says whose it is
      ['.page', 'd/host.html#style@1', null, null],
      ['.btn', 'd/host.html#style@4', null, 'x-w'],
      // then each frame document's, in frame order, never as a rule of the outer page
      ['.framed', 'd/inner.css', inner, null],
      ['.own', 'd/_inner.html#style@1', inner, null],
      ['.deep', 'd/_inner.html#style@1', inner, 'x-i'],
      ['.doc', 'd/host.html#srcdoc@3#style@1', 'iframe[srcdoc]@3', null],
    ]);
    // a shadow host id points into the page's `elements`, offset like every nested element id
    const deep = o.cssRules.find((r: any) => r.selector === '.deep');
    assert.equal(o.elements[deep.shadowHost].frame, inner);
    assert.deepEqual([o.cssRules[2].media, o.cssRules[2].rotation], ['(orientation: portrait)', 90]);
    // the frame's own observation is unchanged: there its rules are document-level
    assert.deepEqual(obs('d/_inner.html').cssRules.map((r: any) => [r.selector, r.frame]), [['.framed', null], ['.own', null], ['.deep', null]]);
    // a frame document's linked sheet is read, so it is part of the page's input digest
    const before = run.anchors.find((a) => a.anchor === 'd/host.html')!.inputDigest;
    writeFileSync(join(dir, 'd/inner.css'), '.framed { color: red }');
    assert.notEqual(runHtmlIndex(dir, views).anchors.find((a) => a.anchor === 'd/host.html')!.inputDigest, before);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('cssRules couldMatch: 0 when no element of the rule\'s own document can be its subject; escapes decoded; never under-counted', () => {
  const { dir, obs } = site({
    'd/page.html': `<!doctype html><html lang="en"><head><style>
.animate-spin { animation: spin 1s linear infinite }
.animate-ping { animation: ping 1s infinite }
.md\\:animate-pulse { animation: pulse 2s infinite }
.lg\\:animate-bounce { animation: bounce 1s infinite }
.\\31 0s { animation: a 10s infinite }
.framed-only { animation: f 1s infinite }
nav .loader::after, .gone { animation: l 1s infinite }
.card:not(.quiet) > [data-state="open" i] { animation: s 1s infinite }
[data-state=closed] { animation: s 1s infinite }
main p.note#n1 { animation: s 1s infinite }
main p.note#n2 { animation: s 1s infinite }
:root, .nothing { animation: bg 9s infinite }
ul > li:is(.a, .b) { animation: s 1s infinite }
@keyframes spin { to { transform: rotate(360deg) } }
</style></head><body><main>
<div class="other animate-ping">ping</div><p class="md:animate-pulse">pulse</p><b class="10s">ten</b>
<span class="LOADER"></span><div data-state="OPEN">open</div><p class="note" id="n1">note</p>
<iframe title="f" srcdoc="<style>.inner { animation: i 1s infinite } .animate-ping { color: red }</style><p class=&quot;framed-only inner&quot;>x</p>"></iframe>
</main></body></html>`,
  });
  try {
    const o = obs('d/page.html');
    const own = Object.fromEntries(o.cssRules.filter((r: any) => r.frame === null).map((r: any) => [r.selector.replace(/\s+/g, ' '), r.couldMatch]));
    const all = o.elements.filter((e: any) => e.frame === null).length;
    assert.deepEqual(own, {
      '.animate-spin': 0,                       // the Tailwind utility nothing uses
      '.animate-ping': 1,
      '.md\\:animate-pulse': 1,                 // the class is `md:animate-pulse` in the markup
      '.lg\\:animate-bounce': 0,
      '.\\31 0s': 1,                            // a hex escape: the class `10s`
      '.framed-only': 0,                        // only an element of the FRAME carries it, and a page rule does not reach it
      'nav .loader::after, .gone': 1,           // the last compound only (no <nav> is needed), a pseudo-element's originating element, classes without case
      '.card:not(.quiet) > [data-state="open" i]': 1,
      '[data-state=closed]': 0,
      'main p.note#n1': 1,
      'main p.note#n2': 0,
      ':root, .nothing': all,                   // a compound with nothing this reads constrains nothing
      'ul > li:is(.a, .b)': 0,                  // no <li> at all; the pseudo-class adds no constraint of its own
      to: 0,                                    // a keyframe selector is no element
    });
    // a frame document's rules are counted against the frame's own elements
    assert.deepEqual(o.cssRules.filter((r: any) => r.frame !== null).map((r: any) => [r.selector, r.couldMatch]), [['.inner', 1], ['.animate-ping', 0]]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('nthOfType: the position among same-tag siblings, null for an only child of its tag; ancestors in parallel', () => {
  const { by } = page('<p id="p"><span id="s1"><img id="a" src="d.png"></span><b>x</b><span id="s2"><img id="b" src="d.png"></span></p><p id="q"></p>');
  assert.deepEqual(['s1', 's2', 'a', 'b', 'p', 'q'].map((x) => by(x).nthOfType), [1, 2, null, null, 1, 2]);
  assert.deepEqual(by('b').ancestorTags, ['span', 'p', 'body', 'html']);
  assert.deepEqual(by('b').ancestorNthOfType, [2, 1, null, null]);
  assert.deepEqual(by('a').ancestorNthOfType, [1, 1, null, null]);
});

test('decodeEntities: the references a serialized srcdoc carries', () => {
  assert.equal(decodeEntities('&lt;a href=&quot;x&quot;&gt;&amp;&#39;&#x41;&nope;'), '<a href="x">&\'A&nope;');
});

test('texts: one row per rendered element with a text run of its own, with its subtree\'s text; not code, the title, a field value or hidden text', () => {
  const { o, by } = page(`<p id="a">Fields marked <span id="b" class="req">*</span> are required.</p>
    <div id="c"><label id="d" for="f">Name <abbr id="e" title="required">*</abbr></label><input id="f"></div>
    <p id="g" hidden>Hidden <b>text</b></p><textarea id="h">a default value</textarea><script>var s = "* required";</script>
    <p id="i">Read <img src="i.png" alt="the terms"> first.</p>`);
  const rows = o.texts.map((t: any) => [o.elements[t.elementId].attrs.id ?? o.elements[t.elementId].tag, t.text]);
  assert.deepEqual(rows, [
    ['a', 'Fields marked * are required.'], ['b', '*'],   // the sentence is whole on the element that holds it
    ['d', 'Name *'], ['e', '*'],                          // #c has no text run of its own: no second copy
    ['i', 'Read the terms first.'],
  ]);
  assert.equal(o.texts.find((t: any) => t.elementId === by('a').id).line, by('a').line);
});

test('labelInName: the visible text as the markup gives it, beside the name, as normalised keys', () => {
  const { by } = page(`<style>.sr{clip-path:inset(50%)} button.ico{font-family:"Material Icons"} @media print{.np{display:none}} [hidden]{display:none!important} [data-state="closed"]{display:none} a[href^="mailto:"] span.late{visibility:hidden}</style>
    <button id="a" aria-label="Submit">Search  flights</button>
    <button id="b" aria-label="how are you"><span>you</span><span>how</span><span>are</span></button>
    <a id="c" href="#" aria-label="Download specification"><span>Download</span><span> </span><span>specification</span></a>
    <button id="d" aria-label="Hello world"><p>Hello</p><p>world</p></button>
    <a id="e" href="#" aria-label="ABC"><div style="display: inline">A</div><div style="display: inline">B</div><div style="display: inline">C</div></a>
    <a id="f" href="#" aria-label="Download specification">Download <span style="visibility: hidden">the</span> <span hidden>gizmo</span> specification</a>
    <a id="g" href="#" aria-label="Download specification">Download <span aria-hidden="true">gizmo</span> specification</a>
    <a id="h" href="#" aria-label="Read more">Read more <span class="sr">about bags</span></a>
    <button id="i" class="ico" aria-label="Find">search</button>
    <button id="j" aria-label="Search by date">Search by date (YYYY-MM-DD)</button>
    <button id="k" aria-label="Submit">&gt;&gt; ** Submit ** &raquo;</button>
    <a id="l" href="#" aria-label="University Avenue">University Ave.</a>
    <a id="m" href="#" aria-label="non-standard">nonstandard</a>
    <a id="n" href="#" aria-label="1 2 3. 5 5 5. 0 1 2 3">123.555.0123</a>
    <button id="o" aria-label="Caf&eacute; menu">Caf&eacute;</button>
    <button id="p" class="np" aria-label="Print">Print page</button>
    <button id="q">Plain</button>
    <a id="r" href="mailto:x@example.com" aria-label="Write to us">Write <span class="late">now</span></a>
    <button id="s" data-state="closed" aria-label="Open menu">Menu</button>`);
  const L = (id: string) => by(id).labelInName;
  assert.equal(by('q').labelInName, null, 'null without aria-label or aria-labelledby');
  assert.deepEqual([L('a').visibleText, L('a').labelKey, L('a').nameKey], ['Search flights', ' search flights ', ' submit ']);
  assert.equal(L('b').labelKey, ' youhoware ', 'inline children are not word boundaries');
  assert.equal(L('c').labelKey, ' download specification ', 'white space alone between inline children is a word boundary');
  assert.equal(L('d').labelKey, ' hello world ', 'block children are');
  assert.equal(L('e').labelKey, ' abc ', 'an inline display in the style attribute is inline');
  assert.equal(L('f').labelKey, ' download specification ', 'content the markup hides is not visible text');
  assert.equal(L('g').labelKey, ' download gizmo specification ', 'aria-hidden content is still on screen');
  assert.deepEqual(L('h').styleRisks.map((r: any) => [r.kind, r.on]), [['hides', 'descendant']]);
  assert.deepEqual(L('i').styleRisks.map((r: any) => [r.kind, r.on, r.detail]), [['font', 'self', '"Material Icons"']]);
  assert.equal(L('j').labelKey, ' search by date ', 'text in round brackets is removed');
  assert.equal(L('k').labelKey, ' submit ', 'punctuation is a space; the references a label carries are decoded');
  assert.deepEqual([L('l').abbreviated, L('a').abbreviated, L('n').abbreviated], [true, false, false], 'a number before a full stop is not an abbreviation');
  assert.deepEqual([L('m').labelKey === L('m').nameKey, L('m').labelKeyDehyphenated === L('m').nameKeyDehyphenated], [false, true]);
  assert.deepEqual(L('o').styleRisks.map((r: any) => r.kind), ['unresolved-entity']);
  assert.deepEqual(L('p').styleRisks, [], 'a print-only rule does not hide anything on screen');
  assert.deepEqual(L('a').styleRisks, [], 'an attribute selector is tested against the element: [hidden] does not match what is not hidden');
  assert.deepEqual(L('r').styleRisks.map((r: any) => [r.kind, r.on]), [['hides', 'descendant']], 'the last compound is the span; the link it descends from is not evaluated');
  assert.deepEqual(L('s').styleRisks.map((r: any) => [r.kind, r.on]), [['hides', 'self']]);
  assert.deepEqual([L('a').labelWordCharacters, L('n').labelDigits], [13, 10]);
});

test('labelInName: a linked stylesheet the tree does not hold is a risk on the children it could hide', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hi-'));
  try {
    writeFileSync(join(dir, 'index.html'), '<!doctype html><html lang="en"><head><title>t</title><link rel="stylesheet" href="https://cdn.example/x.css"></head><body><a id="a" href="#" aria-label="Read more">Read more <span class="x">about bags</span></a><button id="b" aria-label="Go">Search</button></body></html>');
    const o = runHtmlIndex(dir, views, {}).anchors[0].observation as any;
    const L = (id: string) => o.elements.find((e: any) => e.attrs.id === id).labelInName;
    assert.deepEqual(L('a').styleRisks.map((r: any) => [r.kind, r.on]), [['unread-stylesheet', 'descendant']]);
    assert.deepEqual(L('b').styleRisks.map((r: any) => [r.kind, r.on]), [['unread-stylesheet', 'self']]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
