#!/usr/bin/env node
/**
 * Baseline, not a gate: the web-platform-tests `accname/` expectations, read statically.
 *
 *   npm run build
 *   node bench/wpt-accname.mjs --wpt <wpt checkout> --aria <aria views.json> --html <html-aria views.json> [--json <out>]
 *
 * WPT runs these tests in a browser and asks the accessibility tree for each element's computed
 * name. This reads the same files as text: no script runs, no stylesheet is applied, no pseudo-element
 * or counter exists. A test whose subject only exists after script ran, or whose expectation is not a
 * name, is "not applicable"; every other expectation is compared with the `name` this package computes.
 *
 * Cases:
 *  - automated tests: each element carrying `data-expectedlabel` is one case;
 *  - manual tests: each step that states the expected name of an element (by id) is one case.
 *
 * The tables are inputs (see the README); the numbers depend on them and on the WPT commit, so quote
 * both with any result.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { decodeEntities, runHtmlIndex, DRIVER } from '../dist/index.js';

const arg = (k) => { const i = process.argv.indexOf(k); return i >= 0 ? process.argv[i + 1] : undefined; };
const wpt = arg('--wpt'), ariaFile = arg('--aria'), htmlFile = arg('--html');
if (!wpt || !ariaFile || !htmlFile) {
  console.error('usage: node bench/wpt-accname.mjs --wpt <wpt checkout> --aria <views.json> --html <views.json> [--json <out>]');
  process.exit(2);
}
const views = { aria: JSON.parse(readFileSync(ariaFile, 'utf8')), html: JSON.parse(readFileSync(htmlFile, 'utf8')) };
const root = join(wpt, 'accname');
let commit = 'unknown';
try { commit = execFileSync('git', ['-C', wpt, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(); } catch { /* not a git checkout */ }

/** the object literal passed to the manual harness, or null */
function manualSteps(raw) {
  const at = raw.indexOf('new ATTAcomm(');
  if (at < 0) return null;
  const open = raw.indexOf('{', at);
  let depth = 0, inStr = false;
  for (let i = open; i < raw.length; i++) {
    const c = raw[i];
    if (inStr) { if (c === '\\') i++; else if (c === '"') inStr = false; continue; }
    if (c === '"') inStr = true;
    else if (c === '{') depth++;
    else if (c === '}' && --depth === 0) {
      try { return JSON.parse(raw.slice(open, i + 1)).steps ?? null; } catch { return null; }
    }
  }
  return null;
}

/** the expected name a manual step states, or undefined when it states none (a description, a role) */
function expectedName(step) {
  for (const row of step?.test?.ATK ?? []) if (row[0] === 'property' && row[1] === 'name' && row[2] === 'is') return row[3];
  return undefined;
}

const cases = [];
const add = (file, kind, id, expected, actual, na) => cases.push({ file, kind, id, expected, actual, result: na ? 'n/a' : expected === actual ? 'pass' : 'fail', why: na ?? null });

for (const a of runHtmlIndex(root, views).anchors) {
  const o = a.observation;
  const own = o.elements.filter((e) => e.frame === null);
  const kind = a.anchor.startsWith('manual/') ? 'manual' : 'automated';
  let found = 0;
  if (kind === 'automated') {
    for (const e of own) {
      if (!('data-expectedlabel' in e.attrs)) continue;
      found++;
      add(a.anchor, kind, e.attrs['data-testname'] ?? `line ${e.line}`, decodeEntities(e.attrs['data-expectedlabel']), e.name, null);
    }
    if (!found) add(a.anchor, kind, '(file)', null, null, 'no element with an expected name in the markup: built by script, or a support file');
  } else {
    const steps = manualSteps(readFileSync(join(root, a.anchor), 'utf8'));
    for (const s of steps ?? []) {
      if (s.type !== 'test') continue;
      found++;
      const want = expectedName(s);
      if (want === undefined) { add(a.anchor, kind, s.element, null, null, 'the step expects something other than a name'); continue; }
      const e = own.find((x) => x.attrs.id === s.element);
      if (!e) { add(a.anchor, kind, s.element, want, null, 'the element is not in the markup'); continue; }
      add(a.anchor, kind, s.element, want, e.name, null);
    }
    if (!found) add(a.anchor, kind, '(file)', null, null, 'no test step read');
  }
}

cases.sort((x, y) => (x.file < y.file ? -1 : x.file > y.file ? 1 : 0));
const tally = (cs) => ({ pass: cs.filter((c) => c.result === 'pass').length, fail: cs.filter((c) => c.result === 'fail').length, 'n/a': cs.filter((c) => c.result === 'n/a').length, total: cs.length });
const summary = {
  package: `${DRIVER.id}@${DRIVER.version}`, wptCommit: commit,
  files: new Set(cases.map((c) => c.file)).size,
  all: tally(cases), automated: tally(cases.filter((c) => c.kind === 'automated')), manual: tally(cases.filter((c) => c.kind === 'manual')),
};
console.log(JSON.stringify(summary, null, 1));
const byFile = new Map();
for (const c of cases) { const t = byFile.get(c.file) ?? { pass: 0, fail: 0, 'n/a': 0 }; t[c.result]++; byFile.set(c.file, t); }
for (const [f, t] of byFile) if (t.fail) console.log(`  ${f}: pass ${t.pass} · fail ${t.fail} · n/a ${t['n/a']}`);
const out = arg('--json');
if (out) writeFileSync(out, `${JSON.stringify({ summary, cases }, null, 1)}\n`);
