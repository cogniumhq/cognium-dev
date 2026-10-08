// Scores a cognium-dev JSON scan of OWASP BenchmarkJava 1.2 with the scorecard rule:
// a test case is flagged when any finding in its file carries the category's CWE.
// Usage: node score-owasp.mjs <expectedresults.csv> <scan.json> [--list fp|fn] [--cat xss]
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

const [csvPath, scanPath, ...rest] = process.argv.slice(2);
const listKind = rest.includes('--list') ? rest[rest.indexOf('--list') + 1] : null;
const onlyCat = rest.includes('--cat') ? rest[rest.indexOf('--cat') + 1] : null;

const expected = readFileSync(csvPath, 'utf8').split('\n')
  .filter(l => l && !l.startsWith('#'))
  .map(l => { const [name, cat, real, cwe] = l.split(','); return { name, cat, real: real === 'true', cwe: Number(cwe) }; });

const scan = JSON.parse(readFileSync(scanPath, 'utf8'));
const cwesByTest = new Map();
for (const r of scan.results ?? []) {
  const name = basename(r.file).replace(/\.java$/, '');
  const set = cwesByTest.get(name) ?? new Set();
  for (const v of r.vulnerabilities ?? []) {
    const m = /CWE-(\d+)/.exec(String(v.cwe ?? ''));
    if (m) set.add(Number(m[1]));
  }
  cwesByTest.set(name, set);
}

const byCat = new Map();
const listed = [];
for (const e of expected) {
  if (onlyCat && e.cat !== onlyCat) continue;
  const flagged = cwesByTest.get(e.name)?.has(e.cwe) ?? false;
  const c = byCat.get(e.cat) ?? { tp: 0, fn: 0, fp: 0, tn: 0 };
  const outcome = e.real ? (flagged ? 'tp' : 'fn') : (flagged ? 'fp' : 'tn');
  c[outcome]++;
  byCat.set(e.cat, c);
  if (listKind === 'fp' && !e.real && flagged) listed.push(e.name);
  if (listKind === 'fn' && e.real && !flagged) listed.push(e.name);
}

if (listKind) { console.log(listed.join('\n')); process.exit(0); }

const pct = (a, b) => (b ? (100 * a / b).toFixed(1) : '-') + '%';
const tot = { tp: 0, fn: 0, fp: 0, tn: 0 };
console.log('category      TP   FN   FP   TN    TPR     FPR');
for (const [cat, c] of [...byCat].sort()) {
  for (const k of Object.keys(tot)) tot[k] += c[k];
  console.log(`${cat.padEnd(12)} ${String(c.tp).padStart(4)} ${String(c.fn).padStart(4)} ${String(c.fp).padStart(4)} ${String(c.tn).padStart(4)}  ${pct(c.tp, c.tp + c.fn).padStart(6)}  ${pct(c.fp, c.fp + c.tn).padStart(6)}`);
}
console.log(`${'ALL'.padEnd(12)} ${String(tot.tp).padStart(4)} ${String(tot.fn).padStart(4)} ${String(tot.fp).padStart(4)} ${String(tot.tn).padStart(4)}  ${pct(tot.tp, tot.tp + tot.fn).padStart(6)}  ${pct(tot.fp, tot.fp + tot.tn).padStart(6)}`);
console.log(`scorecard (TPR-FPR): ${((tot.tp / (tot.tp + tot.fn) - tot.fp / (tot.fp + tot.tn)) * 100).toFixed(1)}`);
