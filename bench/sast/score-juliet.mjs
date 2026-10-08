// Method-level Juliet Java scorer for a cognium-dev JSON scan of the _01 files.
// bad()           -> TP if a finding with the CWE's class lands inside it, else FN
// good*() (not the good() dispatcher) -> FP if such a finding lands inside it, else TN
// Usage: CIRCLE_IR=<circle-ir dist/index.js> node score-juliet.mjs <scan.json> [--cwes CWE78,CWE89,...] [--misses]
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

const [scanPath, ...rest] = process.argv.slice(2);
const distIndex = process.env.CIRCLE_IR;
if (!distIndex || !scanPath) { console.error('usage: CIRCLE_IR=<dist/index.js> node score-juliet.mjs <scan.json> [--cwes ...]'); process.exit(2); }
const only = rest.includes('--cwes') ? new Set(rest[rest.indexOf('--cwes') + 1].split(',')) : null;
const { initAnalyzer, analyze } = await import(distIndex);
await initAnalyzer();

// Juliet directory CWE -> CWEs a correct finding may carry.
const ACCEPT = {
  CWE78: [78], CWE80: [79, 80], CWE81: [79, 81], CWE83: [79, 83], CWE89: [89],
  CWE90: [90], CWE643: [643], CWE23: [22, 23], CWE36: [22, 36],
  CWE601: [601], CWE113: [113, 93], CWE470: [470], CWE134: [134], CWE15: [15],
};

const scan = JSON.parse(readFileSync(scanPath, 'utf8'));
const stats = new Map();
const misses = [];
for (const r of scan.results ?? []) {
  const name = basename(r.file);
  if (!/_01\.java$/.test(name)) continue;
  const cwe = /^(CWE\d+)_/.exec(name)?.[1];
  if (!cwe || !ACCEPT[cwe] || (only && !only.has(cwe))) continue;
  const ir = await analyze(readFileSync(r.file, 'utf8'), r.file, 'java');
  const methods = ir.types.flatMap(t => t.methods);
  const hits = (r.vulnerabilities ?? [])
    .filter(v => { const m = /CWE-(\d+)/.exec(String(v.cwe ?? '')); return m && ACCEPT[cwe].includes(Number(m[1])); })
    .map(v => v.line);
  const inside = m => hits.some(l => l >= m.start_line && l <= m.end_line);
  const s = stats.get(cwe) ?? { tp: 0, fn: 0, fp: 0, tn: 0 };
  for (const m of methods) {
    if (m.name === 'bad') { if (inside(m)) s.tp++; else { s.fn++; misses.push(name); } }
    else if (/^good./.test(m.name)) { if (inside(m)) s.fp++; else s.tn++; }
  }
  stats.set(cwe, s);
}

const pct = (a, b) => (b ? (100 * a / b).toFixed(1) : '-') + '%';
const tot = { tp: 0, fn: 0, fp: 0, tn: 0 };
console.log('CWE       bad: TP  FN    good*: FP   TN    TPR     FPR');
for (const [cwe, s] of [...stats].sort()) {
  for (const k of Object.keys(tot)) tot[k] += s[k];
  console.log(`${cwe.padEnd(8)} ${String(s.tp).padStart(6)} ${String(s.fn).padStart(3)} ${String(s.fp).padStart(10)} ${String(s.tn).padStart(4)}  ${pct(s.tp, s.tp + s.fn).padStart(6)}  ${pct(s.fp, s.fp + s.tn).padStart(6)}`);
}
console.log(`${'ALL'.padEnd(8)} ${String(tot.tp).padStart(6)} ${String(tot.fn).padStart(3)} ${String(tot.fp).padStart(10)} ${String(tot.tn).padStart(4)}  ${pct(tot.tp, tot.tp + tot.fn).padStart(6)}  ${pct(tot.fp, tot.fp + tot.tn).padStart(6)}`);
if (rest.includes('--misses')) console.log('FN files:', misses.join(' '));
