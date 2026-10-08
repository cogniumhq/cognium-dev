// File-level SecuriBench Micro scorer for a cognium-dev JSON scan.
// Expected count: the file's `@servlet vuln_count = "N"` annotation.
// Found: distinct sink lines among taint findings ("tainted data flows ...").
//   N > 0:  TP if found >= N, PARTIAL if 0 < found < N, FN if 0
//   N == 0: FP if found > 0, else TN
// TPR credits a partial at 0.5, as the published harness does.
// Usage: node score-securibench.mjs <micro dir> <scan.json> [--list fn|fp|partial]
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, basename, resolve } from 'node:path';

const [microArg, scanPath, ...rest] = process.argv.slice(2);
// Scan reports carry absolute paths, so `.` must resolve before files are matched.
const microDir = resolve(microArg);
const listKind = rest.includes('--list') ? rest[rest.indexOf('--list') + 1] : null;
const scan = JSON.parse(readFileSync(scanPath, 'utf8'));
const foundByFile = new Map();
for (const r of scan.results ?? []) {
  const lines = new Set((r.vulnerabilities ?? [])
    .filter(v => /tainted data flows/.test(v.message ?? ''))
    .map(v => v.line));
  foundByFile.set(r.file, lines.size);
}

const stats = new Map();
const listed = [];
for (const cat of readdirSync(microDir)) {
  const dir = join(microDir, cat);
  if (!statSync(dir).isDirectory()) continue;
  for (const f of readdirSync(dir).filter(x => x.endsWith('.java') && !x.includes('TestCase'))) {
    const path = join(dir, f);
    const m = /@servlet\s+vuln_count\s*=\s*"(\d+)"/.exec(readFileSync(path, 'utf8'));
    if (!m) continue;
    const expected = Number(m[1]);
    const found = foundByFile.get(path) ?? 0;
    const s = stats.get(cat) ?? { vuln: 0, safe: 0, tp: 0, partial: 0, fn: 0, fp: 0, tn: 0 };
    let status;
    if (expected > 0) { s.vuln++; status = found >= expected ? 'tp' : found > 0 ? 'partial' : 'fn'; }
    else { s.safe++; status = found > 0 ? 'fp' : 'tn'; }
    s[status]++;
    stats.set(cat, s);
    if (listKind === status) listed.push(`${cat}/${basename(f)} expected=${expected} found=${found}`);
  }
}
if (listKind) { console.log(listed.join('\n')); process.exit(0); }

const pct = (a, b) => (b ? (100 * a / b).toFixed(1) : '-') + '%';
const tot = { vuln: 0, safe: 0, tp: 0, partial: 0, fn: 0, fp: 0, tn: 0 };
console.log('category        vuln safe   TP part  FN   FP    TPR     FPR');
for (const [cat, s] of [...stats].sort()) {
  for (const k of Object.keys(tot)) tot[k] += s[k];
  console.log(`${cat.padEnd(14)} ${String(s.vuln).padStart(5)} ${String(s.safe).padStart(4)} ${String(s.tp).padStart(4)} ${String(s.partial).padStart(4)} ${String(s.fn).padStart(3)} ${String(s.fp).padStart(4)}  ${pct(s.tp + 0.5 * s.partial, s.vuln).padStart(6)}  ${pct(s.fp, s.safe).padStart(6)}`);
}
console.log(`${'ALL'.padEnd(14)} ${String(tot.vuln).padStart(5)} ${String(tot.safe).padStart(4)} ${String(tot.tp).padStart(4)} ${String(tot.partial).padStart(4)} ${String(tot.fn).padStart(3)} ${String(tot.fp).padStart(4)}  ${pct(tot.tp + 0.5 * tot.partial, tot.vuln).padStart(6)}  ${pct(tot.fp, tot.safe).padStart(6)}`);
