// CWE-Bench-Java, static CLI, IRIS-strict:
// a project is DETECTED when a finding carrying the project's CWE lands inside a
// fix method's line range (re-anchored by method name with circle-ir). Projects
// that are missing, time out, or fail to scan count as misses.
// Usage: CIRCLE_IR=<circle-ir dist/index.js> node score-cwe-bench-java.mjs \
//          <cognium-dev cli.js> <cwe-bench-java checkout> <projects dir> <out dir> \
//          [--concurrency N] [--timeout-min N] [--limit N]
// <projects dir> holds one checkout per project, named by `project_slug`, at the
// vulnerable tag from project_info.csv. Scans are cached in <out dir>.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { spawn } from 'node:child_process';

const [cli, benchDir, projectsDir, outDir, ...rest] = process.argv.slice(2);
const distIndex = process.env.CIRCLE_IR;
if (!distIndex || !outDir) { console.error('usage: CIRCLE_IR=<dist/index.js> node score-cwe-bench-java.mjs <cli.js> <cwe-bench-java> <projects> <out>'); process.exit(2); }
const opt = (k, d) => (rest.includes(k) ? Number(rest[rest.indexOf(k) + 1]) : d);
const concurrency = opt('--concurrency', 4);
const timeoutMs = opt('--timeout-min', 15) * 60_000;
const limit = opt('--limit', 1e9);
mkdirSync(outDir, { recursive: true });

function parseCsv(text) {
  const rows = []; let row = []; let field = ''; let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; } else field += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else if (c !== '\r') field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  const [head, ...body] = rows;
  return body.filter(r => r.length > 1).map(r => Object.fromEntries(head.map((h, i) => [h, r[i] ?? ''])));
}

const projects = parseCsv(readFileSync(join(benchDir, 'data/project_info.csv'), 'utf8')).slice(0, limit);
const fixes = parseCsv(readFileSync(join(benchDir, 'data/fix_info.csv'), 'utf8'));
const { initAnalyzer, analyze } = await import(distIndex);
await initAnalyzer();

function scan(dir, jsonOut) {
  return new Promise(resolve => {
    const t0 = Date.now();
    const p = spawn(process.execPath, [cli, 'scan', '.', '--format', 'json', '--category', 'security', '-l', 'java', '-q', '-o', jsonOut], { cwd: dir, stdio: 'ignore' });
    const timer = setTimeout(() => { p.kill('SIGKILL'); }, timeoutMs);
    p.on('exit', (code, sig) => { clearTimeout(timer); resolve({ code, sig, ms: Date.now() - t0 }); });
  });
}

async function fixRanges(dir, projFixes) {
  const out = [];
  for (const f of projFixes) {
    const path = join(dir, f.file);
    if (!existsSync(path)) continue;
    let start = Number(f.method_start), end = Number(f.method_end);
    try {
      const ir = await analyze(readFileSync(path, 'utf8'), path, 'java');
      const ms = ir.types.flatMap(t => t.methods).filter(m => m.name === f.method);
      const overlap = ms.find(m => start > 0 && m.start_line <= end && m.end_line >= start);
      const m = overlap ?? ms[0];
      if (m && !(start > 0 && end >= start && overlap)) { start = m.start_line; end = m.end_line; }
    } catch { /* keep the csv range */ }
    if (start > 0 && end >= start) out.push({ file: f.file, start, end });
  }
  return out;
}

const results = [];
let next = 0;
async function worker() {
  while (next < projects.length) {
    const p = projects[next++];
    const dir = join(projectsDir, p.project_slug);
    const cwe = Number(p.cwe_id.replace(/\D/g, ''));
    const r = { slug: p.project_slug, cwe: p.cwe_id, detected: false, status: 'ok', ms: 0, findings: 0, ranges: 0 };
    if (!existsSync(dir)) { r.status = 'missing'; results.push(r); continue; }
    const jsonOut = join(outDir, `${p.project_slug}.json`);
    const s = existsSync(jsonOut) ? { code: 0, ms: 0 } : await scan(dir, jsonOut);
    r.ms = s.ms;
    if (s.sig) { r.status = 'timeout'; results.push(r); console.log(`[TIMEOUT] ${p.project_slug}`); continue; }
    let json;
    try { json = JSON.parse(readFileSync(jsonOut, 'utf8')); } catch { r.status = 'scan-failed'; results.push(r); console.log(`[FAILED] ${p.project_slug}`); continue; }
    const ranges = await fixRanges(dir, fixes.filter(f => f.project_slug === p.project_slug));
    r.ranges = ranges.length;
    for (const res of json.results ?? []) {
      for (const v of res.vulnerabilities ?? []) {
        r.findings++;
        if (Number(/CWE-(\d+)/.exec(String(v.cwe ?? ''))?.[1]) !== cwe) continue;
        if (ranges.some(g => res.file.endsWith('/' + g.file) && v.line >= g.start && v.line <= g.end)) r.detected = true;
      }
    }
    results.push(r);
    console.log(`${r.detected ? '[DETECTED]' : '[MISS]'} ${p.project_slug} ${(r.ms / 1000).toFixed(0)}s findings=${r.findings} ranges=${r.ranges}`);
  }
}
await Promise.all(Array.from({ length: concurrency }, worker));

writeFileSync(join(outDir, 'summary.json'), JSON.stringify(results, null, 2));
const by = {};
for (const r of results) { const b = (by[r.cwe] ??= { total: 0, detected: 0, notScanned: 0 }); b.total++; if (r.detected) b.detected++; if (r.status !== 'ok') b.notScanned++; }
console.log('\nCWE       detected/total  (not scanned)');
let d = 0, t = 0, n = 0;
for (const [c, b] of Object.entries(by).sort()) { d += b.detected; t += b.total; n += b.notScanned; console.log(`${c.padEnd(9)} ${String(b.detected).padStart(4)}/${String(b.total).padEnd(4)}  (${b.notScanned})  ${(100 * b.detected / b.total).toFixed(1)}%`); }
console.log(`ALL       ${String(d).padStart(4)}/${String(t).padEnd(4)}  (${n})  ${(100 * d / t).toFixed(1)}%`);
