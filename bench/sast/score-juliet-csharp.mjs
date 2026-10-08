// Method-level Juliet C# 1.3 scorer over circle-ir `analyze()` taint flows, for the `_NN`
// variant files of the ten injection families (CWE-23/36/78/80/81/83/89/90/94/643).
//   Bad()    -> TP when an on-family flow's sink is inside it, else FN
//   Good*()  -> FP when one is (the Good() dispatcher is not scored), else TN
//   xLeak    -> on-family flows whose source line and sink line are in different methods.
//               On the single-method `_01` variant every such flow is a name collision (#548).
// `--files` scores per file instead, for variants that put the sink in a helper
// (`_21`, `_41`, `_42`, `_45`): TP when a flow lands in any Bad* method, FP in any Good*.
// Usage: CIRCLE_IR=<circle-ir dist/index.js> node score-juliet-csharp.mjs <juliet-csharp root> [variant=01] [--files] [--list fp|fn|leak]
import fs from 'node:fs'; import path from 'node:path';
const [root, ...rest] = process.argv.slice(2);
const dist = process.env.CIRCLE_IR;
if (!dist || !root) { console.error('usage: CIRCLE_IR=<dist/index.js> node score-juliet-csharp.mjs <juliet-csharp root> [variant] [--files]'); process.exit(2); }
const perFile = rest.includes('--files');
const variant = rest.find(a => /^\d+$/.test(a)) ?? '01';
const list = rest.includes('--list') ? rest[rest.indexOf('--list') + 1] : null;
const { initAnalyzer, analyze } = await import(dist); await initAnalyzer();
const FAM = { CWE89: ['sql_injection'], CWE643: ['xpath_injection'], CWE94: ['code_injection'], CWE23: ['path_traversal'], CWE36: ['path_traversal'], CWE78: ['command_injection'], CWE80: ['xss'], CWE81: ['xss'], CWE83: ['xss'], CWE90: ['ldap_injection'] };
const files = [];
(function walk(d) { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (e.name.endsWith(`_${variant}.cs`)) files.push(p); } })(path.join(root, 'src/testcases'));
const stats = {}; const listed = [];
for (const f of files.sort()) {
  const fam = /^(CWE\d+)_/.exec(path.basename(f))?.[1]; if (!FAM[fam]) continue;
  const ir = await analyze(fs.readFileSync(f, 'utf8'), path.basename(f), 'csharp');
  const methods = ir.types.flatMap(t => t.methods);
  const mAt = l => methods.find(m => l >= m.start_line && l <= m.end_line);
  const flows = (ir.taint.flows ?? []).filter(x => FAM[fam].includes(x.sink_type));
  const s = (stats[fam] ??= { files: 0, tp: 0, fn: 0, fp: 0, tn: 0, leak: 0, fpFiles: 0 });
  s.files++;
  if (perFile) {
    const lands = re => flows.some(x => methods.some(m => re.test(m.name) && x.sink_line >= m.start_line && x.sink_line <= m.end_line));
    if (lands(/^Bad/i)) s.tp++; else { s.fn++; if (list === 'fn') listed.push(path.basename(f)); }
    if (lands(/^Good/i)) { s.fp++; s.fpFiles++; if (list === 'fp') listed.push(path.basename(f)); } else s.tn++;
    continue;
  }
  let fileFp = false;
  for (const m of methods) {
    const hit = flows.some(x => x.sink_line >= m.start_line && x.sink_line <= m.end_line);
    if (m.name === 'Bad') { if (hit) s.tp++; else { s.fn++; if (list === 'fn') listed.push(path.basename(f)); } }
    else if (/^Good./.test(m.name)) { if (hit) { s.fp++; fileFp = true; if (list === 'fp') listed.push(path.basename(f) + ' ' + m.name); } else s.tn++; }
  }
  if (fileFp) s.fpFiles++;
  for (const x of flows) { const a = mAt(x.source_line), b = mAt(x.sink_line); if (a && b && a !== b) { s.leak++; if (list === 'leak') listed.push(`${path.basename(f)} ${x.source_line}(${a.name})->${x.sink_line}(${b.name})`); } }
}
if (list) { console.log(listed.join('\n')); process.exit(0); }
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) : '-') + '%'; const T = { files: 0, tp: 0, fn: 0, fp: 0, tn: 0, leak: 0, fpFiles: 0 };
console.log('family  files  Bad:TP  FN   Good*:FP   TN    TPR     FPR   FPfiles xLeak');
for (const [k, s] of Object.entries(stats).sort()) { for (const j in T) T[j] += s[j]; console.log(`${k.padEnd(7)} ${String(s.files).padStart(5)} ${String(s.tp).padStart(7)} ${String(s.fn).padStart(3)} ${String(s.fp).padStart(10)} ${String(s.tn).padStart(4)}  ${pct(s.tp, s.tp + s.fn).padStart(6)}  ${pct(s.fp, s.fp + s.tn).padStart(6)} ${String(s.fpFiles).padStart(7)} ${String(s.leak).padStart(5)}`); }
console.log(`${'ALL'.padEnd(7)} ${String(T.files).padStart(5)} ${String(T.tp).padStart(7)} ${String(T.fn).padStart(3)} ${String(T.fp).padStart(10)} ${String(T.tn).padStart(4)}  ${pct(T.tp, T.tp + T.fn).padStart(6)}  ${pct(T.fp, T.fp + T.tn).padStart(6)} ${String(T.fpFiles).padStart(7)} ${String(T.leak).padStart(5)}`);
