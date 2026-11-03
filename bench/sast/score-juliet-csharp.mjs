// Method-level Juliet C# 1.3 scorer over circle-ir `analyze()` taint flows, for the `_NN`
// variant files of the ten injection families (CWE-23/36/78/80/81/83/89/90/94/643).
//   Bad()    -> TP when an on-family flow's sink is inside it, else FN
//   Good*()  -> FP when one is (the Good() dispatcher is not scored), else TN
//   xLeak    -> on-family flows whose source line and sink line are in different methods.
//               On the single-method `_01` variant every such flow is a name collision (#548).
// `--files` scores per file instead, for variants that put the sink in a helper
// (`_21`, `_41`, `_42`, `_45`): TP when a flow lands in any Bad* method, FP in any Good*.
//
// Multi-file variants `_51`..`_54` (#636) switch to grouped mode automatically. A case is the
// files `<stem>_<NN>[a-e].cs` that share a stem; each case is one `analyzeProject()` call, so
// the cross-file phase and its project gates (constant-caller gate, etc.) see every caller.
//   hits     -> on-family sinks reported for the case: the per-file `taint.flows` of every file
//               after the project phase (which already carries promoted cross-file paths and has
//               the gates applied), unioned with `taint_paths` where `path_exists`, deduplicated
//               by sink file+line+type and source file+line. A flow equal to a cross-file path's
//               sink/source line and type is that path's promoted copy, so its source is taken
//               from the path's file. This counts what a project scan reports in either list.
//   Bad*     -> one TP per case when a hit's sink is inside any method named Bad* in any file of
//               the case (Bad, BadSink), else one FN
//   Good*    -> per method named Good<something> in any file (GoodG2B, GoodG2BSink, GoodB2G...;
//               not the Good() dispatcher): FP when a hit's sink is inside it, else TN. Methods
//               that only forward data count too, so TN is per method, not per sink.
//   files    -> cases (not .cs files); FPfiles -> cases with at least one FP.
//   xLeak    -> hits whose source and sink are both inside methods and one is Bad* while the
//               other is not (a Bad source reaching a Good sink or the reverse).
//   `--files` is ignored here; `--list fp|fn|leak` prints case stems (plus method / lines).
// Usage: CIRCLE_IR=<circle-ir dist/index.js> node score-juliet-csharp.mjs <juliet-csharp root> [variant=01] [--files] [--list fp|fn|leak]
import fs from 'node:fs'; import path from 'node:path';
const [root, ...rest] = process.argv.slice(2);
const dist = process.env.CIRCLE_IR;
if (!dist || !root) { console.error('usage: CIRCLE_IR=<dist/index.js> node score-juliet-csharp.mjs <juliet-csharp root> [variant] [--files]'); process.exit(2); }
const perFile = rest.includes('--files');
const variant = rest.find(a => /^\d+$/.test(a)) ?? '01';
const list = rest.includes('--list') ? rest[rest.indexOf('--list') + 1] : null;
const grouped = /^5[1-4]$/.test(variant);
const { initAnalyzer, analyze, analyzeProject } = await import(dist); await initAnalyzer();
const FAM = { CWE89: ['sql_injection'], CWE643: ['xpath_injection'], CWE94: ['code_injection'], CWE23: ['path_traversal'], CWE36: ['path_traversal'], CWE78: ['command_injection'], CWE80: ['xss'], CWE81: ['xss'], CWE83: ['xss'], CWE90: ['ldap_injection'] };
const files = [];
const fileRe = grouped ? new RegExp(`_${variant}[a-e]\\.cs$`) : null;
(function walk(d) { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (grouped ? fileRe.test(e.name) : e.name.endsWith(`_${variant}.cs`)) files.push(p); } })(path.join(root, 'src/testcases'));
const stats = {}; const listed = [];
if (grouped) {
  const cases = new Map();
  for (const f of files.sort()) { const stem = path.basename(f).slice(0, -'a.cs'.length); if (!cases.has(stem)) cases.set(stem, []); cases.get(stem).push(f); }
  for (const [stem, group] of cases) {
    const fam = /^(CWE\d+)_/.exec(stem)?.[1]; if (!FAM[fam]) continue;
    const proj = await analyzeProject(group.map(f => ({ code: fs.readFileSync(f, 'utf8'), filePath: path.basename(f), language: 'csharp' })));
    const methods = proj.files.flatMap(fa => fa.analysis.types.flatMap(t => t.methods.map(m => ({ file: fa.file, m }))));
    const mAt = (file, l) => methods.find(x => x.file === file && l >= x.m.start_line && l <= x.m.end_line)?.m;
    const on = t => FAM[fam].includes(t);
    const paths = (proj.taint_paths ?? []).filter(p => p.path_exists && on(p.sink.type));
    const hits = new Map(); const add = h => hits.set(`${h.sinkFile}:${h.sinkLine}:${h.type}:${h.srcFile}:${h.srcLine}`, h);
    for (const p of paths) add({ srcFile: p.source.file, srcLine: p.source.line, sinkFile: p.sink.file, sinkLine: p.sink.line, type: p.sink.type });
    for (const fa of proj.files) for (const x of fa.analysis.taint.flows ?? []) {
      if (!on(x.sink_type)) continue;
      const promoted = paths.find(p => p.source.file !== fa.file && p.sink.file === fa.file && p.sink.line === x.sink_line && p.sink.type === x.sink_type && p.source.line === x.source_line && p.source.type === x.source_type);
      add({ srcFile: promoted ? promoted.source.file : fa.file, srcLine: x.source_line, sinkFile: fa.file, sinkLine: x.sink_line, type: x.sink_type });
    }
    const s = (stats[fam] ??= { files: 0, tp: 0, fn: 0, fp: 0, tn: 0, leak: 0, fpFiles: 0 });
    s.files++;
    const hitIn = ({ file, m }) => [...hits.values()].some(h => h.sinkFile === file && h.sinkLine >= m.start_line && h.sinkLine <= m.end_line);
    if (methods.some(x => /^Bad/.test(x.m.name) && hitIn(x))) s.tp++; else { s.fn++; if (list === 'fn') listed.push(stem); }
    let caseFp = false;
    for (const x of methods) {
      if (!/^Good./.test(x.m.name)) continue;
      if (hitIn(x)) { s.fp++; caseFp = true; if (list === 'fp') listed.push(`${x.file} ${x.m.name}`); } else s.tn++;
    }
    if (caseFp) s.fpFiles++;
    for (const h of hits.values()) { const a = mAt(h.srcFile, h.srcLine), b = mAt(h.sinkFile, h.sinkLine); if (a && b && /^Bad/.test(a.name) !== /^Bad/.test(b.name)) { s.leak++; if (list === 'leak') listed.push(`${stem} ${h.srcFile}:${h.srcLine}(${a.name})->${h.sinkFile}:${h.sinkLine}(${b.name})`); } }
  }
}
for (const f of grouped ? [] : files.sort()) {
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
