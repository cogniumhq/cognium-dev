// unresolved-audit.mjs — enumerate the call sites `resolveCall` does not answer,
// take a seeded sample, and dump each site with the evidence a human needs to
// classify it. Classification itself is NOT done here (see the audit report).
//
//   CIRCLE_IR=$PWD/packages/circle-ir/dist/index.js \
//   SEED=20261002 N=200 node bench/unresolved-audit.mjs <repo> > out.json
//
// Java only, like the rest of bench/.
import { readFileSync, readdirSync, statSync } from 'fs';
import { join, relative } from 'path';
const { initAnalyzer, analyze, buildSymbolTable, buildCrossFileResolver, TypeHierarchyResolver } =
  await import(process.env.CIRCLE_IR);

const ROOT = process.argv[2];
const SEED = Number(process.env.SEED ?? 20261002);
const N = Number(process.env.N ?? 200);

function walk(d, out = []) {
  for (const e of readdirSync(d).sort()) {
    const p = join(d, e), s = statSync(p);
    if (s.isDirectory()) { if (!['node_modules', '.git', 'target'].includes(e)) walk(p, out); }
    else if (p.endsWith('.java')) out.push(p);
  }
  return out;
}

// deterministic PRNG (mulberry32) so the sample is reproducible from SEED alone
function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const files = walk(ROOT);
await initAnalyzer();
const irs = [];
for (const f of files) irs.push({ path: f, ir: await analyze(readFileSync(f, 'utf8'), f, 'java') });
const st = buildSymbolTable(irs);
const th = new TypeHierarchyResolver();
for (const { ir, path } of irs) th.addFromIR(ir, path);
const res = buildCrossFileResolver(irs, st, th);

// every project-declared method name, for "is the target even in scope?"
const declaredNames = new Set();
const declaredTypes = new Set();
for (const { ir } of irs) {
  const pkg = ir.meta?.package || '';
  for (const t of ir.types || []) {
    declaredTypes.add(t.name);
    declaredTypes.add(pkg ? `${pkg}.${t.name}` : t.name);
    for (const m of t.methods || []) declaredNames.add(m.name);
  }
}

const src = new Map();   // path -> lines
const population = [];   // every unresolved call site, in stable order
let total = 0;
const byTier = {};
for (const { ir, path } of irs) {
  if (!src.has(path)) src.set(path, readFileSync(path, 'utf8').split('\n'));
  const text = readFileSync(path, 'utf8');
  for (let i = 0; i < (ir.calls || []).length; i++) {
    const c = ir.calls[i];
    total++;
    const r = res.resolveCall(c, path);
    if (r) { byTier[r.resolution] = (byTier[r.resolution] || 0) + 1; continue; }
    population.push({
      id: `${relative(ROOT, path)}:${c.location.line}:${c.location.column}:${c.method_name}`,
      file: relative(ROOT, path),
      line: c.location.line,
      col: c.location.column,
      method_name: c.method_name,
      receiver: c.receiver ?? null,
      receiver_type: c.receiver_type ?? null,
      receiver_type_fqn: c.receiver_type_fqn ?? null,
      is_constructor: !!c.is_constructor,
      in_method: c.in_method ?? null,
      call_resolution_status: c.resolution?.status ?? null,
      call_resolution_candidates: c.resolution?.candidates ?? null,
      // evidence for classification
      name_declared_in_project: declaredNames.has(c.method_name),
      receiver_type_in_project: !!(c.receiver_type && declaredTypes.has(c.receiver_type)),
      parse_ok: ir.parse_status ? ir.parse_status.success !== false : null,
      src_line: (src.get(path)[c.location.line - 1] ?? '').trim().slice(0, 240),
      file_imports: (ir.imports || []).map(im => im.source ?? im.module ?? im.name).filter(Boolean),
      file_annotations: [...text.matchAll(/^\s*@([A-Z][A-Za-z0-9_]*)/gm)].map(m => m[1])
        .filter((v, i, a) => a.indexOf(v) === i),
    });
  }
}

// seeded sample without replacement, over the stable population order
const rnd = mulberry32(SEED);
const idx = [...population.keys()];
for (let i = idx.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [idx[i], idx[j]] = [idx[j], idx[i]]; }
const pick = idx.slice(0, Math.min(N, idx.length)).sort((a, b) => a - b);

console.log(JSON.stringify({
  meta: {
    root: ROOT, files: files.length, total_call_sites: total,
    resolved_by_tier: byTier, unresolved: population.length,
    seed: SEED, sample_size: pick.length,
    prng: 'mulberry32 over the file-path-sorted, IR-order call list; Fisher-Yates partial shuffle',
    parse_failures: irs.filter(x => x.ir.parse_status && x.ir.parse_status.success === false)
      .map(x => relative(ROOT, x.path)),
  },
  sample: pick.map(i => population[i]),
}, null, 1));
