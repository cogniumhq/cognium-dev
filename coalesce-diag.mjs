#!/usr/bin/env node
// cognium-dev #143 PR B — dogfood driver for the coalesce diagnostic hook.
// Sets globalThis.__circleIrDiagCoalesce, then runs analyzeProject() on a
// directory and emits the per-file JSON-line stream to stderr.
// Usage: node /tmp/coalesce-diag.mjs <dir>

globalThis.__circleIrDiagCoalesce = true;

const { initAnalyzer, analyzeProject } = await import('circle-ir');
const { readFileSync } = await import('fs');
const { readdir, stat } = await import('fs/promises');
const { join, extname, resolve } = await import('path');

const EXTS = new Set(['.java', '.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.rs', '.sh', '.html']);
const EXT_TO_LANG = {
  '.java': 'java',
  '.js': 'javascript', '.jsx': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript',
  '.py': 'python', '.go': 'go', '.rs': 'rust',
  '.sh': 'bash', '.html': 'html',
};

async function collect(dir, out = []) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    if (e.name.startsWith('.') || e.name === 'node_modules' || e.name === 'dist'
        || e.name === 'coverage' || e.name === 'wasm') continue;
    const full = join(dir, e.name);
    if (e.isDirectory()) await collect(full, out);
    else if (EXTS.has(extname(e.name))) out.push(full);
  }
  return out;
}

const root = resolve(process.argv[2] || '.');
console.error(`# dogfood root: ${root}`);

await initAnalyzer();
const files = await collect(root);
console.error(`# collected ${files.length} files`);

const fileObjects = files.map(filePath => {
  const ext = extname(filePath);
  const lang = EXT_TO_LANG[ext];
  if (!lang) return null;
  return { filePath, code: readFileSync(filePath, 'utf8'), language: lang };
}).filter(f => f !== null);

console.error(`# analyzing ${fileObjects.length} files`);
const result = await analyzeProject(fileObjects);

const totalFindings = result.files.reduce((a, f) => a + (f.findings?.length || 0), 0);
const crossFilePaths = result.taint_paths || [];
console.error(`# done — total per-file findings: ${totalFindings}`);
console.error(`# cross-file taint paths: ${crossFilePaths.length}`);

// PR B: compute (source.line, sink.line, sink.file) → distinct sink.type for
// cross-file paths. This is the actual #129/#141 cluster site since per-file
// `generateFindings()` produces 0 on library-only corpora like jedis.
const xfLocLabels = new Map();
for (const tp of crossFilePaths) {
  const key = `${tp.source.file}:${tp.source.line}->${tp.sink.file}:${tp.sink.line}`;
  let set = xfLocLabels.get(key);
  if (!set) { set = new Set(); xfLocLabels.set(key, set); }
  set.add(tp.sink.type);
}
const xfCounts = Array.from(xfLocLabels.values(), s => s.size);
const xfSum = xfCounts.reduce((a, b) => a + b, 0);
const xfMax = xfCounts.length ? Math.max(...xfCounts) : 0;
const xfAvg = xfCounts.length ? xfSum / xfCounts.length : 0;
const xfMulti = xfCounts.filter(c => c > 1).length;
const xfDistribution = xfCounts.reduce((acc, c) => { acc[c] = (acc[c] || 0) + 1; return acc; }, {});

console.error(JSON.stringify({
  diag: 'coalesce_xfile',
  root,
  cross_file_taint_paths: crossFilePaths.length,
  unique_locations: xfLocLabels.size,
  multi_label_locations: xfMulti,
  avg_labels_per_location: Number(xfAvg.toFixed(3)),
  max_labels_per_location: xfMax,
  label_count_distribution: xfDistribution,
}));
