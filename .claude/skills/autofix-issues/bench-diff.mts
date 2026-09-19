#!/usr/bin/env bun
/**
 * bench-diff — verdict-signature differential for precision fixes (autofix §7 gate).
 *
 *   bun bench-diff.mts pretree  <git-ref> <out-dir>
 *       Materialise packages/circle-ir/{src,wasm} at <git-ref> under <out-dir> (git archive)
 *       and symlink the repo node_modules next to it so imports resolve. Never touches the
 *       working tree.
 *   bun bench-diff.mts snapshot <corpus-dir> <out.json> [--src <circle-ir/src>] [--filter <regex>] [--limit N] [--timeout-ms N]
 *       (--timeout-ms, default 60000: a file that exceeds it is recorded as "TIMEOUT" and skipped)
 *       Analyse every supported source file under <corpus-dir> and write
 *       { file: ["sink_type@source_line->sink_line", ...] } (sorted, unique).
 *   bun bench-diff.mts diff <before.json> <after.json> [--expected <expectedresults.csv>] [--allow <regex>]
 *       Print removed/added signatures per file. With --expected (OWASP/BenchmarkPython CSV:
 *       "test name, category, real vulnerability, cwe"), removals on real=true files are
 *       reported as TP-LOSS. --allow is a regex over "sink_type@" that marks the *targeted*
 *       FP shape; removals matching it on real=false files are expected. Exit code 1 on any
 *       TP-LOSS or any removal outside --allow.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, symlinkSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, relative, extname, basename, dirname } from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(here, '..', '..', '..');
const argv = process.argv.slice(2);
const cmd = argv[0];
const opt = (name: string): string | undefined => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
const positional = argv.slice(1).filter((a, i, arr) => !a.startsWith('--') && !(i > 0 && arr[i - 1].startsWith('--')));

const EXT: Record<string, string> = {
  '.java': 'java', '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript', '.py': 'python', '.go': 'go', '.cs': 'csharp',
  '.rs': 'rust', '.sh': 'bash', '.bash': 'bash', '.html': 'html', '.htm': 'html',
};
const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', 'target', '.git', 'coverage', '__pycache__']);

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    if (SKIP_DIRS.has(e)) continue;
    const p = join(dir, e);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (EXT[extname(e)]) out.push(p);
  }
  return out;
}

async function loadEngine(srcDir: string) {
  const analyzer = await import(join(srcDir, 'analyzer.ts'));
  const parser = await import(join(srcDir, 'core', 'parser.ts'));
  // cognium-dev#361/#372 — the scorer historically snapshotted `taint.flows`
  // only, which made every scan-path precision change a zero-delta: findings
  // reach users through `generateFindings` and `ir.findings`, and a change
  // there is invisible to a flow-only signature. `--surface` opts in.
  let generateFindings: ((...a: any[]) => any[]) | null = null;
  try {
    const mod = await import(join(srcDir, 'analysis', 'findings.ts'));
    generateFindings = mod.generateFindings ?? null;
  } catch { /* older trees may not export it; flows-only still works */ }
  const wasmDir = resolve(srcDir, '..', 'wasm');
  const lp: Record<string, string> = {};
  for (const l of ['bash', 'go', 'java', 'javascript', 'python', 'rust', 'html', 'csharp', 'tsx']) lp[l] = join(wasmDir, `tree-sitter-${l}.wasm`);
  lp.typescript = join(wasmDir, 'tree-sitter-typescript.wasm');
  await parser.initParser({ wasmPath: join(REPO, 'node_modules', 'web-tree-sitter', 'web-tree-sitter.wasm'), languagePaths: lp });
  return {
    analyze: analyzer.analyze as (code: string, file: string, lang: string) => Promise<any>,
    generateFindings,
  };
}

function readExpected(csv: string): Map<string, boolean> {
  const m = new Map<string, boolean>();
  for (const line of readFileSync(csv, 'utf8').split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const [name, , real] = line.split(',').map(s => s.trim());
    if (name) m.set(name, real === 'true');
  }
  return m;
}

if (cmd === 'pretree') {
  const [ref, out] = positional;
  if (!ref || !out) throw new Error('usage: pretree <git-ref> <out-dir>');
  mkdirSync(out, { recursive: true });
  execSync(`git -C "${REPO}" archive ${ref} packages/circle-ir/src packages/circle-ir/wasm | tar -x -C "${out}"`, { stdio: 'inherit' });
  const nm = join(out, 'node_modules');
  if (!existsSync(nm)) symlinkSync(join(REPO, 'node_modules'), nm);
  console.log(`pre-tree ready: --src ${join(out, 'packages', 'circle-ir', 'src')}`);
} else if (cmd === 'snapshot') {
  const [corpus, outFile] = positional;
  if (!corpus || !outFile) throw new Error('usage: snapshot <corpus-dir> <out.json> [--src dir] [--filter regex] [--limit N]');
  const srcDir = resolve(opt('--src') ?? join(REPO, 'packages', 'circle-ir', 'src'));
  const filter = opt('--filter') ? new RegExp(opt('--filter')!) : null;
  const limit = opt('--limit') ? Number(opt('--limit')) : Infinity;
  const timeoutMs = opt('--timeout-ms') ? Number(opt('--timeout-ms')) : 60_000;
  // `--surface flows|findings|both` (default `flows`, so existing baselines
  // stay comparable). `findings` adds `F:<type>@<source_line>-><line>` rows
  // from `generateFindings`, which is the surface the scan path and CLI
  // report from — see #372 for how far the surfaces can diverge.
  const surface = (opt('--surface') ?? 'flows') as 'flows' | 'findings' | 'both';
  if (!['flows', 'findings', 'both'].includes(surface)) throw new Error(`--surface must be flows|findings|both`);
  const { analyze, generateFindings } = await loadEngine(srcDir);
  if (surface !== 'flows' && !generateFindings) {
    throw new Error(`--surface ${surface} needs generateFindings, which this tree does not export`);
  }
  let files = walk(resolve(corpus)).sort();
  if (filter) files = files.filter(f => filter.test(f));
  files = files.slice(0, limit);
  const result: Record<string, string[]> = {};
  let errors = 0; const t0 = Date.now();
  for (const [i, f] of files.entries()) {
    const rel = relative(resolve(corpus), f);
    try {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const ir = await Promise.race([
        analyze(readFileSync(f, 'utf8'), f, EXT[extname(f)]),
        new Promise<never>((_, rej) => { timer = setTimeout(() => rej(new Error(`TIMEOUT>${timeoutMs}ms`)), timeoutMs); }),
      ]).finally(() => clearTimeout(timer));
      const sigs = new Set<string>();
      if (surface === 'flows' || surface === 'both') {
        for (const fl of ir?.taint?.flows ?? []) sigs.add(`${fl.sink_type}@${fl.source_line}->${fl.sink_line}`);
      }
      if (surface === 'findings' || surface === 'both') {
        // Prefixed `F:` so a findings row can never be mistaken for a flow row
        // when both surfaces are captured, and so an old flows-only baseline
        // diffed against a `both` snapshot shows the findings rows as ADDED
        // rather than silently colliding.
        const fs = generateFindings!(
          ir?.taint?.sources ?? [],
          ir?.taint?.sinks ?? [],
          ir?.dfg ?? { defs: [], uses: [] },
          f,
          readFileSync(f, 'utf8'),
          EXT[extname(f)],
          ir?.taint?.sanitizers ?? [],
        );
        for (const fd of fs ?? []) {
          sigs.add(`F:${fd.type}@${fd.source?.line ?? '?'}->${fd.line}`);
        }
      }
      result[rel] = [...sigs].sort();
    } catch (e) {
      errors++;
      const msg = String((e as Error).message);
      result[rel] = [msg.startsWith('TIMEOUT') ? msg : `ERROR:${msg.slice(0, 80)}`];
      console.error(`  ! ${rel}: ${msg.slice(0, 80)}`);
    }
    if ((i + 1) % 250 === 0) console.error(`  ${i + 1}/${files.length} (${((Date.now() - t0) / 1000).toFixed(0)}s)`);
  }
  // Provenance — cognium-dev#377. A snapshot is only meaningful if you know
  // WHICH code produced it, and the failure that motivates this is silent: a
  // `post` snapshot taken from the working tree after a checkout/stash/rebase
  // captures whatever HEAD happens to be, so base and post can be the same
  // code and the diff reports a confident `added=0 removed=0`. That happened
  // repeatedly while fixing #363 and #368 and nearly shipped a false result.
  // Recording it makes the mistake visible in `diff` instead of invisible.
  const provenance = (() => {
    try {
      const head = execSync('git rev-parse HEAD', { cwd: REPO, encoding: 'utf8' }).trim();
      const branch = execSync('git rev-parse --abbrev-ref HEAD', { cwd: REPO, encoding: 'utf8' }).trim();
      const dirty = execSync('git status --porcelain', { cwd: REPO, encoding: 'utf8' }).trim().length > 0;
      // A `--src` pointing into a pretree is a materialised historical commit,
      // so the repo's HEAD says nothing about it; flag which kind this is.
      const fromPretree = /\/pre(tree)?\//.test(srcDir) || !srcDir.startsWith(join(REPO, 'packages'));
      return { head, branch, dirty, from: fromPretree ? 'pretree' : 'working-tree' };
    } catch { return null; }
  })();
  writeFileSync(outFile, JSON.stringify({ src: srcDir, corpus: resolve(corpus), surface, provenance, files: files.length, errors, result }, null, 1));
  if (provenance) {
    console.error(`  provenance: ${provenance.from} branch=${provenance.branch} head=${provenance.head.slice(0, 7)}${provenance.dirty ? ' DIRTY' : ''}`);
  }
  const total = Object.values(result).reduce((n, s) => n + s.length, 0);
  console.log(`snapshot: ${files.length} files, ${total} signatures, ${errors} errors, ${((Date.now() - t0) / 1000).toFixed(0)}s → ${outFile}`);
} else if (cmd === 'diff') {
  const [beforeF, afterF] = positional;
  if (!beforeF || !afterF) throw new Error('usage: diff <before.json> <after.json> [--expected csv] [--allow regex]');
  const beforeDoc = JSON.parse(readFileSync(beforeF, 'utf8'));
  const afterDoc = JSON.parse(readFileSync(afterF, 'utf8'));
  // #372 — comparing a flows-only baseline against a findings snapshot would
  // report every findings row as ADDED and read as a huge regression. Refuse
  // rather than mislead.
  const sBefore = beforeDoc.surface ?? 'flows';
  const sAfter = afterDoc.surface ?? 'flows';
  if (sBefore !== sAfter) {
    throw new Error(`surface mismatch: before='${sBefore}' after='${sAfter}' — re-snapshot both with the same --surface`);
  }
  // #377 — print what produced each side, and refuse the one comparison that
  // is guaranteed to mislead: two working-tree snapshots from the same commit
  // with neither dirty cannot contain a code difference, so a clean gate there
  // means "I measured nothing", not "nothing changed".
  const pv = (d: any) => d.provenance
    ? `${d.provenance.from} ${d.provenance.branch}@${String(d.provenance.head).slice(0, 7)}${d.provenance.dirty ? ' DIRTY' : ''}`
    : '(no provenance recorded)';
  console.log(`before: ${pv(beforeDoc)}`);
  console.log(`after:  ${pv(afterDoc)}`);
  const pb = beforeDoc.provenance, pa = afterDoc.provenance;
  if (pb && pa && pb.from === 'working-tree' && pa.from === 'working-tree'
      && pb.head === pa.head && !pb.dirty && !pa.dirty) {
    throw new Error(
      `both snapshots came from the same clean commit (${String(pb.head).slice(0, 7)}) — ` +
      `they cannot differ, so this diff would prove nothing. Re-snapshot the base from a ` +
      `pretree (\`bench-diff pretree <ref> <dir>\`) or the post from the tree carrying the fix.`,
    );
  }
  const before = beforeDoc.result as Record<string, string[]>;
  const after = afterDoc.result as Record<string, string[]>;
  const expected = opt('--expected') ? readExpected(opt('--expected')!) : null;
  const allow = opt('--allow') ? new RegExp(opt('--allow')!) : null;
  let removed = 0, added = 0, tpLoss = 0, disallowed = 0, filesChanged = 0;
  const rows: string[] = [];
  for (const file of new Set([...Object.keys(before), ...Object.keys(after)])) {
    const b = new Set(before[file] ?? []), a = new Set(after[file] ?? []);
    const rem = [...b].filter(s => !a.has(s)), add = [...a].filter(s => !b.has(s));
    if (!rem.length && !add.length) continue;
    filesChanged++;
    const name = basename(file).replace(/\.[^.]+$/, '');
    const real = expected ? expected.get(name) : undefined;
    for (const s of rem) {
      removed++;
      let tag = 'REMOVED';
      if (real === true) { tag = 'TP-LOSS'; tpLoss++; }
      else if (allow && !allow.test(s)) { tag = 'REMOVED-OUTSIDE-ALLOW'; disallowed++; }
      else if (!allow) { tag = 'REMOVED-UNCLASSIFIED'; disallowed++; }
      rows.push(`${tag}\t${file}\t${s}\t${real === undefined ? 'expected=?' : `expected=${real}`}`);
    }
    for (const s of add) { added++; rows.push(`ADDED\t${file}\t${s}\t${real === undefined ? 'expected=?' : `expected=${real}`}`); }
  }
  console.log(rows.join('\n'));
  console.log(`\nsummary: files_changed=${filesChanged} removed=${removed} added=${added} tp_loss=${tpLoss} removed_outside_allow=${disallowed}`);
  console.log(tpLoss === 0 && disallowed === 0 ? 'GATE: PASS' : 'GATE: FAIL');
  process.exit(tpLoss === 0 && disallowed === 0 ? 0 : 1);
} else {
  console.error('commands: pretree | snapshot | diff'); process.exit(2);
}
