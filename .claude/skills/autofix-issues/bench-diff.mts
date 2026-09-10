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
  const wasmDir = resolve(srcDir, '..', 'wasm');
  const lp: Record<string, string> = {};
  for (const l of ['bash', 'go', 'java', 'javascript', 'python', 'rust', 'html', 'csharp', 'tsx']) lp[l] = join(wasmDir, `tree-sitter-${l}.wasm`);
  lp.typescript = join(wasmDir, 'tree-sitter-typescript.wasm');
  await parser.initParser({ wasmPath: join(REPO, 'node_modules', 'web-tree-sitter', 'web-tree-sitter.wasm'), languagePaths: lp });
  return analyzer.analyze as (code: string, file: string, lang: string) => Promise<any>;
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
  const analyze = await loadEngine(srcDir);
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
      for (const fl of ir?.taint?.flows ?? []) sigs.add(`${fl.sink_type}@${fl.source_line}->${fl.sink_line}`);
      result[rel] = [...sigs].sort();
    } catch (e) {
      errors++;
      const msg = String((e as Error).message);
      result[rel] = [msg.startsWith('TIMEOUT') ? msg : `ERROR:${msg.slice(0, 80)}`];
      console.error(`  ! ${rel}: ${msg.slice(0, 80)}`);
    }
    if ((i + 1) % 250 === 0) console.error(`  ${i + 1}/${files.length} (${((Date.now() - t0) / 1000).toFixed(0)}s)`);
  }
  writeFileSync(outFile, JSON.stringify({ src: srcDir, corpus: resolve(corpus), files: files.length, errors, result }, null, 1));
  const total = Object.values(result).reduce((n, s) => n + s.length, 0);
  console.log(`snapshot: ${files.length} files, ${total} signatures, ${errors} errors, ${((Date.now() - t0) / 1000).toFixed(0)}s → ${outFile}`);
} else if (cmd === 'diff') {
  const [beforeF, afterF] = positional;
  if (!beforeF || !afterF) throw new Error('usage: diff <before.json> <after.json> [--expected csv] [--allow regex]');
  const before = JSON.parse(readFileSync(beforeF, 'utf8')).result as Record<string, string[]>;
  const after = JSON.parse(readFileSync(afterF, 'utf8')).result as Record<string, string[]>;
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
