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
 *   bun bench-diff.mts selftest
 *       Assert the gate's own classification logic (run after editing it).
 *   bun bench-diff.mts diff <before.json> <after.json> [--expected <expectedresults.csv>] [--allow <regex>]
 *       Print removed/added signatures per file. With --expected (OWASP/BenchmarkPython CSV:
 *       "test name, category, real vulnerability, cwe"), removals on real=true files are
 *       reported as TP-LOSS. --allow is a regex over "sink_type@" that marks the *targeted*
 *       FP shape; removals matching it on real=false files are expected. Exit code 1 on any
 *       TP-LOSS or any removal outside --allow.
 *
 *       TWO KEYS, ONE GATE — cognium-dev#380. A signature is
 *       "sink_type@source_line->sink_line", so a fix that keeps a detection but
 *       corrects its SOURCE line reads as one removal plus one addition. The gate
 *       looks at removals, so a pure improvement scored as TP loss: #361/#372
 *       reported `tp_loss=74 GATE: FAIL` while losing nothing at all. Worse, a
 *       genuine 63-detection loss produced an indistinguishable verdict, so the
 *       gate gave no signal on exactly the class of change it is most needed for.
 *
 *       So `diff` now compares at two keys. The DETECTION key drops the source
 *       line ("sink_type@sink_line") and is what the gate judges — it answers
 *       "is this finding still reported?". The full signature is still compared,
 *       but a removal whose detection key survives is reported as REATTRIBUTED
 *       and does not gate. The summary also carries `source_after_sink`, a count
 *       of findings whose reported source line sits AFTER their own sink, which
 *       is impossible as written and so a cheap attribution-quality metric.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, symlinkSync, readdirSync, statSync, realpathSync } from 'node:fs';
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

const PRETREE_MARKER = '.bench-diff-pretree.json';

/**
 * Provenance for the tree that ACTUALLY produced a snapshot — cognium-dev#378.
 *
 * #377 recorded `git rev-parse HEAD` of the repo, but `snapshot --src <dir>`
 * measures whatever tree that path points at: a pretree, or another worktree.
 * When `--src` was used the provenance therefore described the wrong thing, and
 * two genuinely different trees printed identical lines:
 *
 *   before: pretree agent/fix-361@25763bc
 *   after:  pretree agent/fix-361@25763bc     <- different code, same label
 *
 * That defeats #377 exactly where snapshots are easiest to confuse, because the
 * working tree looks untouched the whole time. Resolution order:
 *
 *   1. a `.bench-diff-pretree.json` marker at or above `--src` — a materialised
 *      historical commit, so report the commit it was made from;
 *   2. otherwise the git worktree enclosing `--src`, which may be a different
 *      worktree (and a different branch) from the repo this script lives in;
 *   3. otherwise no provenance.
 *
 * The resolved path is recorded too, so `diff` can tell "same commit, same
 * tree" (cannot differ) from "same commit, different trees" (can differ).
 */
function resolveProvenance(srcDir: string) {
  const srcResolved = (() => { try { return realpathSync(srcDir); } catch { return resolve(srcDir); } })();
  // 1. pretree marker
  for (let d = srcResolved; ; d = dirname(d)) {
    const marker = join(d, PRETREE_MARKER);
    if (existsSync(marker)) {
      try {
        const { ref, head } = JSON.parse(readFileSync(marker, 'utf8'));
        return { head, branch: ref, dirty: false, from: 'pretree', srcResolved };
      } catch { /* fall through to git */ }
    }
    if (dirname(d) === d) break;
  }
  // 2. the git worktree enclosing --src
  try {
    const g = (a: string) => execSync(`git -C "${srcResolved}" ${a}`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    return {
      head: g('rev-parse HEAD'),
      branch: g('rev-parse --abbrev-ref HEAD'),
      dirty: g('status --porcelain').length > 0,
      from: 'working-tree',
      srcResolved,
    };
  } catch { return null; }
}

/**
 * Classify the difference between two snapshots. Pure, so `selftest` can
 * assert on it — the gate is measurement-critical code that twice reported a
 * pure improvement as TP loss (#380), and a regression in this logic is
 * exactly the kind of thing that goes unnoticed until it has misled someone.
 */
function classify(
  before: Record<string, string[]>,
  after: Record<string, string[]>,
  expected: Map<string, boolean> | null,
  allow: RegExp | null,
) {
  let removed = 0, added = 0, tpLoss = 0, disallowed = 0, filesChanged = 0, reattributed = 0;
  const rows: string[] = [];
  for (const file of new Set([...Object.keys(before), ...Object.keys(after)])) {
    const b = new Set(before[file] ?? []), a = new Set(after[file] ?? []);
    const rem = [...b].filter(s => !a.has(s)), add = [...a].filter(s => !b.has(s));
    if (!rem.length && !add.length) continue;
    filesChanged++;
    const name = basename(file).replace(/\.[^.]+$/, '');
    const real = expected ? expected.get(name) : undefined;
    const exp = real === undefined ? 'expected=?' : `expected=${real}`;

    // #380 — judge at the DETECTION key. A removal whose detection key
    // survives is the same finding with a corrected source line, not a lost
    // finding.
    const detBefore = detKeys(b), detAfter = detKeys(a);
    const movedTo = new Map<string, string[]>();
    for (const sig of add) {
      const p = parseSig(sig);
      const k = p.opaque ? p.key : p.detKey;
      if (detBefore.has(k)) {
        if (!movedTo.has(k)) movedTo.set(k, []);
        movedTo.get(k)!.push(sig);
      }
    }

    for (const sig of rem) {
      removed++;
      const p = parseSig(sig);
      const k = p.opaque ? p.key : p.detKey;
      if (detAfter.has(k)) {
        reattributed++;
        const to = (movedTo.get(k) ?? []).join(',') || '(same sink, source unchanged elsewhere)';
        rows.push(`REATTRIBUTED\t${file}\t${sig} -> ${to}\t${exp}`);
        continue;
      }
      let tag = 'REMOVED';
      if (real === true) { tag = 'TP-LOSS'; tpLoss++; }
      else if (allow && !allow.test(sig)) { tag = 'REMOVED-OUTSIDE-ALLOW'; disallowed++; }
      else if (!allow) { tag = 'REMOVED-UNCLASSIFIED'; disallowed++; }
      rows.push(`${tag}\t${file}\t${sig}\t${exp}`);
    }
    for (const sig of add) {
      added++;
      const p = parseSig(sig);
      const k = p.opaque ? p.key : p.detKey;
      // Suppress the partner row of a re-attribution; it is already on the
      // REATTRIBUTED line, and listing it as ADDED reads as a new finding.
      if (detBefore.has(k)) continue;
      rows.push(`ADDED\t${file}\t${sig}\t${exp}`);
    }
  }
  return { rows, removed, added, tpLoss, disallowed, filesChanged, reattributed };
}

/**
 * Split a verdict signature into its parts.
 *
 * Forms: "sink_type@12->34" (flows surface) and "F:sink_type@12->34" (findings
 * surface, #373). Anything else — an "ERROR:..." or "TIMEOUT..." entry — has no
 * structure to key on and is returned as opaque, so it keeps its exact previous
 * behaviour: compared literally, and any disappearance counts as a removal.
 */
function parseSig(sig: string): { opaque: true; key: string } | {
  opaque: false; prefix: string; sinkType: string; sourceLine: number; sinkLine: number; detKey: string;
} {
  const m = /^(F:)?([a-z_0-9]+)@(-?\d+)->(-?\d+)$/.exec(sig);
  if (!m) return { opaque: true, key: sig };
  const [, prefix = '', sinkType, src, snk] = m;
  return {
    opaque: false, prefix, sinkType,
    sourceLine: Number(src), sinkLine: Number(snk),
    // The detection key deliberately keeps the surface prefix: a flows row and
    // a findings row for the same sink are different claims and must not
    // cancel each other out.
    detKey: `${prefix}${sinkType}@${snk}`,
  };
}

/** Detection keys present in a signature list. */
function detKeys(sigs: Iterable<string>): Set<string> {
  const out = new Set<string>();
  for (const s of sigs) { const p = parseSig(s); out.add(p.opaque ? p.key : p.detKey); }
  return out;
}

/** Findings whose reported source line sits after their own sink — impossible as written. */
function sourceAfterSink(result: Record<string, string[]>): number {
  let n = 0;
  for (const sigs of Object.values(result)) {
    for (const s of sigs) {
      const p = parseSig(s);
      if (!p.opaque && p.sourceLine > p.sinkLine) n++;
    }
  }
  return n;
}

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
  // #378 — record WHICH commit was materialised, so a snapshot taken against
  // this tree can report its real provenance instead of the repo's HEAD.
  const head = execSync(`git -C "${REPO}" rev-parse ${ref}`, { encoding: 'utf8' }).trim();
  writeFileSync(join(out, PRETREE_MARKER), JSON.stringify({ ref, head }, null, 1));
  console.log(`pre-tree ready (${ref} = ${head.slice(0, 7)}): --src ${join(out, 'packages', 'circle-ir', 'src')}`);
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
          // #361 — method ranges for the proximity gate. Older trees have a
          // 7-parameter `generateFindings` and simply ignore this, so a
          // pretree base snapshot is unaffected.
          ir?.types ?? [],
          // #372 — flow-derived findings. Older trees take 8 parameters or
          // fewer and ignore the extra argument, so pretree baselines stay
          // valid.
          ir?.taint?.flows ?? [],
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
  const provenance = resolveProvenance(srcDir);
  writeFileSync(outFile, JSON.stringify({ src: srcDir, corpus: resolve(corpus), surface, provenance, files: files.length, errors, result }, null, 1));
  if (provenance) {
    console.error(`  provenance: ${provenance.from} branch=${provenance.branch} head=${provenance.head.slice(0, 7)}${provenance.dirty ? ' DIRTY' : ''} src=${provenance.srcResolved}`);
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
    ? `${d.provenance.from} ${d.provenance.branch}@${String(d.provenance.head).slice(0, 7)}`
      + `${d.provenance.dirty ? ' DIRTY' : ''}`
      + `${d.provenance.srcResolved ? `\n        src ${d.provenance.srcResolved}` : ''}`
    : '(no provenance recorded)';
  console.log(`before: ${pv(beforeDoc)}`);
  console.log(`after:  ${pv(afterDoc)}`);
  const pb = beforeDoc.provenance, pa = afterDoc.provenance;
  // #378 — the refusal now keys on (commit, tree) rather than on `from`. Same
  // commit AND same source tree, neither dirty, cannot contain a code
  // difference whether the tree is a working tree or a pretree. Same commit but
  // DIFFERENT trees is legitimate and must not be refused — that is the
  // pretree-vs-worktree comparison used to measure an unmerged branch.
  if (pb && pa && pb.head === pa.head && !pb.dirty && !pa.dirty
      && (pb.srcResolved ?? '?') === (pa.srcResolved ?? '!')) {
    throw new Error(
      `both snapshots came from the same clean commit (${String(pb.head).slice(0, 7)}) ` +
      `AND the same source tree (${pb.srcResolved}) — they cannot differ, so this diff ` +
      `would prove nothing. Re-snapshot the base from a pretree ` +
      `(\`bench-diff pretree <ref> <dir>\`) or the post from the tree carrying the fix.`,
    );
  }
  const before = beforeDoc.result as Record<string, string[]>;
  const after = afterDoc.result as Record<string, string[]>;
  const expected = opt('--expected') ? readExpected(opt('--expected')!) : null;
  const allow = opt('--allow') ? new RegExp(opt('--allow')!) : null;
  const { rows, removed, added, tpLoss, disallowed, filesChanged, reattributed } =
    classify(before, after, expected, allow);
  const sasBefore = sourceAfterSink(before), sasAfter = sourceAfterSink(after);
  if (rows.length) console.log(rows.join('\n'));
  console.log(
    `\nsummary: files_changed=${filesChanged} removed=${removed} added=${added} ` +
    `reattributed=${reattributed} tp_loss=${tpLoss} removed_outside_allow=${disallowed}`,
  );
  console.log(
    `detection-level: lost=${tpLoss + disallowed} (gated)  ` +
    `source_after_sink: ${sasBefore} -> ${sasAfter}`,
  );
  console.log(tpLoss === 0 && disallowed === 0 ? 'GATE: PASS' : 'GATE: FAIL');
  process.exit(tpLoss === 0 && disallowed === 0 ? 0 : 1);
} else if (cmd === 'selftest') {
  // Assertions on `classify` and `sourceAfterSink`. Run after any edit to the
  // gate: `bun bench-diff.mts selftest`. The case that matters most is the
  // first one — a re-attribution on an expected=true file must NOT be TP loss,
  // which is the exact defect #380 was filed for.
  let failures = 0;
  const check = (name: string, cond: boolean, detail = '') => {
    if (cond) { console.log(`  ok   ${name}`); }
    else { console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`); failures++; }
  };
  const expTrue = new Map([['T', true]]);
  const expFalse = new Map([['T', false]]);

  // 1. #380's defect: source line moves, detection preserved, file is a real
  //    vulnerability. Must be REATTRIBUTED and must NOT gate.
  {
    const r = classify({ 'T.py': ['xss@21->45'] }, { 'T.py': ['xss@42->45'] }, expTrue, null);
    check('re-attribution on expected=true is not TP loss', r.tpLoss === 0 && r.disallowed === 0, `tpLoss=${r.tpLoss} disallowed=${r.disallowed}`);
    check('re-attribution is counted as such', r.reattributed === 1, `reattributed=${r.reattributed}`);
    check('re-attribution emits no bare ADDED row', !r.rows.some(x => x.startsWith('ADDED')), r.rows.join(' | '));
    check('re-attribution row pairs old -> new', r.rows[0].includes('xss@21->45 -> xss@42->45'), r.rows[0]);
  }
  // 2. A genuine detection loss on a real vulnerability must still gate.
  {
    const r = classify({ 'T.py': ['xss@21->45'] }, { 'T.py': [] }, expTrue, null);
    check('genuine detection loss on expected=true is TP loss', r.tpLoss === 1 && r.reattributed === 0, `tpLoss=${r.tpLoss}`);
  }
  // 3. A genuine loss on a non-vulnerable file, with no --allow, stays gated.
  {
    const r = classify({ 'T.py': ['xss@21->45'] }, { 'T.py': [] }, expFalse, null);
    check('unclassified removal gates without --allow', r.disallowed === 1, `disallowed=${r.disallowed}`);
  }
  // 4. --allow exempts the targeted FP shape on a non-vulnerable file.
  {
    const r = classify({ 'T.py': ['xss@21->45'] }, { 'T.py': [] }, expFalse, /^xss@/);
    check('--allow exempts the targeted shape', r.disallowed === 0, `disallowed=${r.disallowed}`);
  }
  // 5. Pure addition never gates.
  {
    const r = classify({ 'T.py': [] }, { 'T.py': ['xss@21->45'] }, expTrue, null);
    check('pure addition does not gate', r.tpLoss === 0 && r.disallowed === 0 && r.added === 1);
  }
  // 6. The two surfaces must not cancel each other: a flows row and a findings
  //    row for the same sink are different claims (#373).
  {
    const r = classify({ 'T.py': ['xss@21->45'] }, { 'T.py': ['F:xss@21->45'] }, expTrue, null);
    check('flows and findings rows do not cancel', r.tpLoss === 1 && r.reattributed === 0, `tpLoss=${r.tpLoss} reattributed=${r.reattributed}`);
  }
  // 7. A different SINK line is a different detection, not a re-attribution.
  {
    const r = classify({ 'T.py': ['xss@21->45'] }, { 'T.py': ['xss@21->99'] }, expTrue, null);
    check('a moved sink line is a real loss, not a re-attribution', r.tpLoss === 1 && r.reattributed === 0, `tpLoss=${r.tpLoss}`);
  }
  // 8. Opaque rows (ERROR/TIMEOUT) keep their literal behaviour.
  {
    const r = classify({ 'T.py': ['TIMEOUT after 60000ms'] }, { 'T.py': ['xss@1->2'] }, expFalse, null);
    check('opaque row disappearing is a plain removal', r.disallowed === 1 && r.reattributed === 0, `disallowed=${r.disallowed}`);
  }
  // 9. source-after-sink only counts the impossible direction.
  {
    const n = sourceAfterSink({ 'a.py': ['xss@9->5', 'F:xss@1->5', 'sqli@7->7'], 'b.py': ['ERROR:boom'] });
    check('sourceAfterSink counts only source>sink', n === 1, `got ${n}`);
  }
  // 10. parseSig round-trips both surfaces and rejects junk.
  {
    const a = parseSig('F:path_traversal@33->60');
    const b = parseSig('ERROR:nope');
    check('parseSig reads the findings prefix', !a.opaque && a.prefix === 'F:' && a.sinkType === 'path_traversal' && a.sourceLine === 33 && a.sinkLine === 60);
    check('parseSig marks junk opaque', b.opaque === true);
  }
  console.log(failures === 0 ? '\nselftest: PASS' : `\nselftest: ${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
} else {
  console.error('commands: pretree | snapshot | diff | selftest'); process.exit(2);
}
