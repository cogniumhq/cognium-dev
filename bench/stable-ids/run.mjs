#!/usr/bin/env node
// The stable-ids conformance set: list, fetch, check, verify, score, seal.
// See README.md in this directory.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { LABEL_RULE, isLabelledPath, labelPair, loadTypeScript, summarize } from './label.mjs';
import {
  ADMITTED_LICENCES, HERE, checkPair, corpusRoot, fetchPairs, findLicenceFile, gitBlobId, isExcludedPath,
  labelsText, licenceOf, loadManifest, openClone, pairDigest, readLabels, readPairFile, setDigest, sha256,
} from './pairs.mjs';
import { addCounts, formatRatio, metrics, scorePair, totals } from './score.mjs';

const USAGE = `usage: node bench/stable-ids/run.mjs <command> [options] [pair-id...]

  list                       print the pinned pairs
  verify [--relabel]         check the manifest's digests and label files;
                             --relabel also re-derives every label from the
                             fetched corpus and compares (needs CORPUS_ROOT)
  fetch                      fetch missing pairs into $CORPUS_ROOT/stable-ids/
  check                      verify fetched pairs against their pins (read-only)
  score [--provider <file>] [--nodes] [--json <file>] [--strict] [--show <n>]
                             measure a provider's ids against the labels
                             (default provider: providers/circle-ir.mjs)
  seal <selection-file>      build manifest.json and labels/ from a selection
                             (lines "id repository-url after-sha"); maintainers only

options: --dir <dir> uses another set directory (default: this one)`;

function parseArgs(argv) {
  const opts = { ids: [], provider: null, json: null, nodes: false, strict: false, relabel: false, show: 10, dir: HERE };
  const [cmd, ...rest] = argv;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--provider') opts.provider = rest[++i];
    else if (a === '--json') opts.json = rest[++i];
    else if (a === '--nodes') opts.nodes = true;
    else if (a === '--strict') opts.strict = true;
    else if (a === '--relabel') opts.relabel = true;
    else if (a === '--show') opts.show = Number(rest[++i]);
    else if (a === '--dir') opts.dir = resolve(rest[++i]);
    else if (a.startsWith('--')) throw new Error(`unknown option ${a}\n\n${USAGE}`);
    else opts.ids.push(a);
  }
  return { cmd, opts };
}

function selectPairs(manifest, ids) {
  if (ids.length === 0) return manifest.pairs;
  const known = new Map(manifest.pairs.map(p => [p.id, p]));
  return ids.map(id => {
    const p = known.get(id);
    if (!p) throw new Error(`unknown pair '${id}'`);
    return p;
  });
}

// ---------------------------------------------------------------------------

/** Check the manifest against itself and its label files; optionally re-derive the labels. */
export function verifyManifest(dir, { relabel = false, root = null } = {}) {
  const manifest = loadManifest(dir);
  const problems = [];
  const notes = [];
  if (manifest.label_rule !== LABEL_RULE) problems.push(`manifest label rule ${manifest.label_rule}, labeller is ${LABEL_RULE}`);
  const ids = new Set();
  for (const p of manifest.pairs) {
    if (ids.has(p.id)) problems.push(`${p.id}: duplicate pair id`);
    ids.add(p.id);
    if (!ADMITTED_LICENCES.has(p.licence)) problems.push(`${p.id}: licence ${p.licence} is not admitted`);
    if (pairDigest(p) !== p.digest) problems.push(`${p.id}: pin digest does not match its entry`);
    const lp = join(dir, p.labels);
    if (!existsSync(lp)) { problems.push(`${p.id}: ${p.labels} is missing`); continue; }
    const text = readFileSync(lp);
    if (sha256(text) !== p.labels_digest) problems.push(`${p.id}: ${p.labels} does not match its digest`);
    const s = summarize(readLabels(dir, p));
    for (const k of Object.keys(s)) if (s[k] !== p.counts[k]) problems.push(`${p.id}: counts.${k} is ${p.counts[k]}, labels give ${s[k]}`);
  }
  if (setDigest(manifest.pairs) !== manifest.digest) problems.push('set digest does not match the pair entries');
  if (relabel) {
    const ts = loadTypeScript();
    const want = manifest.labeller && manifest.labeller.parser;
    if (want && want !== `typescript@${ts.version}`) notes.push(`labels were sealed with ${want}; re-deriving with typescript@${ts.version}`);
    for (const p of manifest.pairs) {
      const pr = checkPair(root, p);
      if (pr.length > 0) { problems.push(...pr); continue; }
      const r = labelPair(p.files.map(f => ({ before: f.before, after: f.after })), (side, path) => readPairFile(root, p, side, path));
      if (labelsText(r.records) !== readFileSync(join(dir, p.labels), 'utf8')) problems.push(`${p.id}: re-derived labels differ from ${p.labels}`);
      if (r.added !== p.counts.added) problems.push(`${p.id}: re-derived added count ${r.added}, sealed ${p.counts.added}`);
      if (r.kinds.join(',') !== p.kinds.join(',')) problems.push(`${p.id}: re-derived kinds ${r.kinds.join(',')}, sealed ${p.kinds.join(',')}`);
    }
  }
  return { manifest, problems, notes };
}

// ---------------------------------------------------------------------------

async function loadProvider(path) {
  const file = path ? resolve(path) : join(HERE, 'providers', 'circle-ir.mjs');
  const mod = await import(pathToFileURL(file).href);
  if (typeof mod.derive !== 'function') throw new Error(`provider ${file} exports no derive()`);
  return mod;
}

/** Why a provider's answer for one file cannot be scored, or null when it can. */
export function checkProviderOutput(ids) {
  if (!ids || typeof ids !== 'object') return 'the provider returned no result';
  if (!Array.isArray(ids.decls)) return 'the provider result has no decls array';
  const bad = ids.decls.find(d => !d || typeof d.id !== 'string' || typeof d.body_id !== 'string'
    || !Number.isInteger(d.start_line) || !Number.isInteger(d.end_line));
  if (bad) return 'a declaration lacks a string id and body_id or integer start_line and end_line';
  if (!ids.decls.some(d => d.parent === null || d.parent === undefined)) return 'no root declaration (a declaration with parent null) for the file';
  return null;
}

async function deriveSide(provider, root, pair, side, wantNodes, errors) {
  const decls = new Map();
  const nodes = new Map();
  const partial = new Set();
  for (const f of pair.files) {
    const path = f[side];
    if (!path) continue;
    const code = readPairFile(root, pair, side, path);
    try {
      const ids = await provider.derive(code, path);
      const problem = checkProviderOutput(ids);
      if (problem) {
        errors.push(`${pair.id}: ${side}/${path}: ${problem}`);
        decls.set(path, []);
        continue;
      }
      decls.set(path, ids.decls);
      if (ids.partial) partial.add(path);
      if (wantNodes && typeof provider.nodes === 'function') {
        const n = await provider.nodes(code, path, ids);
        if (n) nodes.set(path, n);
      }
    } catch (e) {
      errors.push(`${pair.id}: ${side}/${path}: ${String(e && e.message ? e.message : e).split('\n')[0]}`);
      decls.set(path, []);
    }
  }
  return { decls, nodes, partial };
}

/** Score every selected pair; returns the report object (also what --json writes). */
export async function scoreSet({ dir = HERE, root, provider, pairs = null, nodes = false }) {
  const manifest = loadManifest(dir);
  const selected = pairs ?? manifest.pairs;
  const missing = selected.flatMap(p => checkPair(root, p));
  if (missing.length > 0) return { missing };
  const desc = typeof provider.describe === 'function' ? await provider.describe() : { provider: provider.name ?? 'unnamed' };
  const total = totals();
  const rows = [];
  const errors = [];
  for (const p of selected) {
    const records = readLabels(dir, p);
    const b = await deriveSide(provider, root, p, 'before', nodes, errors);
    const a = await deriveSide(provider, root, p, 'after', nodes, errors);
    const engine = { before: b.decls, after: a.decls, partial: { before: b.partial, after: a.partial } };
    if (nodes) engine.nodes = { before: b.nodes, after: a.nodes };
    const { counts, misses } = scorePair(records, engine);
    addCounts(total, counts);
    const partialFiles = [...[...b.partial].map(f => `before/${f}`), ...[...a.partial].map(f => `after/${f}`)];
    rows.push({ id: p.id, counts, metrics: metrics(counts), provider_partial: partialFiles, misses });
  }
  return { set: manifest.set, digest: manifest.digest, label_rule: manifest.label_rule, provider: desc, totals: total, metrics: metrics(total), pairs: rows, provider_errors: errors };
}

function printReport(report, show, wantNodes) {
  const pad = (s, n) => String(s).padEnd(n);
  const lpad = (s, n) => String(s).padStart(n);
  console.log(`set ${report.set} ${report.digest.slice(0, 19)}…  labels ${report.label_rule}  provider ${report.provider.provider}${report.provider.scheme ? ' (' + report.provider.scheme + ')' : ''}`);
  console.log('');
  console.log(`${pad('pair', 18)}${lpad('scored', 7)}${lpad('tp', 6)}${lpad('fp', 5)}${lpad('fn', 5)}${lpad('unjoined', 9)}${lpad('set aside', 10)}  precision / recall of stable`);
  for (const r of report.pairs) {
    const c = r.counts;
    const aside = Object.values(c.judgement).reduce((s, v) => s + v, 0);
    console.log(`${pad(r.id, 18)}${lpad(c.scored, 7)}${lpad(c.tp, 6)}${lpad(c.fp, 5)}${lpad(c.fn, 5)}${lpad(c.unjoined, 9)}${lpad(aside, 10)}  ${formatRatio(r.metrics.precision)} / ${formatRatio(r.metrics.recall)}`);
  }
  const t = report.totals;
  const m = report.metrics;
  console.log('');
  console.log(`declarations scored     ${t.scored} (labels: ${t.confusion.stable.stable + t.confusion.stable.body + t.confusion.stable.identity + t.confusion.stable.none} stable, ${Object.values(t.confusion.body).reduce((s, v) => s + v, 0)} body changed, ${Object.values(t.confusion.identity).reduce((s, v) => s + v, 0)} identity changed)`);
  console.log(`set aside (judgement)   ${Object.entries(t.judgement).map(([k, v]) => `${k} ${v}`).join(', ') || 'none'}`);
  const unjoinedStable = t.confusion.stable.none;
  console.log(`no provider declaration ${t.unjoined} (labelled stable ${unjoinedStable}${t.unjoined_partial ? `; in files the provider parsed only partly: ${t.unjoined_partial}, of them stable ${t.unjoined_partial_stable}` : ''})`);
  console.log(`precision of stable     ${formatRatio(m.precision)}`);
  console.log(`recall of stable        ${formatRatio(m.recall)}`);
  console.log(`body change keeps decl  ${formatRatio(m.body_keeps_decl)}`);
  console.log(`identity change, new id ${formatRatio(m.identity_new_decl)}`);
  console.log(`identity change, no decl ${formatRatio(m.identity_no_decl)}`);
  if (wantNodes) {
    const n = t.nodes;
    console.log(`node ids kept (stable)  ${n.checked === 0 ? 'n/a (the provider gave no node ids)' : `${n.kept}/${n.checked} correctly stable bodies with node ids`}; ${n.without} without node ids`);
  }
  console.log('');
  console.log('confusion (rows: label, columns: provider)');
  console.log(`${pad('', 10)}${['stable', 'body', 'identity', 'none'].map(x => lpad(x, 10)).join('')}`);
  for (const l of ['stable', 'body', 'identity']) console.log(`${pad(l, 10)}${['stable', 'body', 'identity', 'none'].map(x => lpad(t.confusion[l][x], 10)).join('')}`);
  const partial = report.pairs.flatMap(r => r.provider_partial.map(f => `${r.id}: ${f}`));
  if (partial.length > 0) {
    console.log('');
    console.log(`files the provider parsed only partly (${partial.length}):`);
    for (const f of partial.slice(0, show)) console.log('  ' + f);
  }
  if (report.provider_errors.length > 0) {
    console.log('');
    console.log(`provider errors (${report.provider_errors.length}):`);
    for (const e of report.provider_errors.slice(0, show)) console.log('  ' + e);
  }
  const misses = report.pairs.flatMap(r => r.misses.map(x => ({ pair: r.id, ...x })));
  if (misses.length > 0 && show > 0) {
    console.log('');
    console.log(`disagreements (${misses.length}; first ${Math.min(show, misses.length)}):`);
    for (const x of misses.slice(0, show)) console.log(`  ${x.pair} ${x.file}:${x.line} ${x.kind} ${x.name}: label ${x.label}, provider ${x.pred}${x.note ? ' (' + x.note + ')' : ''}`);
  }
}

// ---------------------------------------------------------------------------

/**
 * Build the sealed set from a selection: for each `{ id, repository, after }`,
 * pin the parent, list the touched TypeScript files, record the licence,
 * write the files under `root` and the labels under `dir`. Returns the manifest.
 */
export function sealPairs(selection, { root, dir, log = () => {} }) {
  const ts = loadTypeScript();
  const pairs = [];
  const byRepo = new Map();
  for (const s of selection) {
    const g = byRepo.get(s.repository);
    if (g) g.push(s); else byRepo.set(s.repository, [s]);
  }
  mkdirSync(join(dir, 'labels'), { recursive: true });
  mkdirSync(join(root, 'stable-ids'), { recursive: true });
  for (const [repository, group] of byRepo) {
    const clone = openClone(join(root, 'stable-ids', `.seal-${process.pid}`), repository, group.map(s => s.after));
    try {
      for (const s of group) {
        const parents = clone.text(['rev-list', '--parents', '-n', '1', s.after]).trim().split(' ').slice(1);
        if (parents.length !== 1) throw new Error(`${s.id}: ${s.after} has ${parents.length} parents; only single-parent commits are pairs`);
        const before = parents[0];
        const ext = ['--', '*.ts', '*.tsx', '*.mts', '*.cts'];
        const plain = clone.text(['diff-tree', '-r', '--raw', '--no-commit-id', before, s.after, ...ext]).trim();
        clone.prefetch(plain.split('\n').filter(Boolean).flatMap(l => l.split('\t')[0].split(' ').slice(2, 4)));
        const raw = clone.text(['diff-tree', '-r', '--raw', '-M50%', '--no-commit-id', before, s.after, ...ext]).trim();
        const keep = p => !!p && isLabelledPath(p) && !isExcludedPath(p);
        const files = [];
        for (const line of raw.split('\n').filter(Boolean)) {
          const [meta, ...paths] = line.split('\t');
          const m = meta.split(' ');
          const st = m[4][0];
          let b = null; let a = null;
          if (st === 'R') { b = paths[0]; a = paths[1]; } else if (st === 'A') a = paths[0];
          else if (st === 'D') b = paths[0]; else if (st === 'M') { b = paths[0]; a = paths[0]; } else continue;
          if (!keep(b)) b = null;
          if (!keep(a)) a = null;
          if (!b && !a) continue;
          files.push({ before: b, after: a, before_blob: b ? m[2] : null, after_blob: a ? m[3] : null });
        }
        files.sort((x, y) => ((x.before ?? x.after) < (y.before ?? y.after) ? -1 : 1));
        if (files.length === 0) throw new Error(`${s.id}: touches no labelled TypeScript file`);
        const licence_file = findLicenceFile(clone, s.after);
        if (!licence_file) throw new Error(`${s.id}: no licence file at the repository root`);
        clone.prefetch([licence_file.blob]);
        const licence = licenceOf(clone.blob(licence_file.blob).toString('utf8'));
        if (!licence || !ADMITTED_LICENCES.has(licence)) throw new Error(`${s.id}: licence file ${licence_file.path} is not MIT, Apache-2.0 or BSD`);
        const read = (side, path) => clone.blob(files.find(f => f[side] === path)[side + '_blob']).toString('utf8');
        const r = labelPair(files.map(f => ({ before: f.before, after: f.after })), read);
        const labels = `labels/${s.id}.jsonl`;
        const text = labelsText(r.records);
        writeFileSync(join(dir, labels), text);
        const pair = {
          id: s.id, repository, licence, licence_file, before, after: s.after, files,
          kinds: r.kinds, counts: { ...summarize(r.records), added: r.added },
          digest: null, labels, labels_digest: sha256(Buffer.from(text, 'utf8')),
        };
        pair.digest = pairDigest(pair);
        // Write the corpus copy so the pair can be scored without a second fetch.
        const pdir = join(root, 'stable-ids', s.id);
        if (!existsSync(pdir)) {
          for (const f of files) for (const side of ['before', 'after']) {
            if (!f[side]) continue;
            const content = clone.blob(f[side + '_blob']);
            if (gitBlobId(content) !== f[side + '_blob']) throw new Error(`${s.id}: blob did not verify`);
            const out = join(pdir, side, f[side]);
            mkdirSync(join(out, '..'), { recursive: true });
            writeFileSync(out, content);
          }
          writeFileSync(join(pdir, '.stable-ids-pin'), pair.digest + '\n');
        }
        pairs.push(pair);
        log(`sealed   ${s.id}: ${files.length} files, ${pair.counts.declarations} declarations, ${r.kinds.join(' ')}`);
      }
    } finally {
      clone.close();
    }
  }
  const order = new Map(selection.map((s, i) => [s.id, i]));
  pairs.sort((x, y) => order.get(x.id) - order.get(y.id));
  const manifest = {
    set: 'stable-ids-typescript',
    scheme: 'ids@0.1',
    language: 'typescript',
    label_rule: LABEL_RULE,
    labeller: { parser: `typescript@${ts.version}` },
    pairs,
    digest: setDigest(pairs),
  };
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  return manifest;
}

export function parseSelection(text) {
  return text.split('\n').map(l => l.replace(/#.*/, '').trim()).filter(Boolean).map(l => {
    const [id, repository, after] = l.split(/\s+/);
    if (!id || !repository || !/^[0-9a-f]{40}$/.test(after ?? '')) throw new Error(`bad selection line: ${l}`);
    return { id, repository, after };
  });
}

// ---------------------------------------------------------------------------

export async function main(argv) {
  const { cmd, opts } = parseArgs(argv);
  switch (cmd) {
    case 'list': {
      const m = loadManifest(opts.dir);
      console.log(`${m.set}: ${m.pairs.length} pairs, ${m.scheme}, labels ${m.label_rule}, ${m.digest}`);
      for (const p of selectPairs(m, opts.ids)) {
        const c = p.counts;
        console.log(`${p.id.padEnd(18)}${p.licence.padEnd(13)}${p.before.slice(0, 7)}..${p.after.slice(0, 7)}  ${p.repository}  ${c.declarations} decls (${c.stable} stable, ${c.body} body, ${c.identity} identity, ${c.judgement} set aside)  ${p.kinds.join(' ')}`);
      }
      return 0;
    }
    case 'verify': {
      const root = opts.relabel ? corpusRoot() : null;
      const { manifest, problems, notes } = verifyManifest(opts.dir, { relabel: opts.relabel, root });
      for (const n of notes) console.log(`note     ${n}`);
      for (const p of problems) console.error(p);
      if (problems.length > 0) return 1;
      console.log(`ok       ${manifest.pairs.length} pairs, ${manifest.digest}${opts.relabel ? ', labels re-derived' : ''}`);
      return 0;
    }
    case 'fetch':
    case 'check': {
      const root = corpusRoot();
      const pairs = selectPairs(loadManifest(opts.dir), opts.ids);
      const problems = cmd === 'fetch' ? fetchPairs(root, pairs, s => console.log(s)) : pairs.flatMap(p => {
        const pr = checkPair(root, p);
        if (pr.length === 0) console.log(`ok       ${p.id}`);
        return pr;
      });
      for (const p of problems) console.error(p);
      if (problems.length > 0) {
        console.error('stable-ids: one or more pairs are unavailable; do not score on them.');
        return 1;
      }
      return 0;
    }
    case 'score': {
      const root = corpusRoot();
      const provider = await loadProvider(opts.provider);
      const pairs = selectPairs(loadManifest(opts.dir), opts.ids);
      const report = await scoreSet({ dir: opts.dir, root, provider, pairs, nodes: opts.nodes });
      if (report.missing) {
        for (const p of report.missing) console.error(p);
        console.error('stable-ids: fetch the pairs first (run.mjs fetch).');
        return 1;
      }
      printReport(report, opts.show, opts.nodes);
      if (opts.json) writeFileSync(opts.json, JSON.stringify(report, null, 2) + '\n');
      if (report.provider_errors.length > 0) {
        console.error(`stable-ids: the provider failed on ${report.provider_errors.length} file(s); these numbers do not measure it.`);
        return 1;
      }
      if (opts.strict && (report.metrics.precision.value !== 1 || report.metrics.recall.value !== 1)) return 1;
      return 0;
    }
    case 'seal': {
      const [selectionFile] = opts.ids;
      if (!selectionFile) throw new Error(USAGE);
      const root = corpusRoot();
      const manifest = sealPairs(parseSelection(readFileSync(selectionFile, 'utf8')), { root, dir: opts.dir, log: s => console.log(s) });
      console.log(`sealed   ${manifest.pairs.length} pairs, ${manifest.digest}`);
      return 0;
    }
    default:
      console.error(USAGE);
      return cmd === undefined || cmd === 'help' || cmd === '--help' ? 0 : 2;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main(process.argv.slice(2)).then(code => { process.exitCode = code; }, e => {
    console.error(`stable-ids: ${e && e.message ? e.message : e}`);
    process.exitCode = 2;
  });
}
