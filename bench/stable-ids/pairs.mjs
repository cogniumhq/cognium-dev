// Pins, digests and the local corpus for the stable-ids conformance set.
//
// Pairs are pinned by repository and commit pair in manifest.json, the same
// way bench/ pins its other corpora: fetched next to the repo under
// $CORPUS_ROOT, never committed. A fetch is a shallow, blob-less clone of the
// later commit and its parent; only the touched files are written out, and
// the clone is deleted afterwards. Each written file is checked against the
// git blob id the manifest records, so `check` needs no git and no network.

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, renameSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const HERE = dirname(fileURLToPath(import.meta.url));
export const PIN_MARKER = '.stable-ids-pin';

/** The git blob id of `content` (what `git hash-object` prints). */
export function gitBlobId(content) {
  const buf = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
  return createHash('sha1').update(`blob ${buf.length}\0`).update(buf).digest('hex');
}

export function sha256(content) {
  return 'sha256:' + createHash('sha256').update(content).digest('hex');
}

/** JSON with object keys sorted at every level: the form every digest is taken over. */
export function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}

/** Digest of what a pair pins: repository, commits, licence file and every touched file's blobs. */
export function pairDigest(pair) {
  const { repository, before, after, licence, licence_file, files } = pair;
  return sha256(canonical({ repository, before, after, licence, licence_file, files }));
}

/** Digest over every pair entry (pins, counts, kinds and label digests). */
export function setDigest(pairs) {
  return sha256(canonical(pairs));
}

export function loadManifest(dir = HERE) {
  return JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
}

export function labelsPath(dir, pair) {
  return join(dir, pair.labels);
}

export function readLabels(dir, pair) {
  const text = readFileSync(labelsPath(dir, pair), 'utf8');
  return text.split('\n').filter(Boolean).map(l => JSON.parse(l));
}

/** One label record per line, in the order given. */
export function labelsText(records) {
  return records.map(r => JSON.stringify(r)).join('\n') + '\n';
}

/** Paths a pair never labels even when they are TypeScript: build output, vendored and generated code, fixtures. */
export function isExcludedPath(path) {
  return /(^|\/)(dist|build|vendor|node_modules|__snapshots__|fixtures?)\//.test(path) || /\.(gen|generated)\.ts$/.test(path);
}

export function corpusRoot(env = process.env) {
  const root = env.CORPUS_ROOT;
  if (!root) throw new Error('CORPUS_ROOT is not set. Point it at a directory outside this repository.');
  if (!root.startsWith('/')) throw new Error(`CORPUS_ROOT must be an absolute path (got '${root}').`);
  return root;
}

export function pairDir(root, pair) {
  return join(root, 'stable-ids', pair.id);
}

function sidePath(root, pair, side, path) {
  return join(pairDir(root, pair), side, path);
}

/** Text of one touched file on side `before` or `after` from the local corpus. */
export function readPairFile(root, pair, side, path) {
  return readFileSync(sidePath(root, pair, side, path), 'utf8');
}

/**
 * Verify a pair under `root` against its pin. Read-only.
 * Returns a list of problems (empty when the pair is present and intact).
 */
export function checkPair(root, pair) {
  const dir = pairDir(root, pair);
  if (!existsSync(dir)) return [`MISSING  ${pair.id}: not under $CORPUS_ROOT`];
  const marker = join(dir, PIN_MARKER);
  if (!existsSync(marker) || readFileSync(marker, 'utf8').trim() !== pair.digest) {
    return [`DRIFT    ${pair.id}: fetched for a different pin; remove it and fetch again`];
  }
  const problems = [];
  for (const f of pair.files) {
    for (const side of ['before', 'after']) {
      if (!f[side]) continue;
      const p = sidePath(root, pair, side, f[side]);
      if (!existsSync(p)) { problems.push(`MISSING  ${pair.id}: ${side}/${f[side]}`); continue; }
      if (gitBlobId(readFileSync(p)) !== f[side + '_blob']) problems.push(`DIRTY    ${pair.id}: ${side}/${f[side]} differs from its pinned blob`);
    }
  }
  return problems;
}

function runGit(cwd, args, input) {
  return execFileSync('git', args, { cwd, input, encoding: 'buffer', maxBuffer: 1 << 28, stdio: ['pipe', 'pipe', 'pipe'] });
}

/**
 * A shallow, blob-less clone of `afters` and their parents, in a fresh
 * directory. Call `close()` to delete it.
 */
export function openClone(dir, repository, afters) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const git = (args, input) => runGit(dir, args, input);
  git(['init', '-q']);
  git(['remote', 'add', 'origin', repository]);
  git(['config', 'remote.origin.promisor', 'true']);
  git(['config', 'remote.origin.partialclonefilter', 'blob:none']);
  git(['fetch', '-q', '--no-tags', '--filter=blob:none', '--depth=2', 'origin', ...afters]);
  return {
    git,
    text: args => git(args).toString('utf8'),
    /** Fetch blobs by id in batches, so reading them later needs no further round trips. */
    prefetch(oids) {
      const want = [...new Set(oids)].filter(o => o && !/^0+$/.test(o));
      for (let i = 0; i < want.length; i += 200) {
        git(['-c', 'fetch.negotiationAlgorithm=noop', 'fetch', '-q', '--no-tags', '--no-write-fetch-head', '--filter=blob:none', 'origin', ...want.slice(i, i + 200)]);
      }
    },
    blob: oid => git(['cat-file', 'blob', oid]),
    parent: sha => git(['rev-parse', `${sha}^`]).toString('utf8').trim(),
    /** `{ path: oid }` for `paths` in the tree of `commit` (paths absent from it are missing). */
    lsTree(commit, paths) {
      const out = {};
      if (paths.length === 0) return out;
      const text = git(['ls-tree', '-z', commit, '--', ...paths]).toString('utf8');
      for (const entry of text.split('\0').filter(Boolean)) {
        const [meta, path] = entry.split('\t');
        out[path] = meta.split(' ')[2];
      }
      return out;
    },
    close: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/**
 * Fetch every pair in `pairs` that is missing under `root` (pairs from one
 * repository share one clone). An existing pair directory is never modified,
 * only checked. Returns the problems found (empty on success).
 */
export function fetchPairs(root, pairs, log = () => {}) {
  const problems = [];
  const byRepo = new Map();
  for (const p of pairs) {
    if (existsSync(pairDir(root, p))) {
      const pr = checkPair(root, p);
      problems.push(...pr);
      if (pr.length === 0) log(`ok       ${p.id}`);
      continue;
    }
    const g = byRepo.get(p.repository);
    if (g) g.push(p); else byRepo.set(p.repository, [p]);
  }
  for (const [repository, group] of byRepo) {
    const cloneDir = join(root, 'stable-ids', `.clone-${process.pid}`);
    let clone;
    try {
      clone = openClone(cloneDir, repository, group.map(p => p.after));
    } catch (e) {
      for (const p of group) problems.push(`FAILED   ${p.id}: could not fetch ${p.after} from ${repository}`);
      rmSync(cloneDir, { recursive: true, force: true });
      continue;
    }
    try {
      for (const p of group) {
        const pr = writePair(root, p, clone);
        problems.push(...pr);
        if (pr.length === 0) log(`fetch    ${p.id} @ ${p.after.slice(0, 7)}`);
      }
    } finally {
      clone.close();
    }
  }
  return problems;
}

function writePair(root, pair, clone) {
  const parent = clone.parent(pair.after);
  if (parent !== pair.before) return [`FAILED   ${pair.id}: ${pair.after.slice(0, 7)}^ is ${parent.slice(0, 7)}, pinned ${pair.before.slice(0, 7)}`];
  const problems = [];
  const sides = { before: pair.before, after: pair.after };
  const want = [];
  const trees = {};
  for (const side of ['before', 'after']) {
    const paths = pair.files.map(f => f[side]).filter(Boolean);
    if (side === 'after' && pair.licence_file) paths.push(pair.licence_file.path);
    trees[side] = clone.lsTree(sides[side], paths);
    for (const f of pair.files) {
      if (!f[side]) continue;
      if (trees[side][f[side]] !== f[side + '_blob']) problems.push(`DRIFT    ${pair.id}: ${side}/${f[side]} is ${trees[side][f[side]] ?? 'absent'} at the pinned commit, pinned ${f[side + '_blob']}`);
      want.push(f[side + '_blob']);
    }
  }
  if (pair.licence_file && trees.after[pair.licence_file.path] !== pair.licence_file.blob) {
    problems.push(`DRIFT    ${pair.id}: licence file ${pair.licence_file.path} differs from its pin`);
  }
  if (problems.length > 0) return problems;
  clone.prefetch(want);
  const dir = pairDir(root, pair);
  const tmp = `${dir}.partial.${process.pid}`;
  rmSync(tmp, { recursive: true, force: true });
  for (const f of pair.files) {
    for (const side of ['before', 'after']) {
      if (!f[side]) continue;
      const content = clone.blob(f[side + '_blob']);
      if (gitBlobId(content) !== f[side + '_blob']) {
        rmSync(tmp, { recursive: true, force: true });
        return [`FAILED   ${pair.id}: blob ${f[side + '_blob']} did not verify`];
      }
      const out = join(tmp, side, f[side]);
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, content);
    }
  }
  writeFileSync(join(tmp, PIN_MARKER), pair.digest + '\n');
  renameSync(tmp, dir);
  return [];
}

/** SPDX id of a licence text, for the permissive licences the set admits; null otherwise. */
export function licenceOf(text) {
  const t = text.replace(/\s+/g, ' ');
  if (/Permission is hereby granted, free of charge/i.test(t)) return 'MIT';
  if (/Apache License/i.test(t) && /Version 2\.0/i.test(t)) return 'Apache-2.0';
  if (/Redistribution and use in source and binary forms/i.test(t)) {
    return /Neither the name/i.test(t) || /names? of (?:its|the) contributors may (?:not )?be used/i.test(t) ? 'BSD-3-Clause' : 'BSD-2-Clause';
  }
  return null;
}

export const ADMITTED_LICENCES = new Set(['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause']);

/** The repository's root licence file at `commit`: `{ path, blob }`, or null. */
export function findLicenceFile(clone, commit) {
  const names = clone.text(['ls-tree', '--name-only', commit]).split('\n').filter(Boolean);
  const hit = names.filter(n => /^(?:licen[cs]e|copying)(?:[.-](?:md|txt|mit|apache))?$/i.test(n)).sort()[0];
  if (!hit) return null;
  return { path: hit, blob: clone.lsTree(commit, [hit])[hit] };
}
