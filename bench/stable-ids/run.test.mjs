// End-to-end tests over a local git repository (node --test; no network).
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, mkdirSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { canonical, checkPair, fetchPairs, gitBlobId, licenceOf, loadManifest, pairDigest, setDigest, sha256 } from './pairs.mjs';
import { checkProviderOutput, main, parseSelection, scoreSet, sealPairs, verifyManifest } from './run.mjs';
import * as reference from './providers/reference.mjs';

const tmp = mkdtempSync(join(tmpdir(), 'stable-ids-test-'));
test.after(() => rmSync(tmp, { recursive: true, force: true }));

function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

/** A repository with two commits; the second edits, renames, reorders and moves. */
function makeRepo() {
  const repo = join(tmp, 'origin');
  mkdirSync(join(repo, 'src'), { recursive: true });
  git(repo, 'init', '-q', '-b', 'main');
  git(repo, 'config', 'user.email', 'test@example.invalid');
  git(repo, 'config', 'user.name', 'test');
  git(repo, 'config', 'uploadpack.allowFilter', 'true');
  git(repo, 'config', 'uploadpack.allowAnySHA1InWant', 'true');
  writeFileSync(join(repo, 'LICENSE'), 'Test licence.\n\nPermission is hereby granted, free of charge, to any person obtaining a copy.\n');
  writeFileSync(join(repo, 'src', 'a.ts'), [
    'export function keep(a: string): number { return a.length }',
    'export function edit(a: string): number { return 1 }',
    'export function oldName(a: number) { return a * 2 }',
    'export class K {',
    '  one(): void { first(); }',
    '  two(): void { second(); }',
    '}',
    '',
  ].join('\n'));
  writeFileSync(join(repo, 'src', 'm.ts'), 'export function mv(x: number): number { return x + 1 }\n');
  writeFileSync(join(repo, 'README.md'), 'r\n');
  git(repo, 'add', '-A');
  git(repo, 'commit', '-q', '-m', 'one');
  writeFileSync(join(repo, 'src', 'a.ts'), [
    '// changed comment',
    'export function keep(a: string): number {',
    '  return a.length',
    '}',
    'export function edit(a: string): number { return 2 }',
    'export function newName(a: number) { return a * 2 }',
    'export class K {',
    '  two(): void { second(); }',
    '  one(): void { first(); }',
    '}',
    '',
  ].join('\n'));
  mkdirSync(join(repo, 'lib'));
  git(repo, 'mv', 'src/m.ts', 'lib/m.ts');
  writeFileSync(join(repo, 'README.md'), 'r2\n');
  git(repo, 'add', '-A');
  git(repo, 'commit', '-q', '-m', 'two');
  return { repo, after: git(repo, 'rev-parse', 'HEAD'), before: git(repo, 'rev-parse', 'HEAD^') };
}

const origin = makeRepo();
const url = pathToFileURL(origin.repo).href;
const setDir = join(tmp, 'set');
const root = join(tmp, 'corpus');
mkdirSync(setDir);

test('gitBlobId matches git hash-object; canonical JSON sorts keys', () => {
  const f = join(tmp, 'blob.txt');
  writeFileSync(f, 'héllo\n');
  assert.equal(gitBlobId(readFileSync(f)), git(tmp, 'hash-object', f));
  assert.equal(gitBlobId('héllo\n'), git(tmp, 'hash-object', f));
  assert.equal(canonical({ b: 1, a: [{ d: null, c: 'x' }] }), '{"a":[{"c":"x","d":null}],"b":1}');
  assert.match(sha256('x'), /^sha256:[0-9a-f]{64}$/);
});

test('licenceOf admits MIT, Apache-2.0 and BSD only', () => {
  assert.equal(licenceOf('Permission is hereby granted, free of charge, to any person'), 'MIT');
  assert.equal(licenceOf('Apache License\n  Version 2.0, January 2004'), 'Apache-2.0');
  assert.equal(licenceOf('Redistribution and use in source and binary forms ... Neither the name of'), 'BSD-3-Clause');
  assert.equal(licenceOf('Redistribution and use in source and binary forms, with or without'), 'BSD-2-Clause');
  assert.equal(licenceOf('GNU GENERAL PUBLIC LICENSE Version 3'), null);
});

test('parseSelection reads id, repository and commit; rejects bad lines', () => {
  assert.deepEqual(parseSelection(`# comment\nx-01 ${url} ${origin.after}\n`), [{ id: 'x-01', repository: url, after: origin.after }]);
  assert.throws(() => parseSelection('x-01 repo notasha'));
});

test('seal pins the pair, lists the touched files and writes labels', () => {
  const manifest = sealPairs([{ id: 'local-01', repository: url, after: origin.after }], { root, dir: setDir });
  assert.equal(manifest.pairs.length, 1);
  const p = manifest.pairs[0];
  assert.equal(p.before, origin.before);
  assert.equal(p.licence, 'MIT');
  assert.equal(p.licence_file.path, 'LICENSE');
  assert.deepEqual(p.files.map(f => `${f.before}->${f.after}`), ['src/a.ts->src/a.ts', 'src/m.ts->lib/m.ts']);
  assert.deepEqual(p.kinds, ['add', 'body', 'format', 'move', 'rename', 'reorder']);
  assert.equal(p.digest, pairDigest(p));
  assert.equal(manifest.digest, setDigest(manifest.pairs));
  const labels = readFileSync(join(setDir, p.labels), 'utf8').trim().split('\n').map(l => JSON.parse(l));
  const by = Object.fromEntries(labels.map(l => [(l.chain ? l.chain + '.' : '') + (l.name || l.file), l]));
  assert.equal(by.keep.label, 'stable');
  assert.equal(by.edit.change, 'body');
  assert.equal(by.oldName.reason, 'renamed');
  assert.equal(by['K.one'].label, 'stable');
  assert.equal(by.K.judgement, 'member-order');
  assert.equal(by.mv.reason, 'moved');
});

test('verify accepts the sealed set and catches tampering', () => {
  assert.deepEqual(verifyManifest(setDir).problems, []);
  assert.deepEqual(verifyManifest(setDir, { relabel: true, root }).problems, []);
  const m = loadManifest(setDir);
  const lp = join(setDir, m.pairs[0].labels);
  const saved = readFileSync(lp, 'utf8');
  writeFileSync(lp, saved.replace('"label":"stable"', '"label":"changed"'));
  const problems = verifyManifest(setDir).problems;
  assert.ok(problems.some(x => x.includes('does not match its digest')));
  writeFileSync(lp, saved);
  const mp = join(setDir, 'manifest.json');
  const savedManifest = readFileSync(mp, 'utf8');
  writeFileSync(mp, savedManifest.replace(origin.before, origin.after));
  assert.ok(verifyManifest(setDir).problems.some(x => x.includes('pin digest')));
  writeFileSync(mp, savedManifest);
});

test('fetch writes the pinned files and deletes its clone; check catches edits', () => {
  const fresh = join(tmp, 'corpus2');
  const m = loadManifest(setDir);
  assert.deepEqual(fetchPairs(fresh, m.pairs), []);
  assert.deepEqual(readdirSync(join(fresh, 'stable-ids')), ['local-01'], 'no clone or partial directory is left');
  assert.deepEqual(checkPair(fresh, m.pairs[0]), []);
  assert.deepEqual(fetchPairs(fresh, m.pairs), [], 'a second fetch only checks');
  appendFileSync(join(fresh, 'stable-ids', 'local-01', 'after', 'src', 'a.ts'), '// edit\n');
  assert.match(checkPair(fresh, m.pairs[0])[0], /^DIRTY/);
  assert.match(checkPair(join(tmp, 'nowhere'), m.pairs[0])[0], /^MISSING/);
  // a pin whose parent is wrong fails, and leaves nothing behind
  const bad = { ...m.pairs[0], id: 'bad-01', before: m.pairs[0].after };
  const problems = fetchPairs(fresh, [bad]);
  assert.match(problems[0], /^FAILED/);
  assert.deepEqual(readdirSync(join(fresh, 'stable-ids')), ['local-01']);
});

test('score: the reference stub scores 100%; a positional stub does not', async () => {
  const good = await scoreSet({ dir: setDir, root, provider: reference, nodes: true });
  assert.equal(good.metrics.precision.value, 1);
  assert.equal(good.totals.nodes.checked, 0, 'the reference stub gives no node ids, so none are compared');
  assert.equal(good.totals.nodes.kept, 0);
  assert.equal(good.metrics.recall.value, 1);
  assert.equal(good.totals.unjoined, 0);
  assert.equal(good.metrics.body_keeps_decl.value, 1);
  assert.equal(good.metrics.identity_new_decl.value, 1);

  // Ids from position: any edit above a declaration re-keys it.
  const positional = {
    name: 'positional',
    async derive(code, file) {
      const r = await reference.derive(code, file);
      return { ...r, decls: r.decls.map(x => ({ ...x, id: `${file}:${x.start_line}`, body_id: `${file}:${x.start_line}.${x.body_id}` })) };
    },
  };
  const bad = await scoreSet({ dir: setDir, root, provider: positional });
  assert.ok(bad.metrics.recall.value < 1);
  assert.ok(bad.pairs[0].misses.length > 0);

  // A provider that throws on a file: no declarations for it, reported.
  // A provider that answers with nothing to score: every file is a provider error.
  const empty = { name: 'empty', async derive() { return { decls: [] }; } };
  const e = await scoreSet({ dir: setDir, root, provider: empty });
  assert.equal(e.provider_errors.length, 4);
  assert.match(e.provider_errors[0], /no root declaration/);

  const broken = { name: 'broken', async derive() { throw new Error('boom'); } };
  const r = await scoreSet({ dir: setDir, root, provider: broken });
  assert.equal(r.provider_errors.length, 4);
  assert.equal(r.metrics.recall.value, 0);

  const missing = await scoreSet({ dir: setDir, root: join(tmp, 'nowhere'), provider: reference });
  assert.ok(missing.missing.length > 0);
});

test('checkProviderOutput rejects results that cannot be scored', () => {
  const root = { id: 'm', body_id: 'm.b', name: '', kind: 'module', start_line: 1, end_line: 2, parent: null };
  assert.equal(checkProviderOutput({ decls: [root] }), null);
  assert.match(checkProviderOutput(undefined), /no result/);
  assert.match(checkProviderOutput({}), /no decls array/);
  assert.match(checkProviderOutput({ decls: 'x' }), /no decls array/);
  assert.match(checkProviderOutput({ decls: [] }), /no root declaration/);
  assert.match(checkProviderOutput({ decls: [{ ...root, parent: 'm' }] }), /no root declaration/);
  assert.match(checkProviderOutput({ decls: [{ ...root, id: 7 }] }), /lacks a string id/);
  assert.match(checkProviderOutput({ decls: [{ ...root, start_line: '1' }] }), /integer start_line/);
});

test('the command line: list, verify, check, score', async () => {
  const log = [];
  const orig = console.log;
  const origErr = console.error;
  console.log = (...a) => log.push(a.join(' '));
  console.error = (...a) => log.push(a.join(' '));
  const env = process.env.CORPUS_ROOT;
  process.env.CORPUS_ROOT = root;
  try {
    assert.equal(await main(['list', '--dir', setDir]), 0);
    assert.equal(await main(['verify', '--dir', setDir]), 0);
    assert.equal(await main(['check', '--dir', setDir]), 0);
    const json = join(tmp, 'report.json');
    assert.equal(await main(['score', '--dir', setDir, '--provider', join(import.meta.dirname, 'providers', 'reference.mjs'), '--json', json, '--strict']), 0);
    assert.equal(JSON.parse(readFileSync(json, 'utf8')).metrics.recall.value, 1);
    const broken = join(tmp, 'broken-provider.mjs');
    writeFileSync(broken, "export async function derive() { throw new Error('boom'); }\n");
    assert.equal(await main(['score', '--dir', setDir, '--provider', broken]), 1, 'provider errors fail the run');
    const empty = join(tmp, 'empty-provider.mjs');
    writeFileSync(empty, 'export async function derive() { return { decls: [] }; }\n');
    assert.equal(await main(['score', '--dir', setDir, '--provider', empty]), 1, 'an empty answer fails the run');
    assert.equal(await main(['check', '--dir', setDir, 'no-such-pair']).catch(e => e.message), "unknown pair 'no-such-pair'");
    assert.equal(await main(['bogus']), 2);
  } finally {
    console.log = orig;
    console.error = origErr;
    if (env === undefined) delete process.env.CORPUS_ROOT; else process.env.CORPUS_ROOT = env;
  }
  assert.ok(log.some(l => l.includes('local-01')));
  assert.ok(log.some(l => l.startsWith('precision of stable')));
});
