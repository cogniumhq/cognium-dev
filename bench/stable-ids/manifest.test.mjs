// The committed set: its digests hold and it has the shape the README states
// (node --test; no network).
import test from 'node:test';
import assert from 'node:assert/strict';
import { ADMITTED_LICENCES, HERE, loadManifest, readLabels } from './pairs.mjs';
import { verifyManifest } from './run.mjs';

const manifest = loadManifest(HERE);

test('the sealed manifest and label files verify', () => {
  const { problems } = verifyManifest(HERE);
  assert.deepEqual(problems, []);
});

test('30 consecutive pairs from several repositories, permissive licences only', () => {
  assert.equal(manifest.pairs.length, 30);
  assert.equal(manifest.scheme, 'ids@0.1');
  const repos = new Set(manifest.pairs.map(p => p.repository));
  assert.ok(repos.size >= 6, `${repos.size} repositories`);
  for (const p of manifest.pairs) {
    assert.ok(ADMITTED_LICENCES.has(p.licence), `${p.id}: ${p.licence}`);
    assert.match(p.before, /^[0-9a-f]{40}$/);
    assert.match(p.after, /^[0-9a-f]{40}$/);
    assert.notEqual(p.before, p.after);
    assert.ok(p.licence_file && /^[0-9a-f]{40}$/.test(p.licence_file.blob), `${p.id}: licence file pinned`);
    assert.ok(p.files.length > 0);
  }
  const licences = new Set(manifest.pairs.map(p => p.licence));
  assert.ok(licences.has('MIT') && licences.has('Apache-2.0') && [...licences].some(l => l.startsWith('BSD')), [...licences].join(','));
});

test('every edit kind is exercised by several pairs', () => {
  const count = k => manifest.pairs.filter(p => p.kinds.includes(k)).length;
  for (const k of ['body', 'signature', 'rename', 'move', 'reorder', 'format']) {
    assert.ok(count(k) >= 3, `${k}: ${count(k)} pairs`);
  }
});

test('labels cover both outcomes and say why a declaration is set aside', () => {
  let stable = 0;
  let changed = 0;
  for (const p of manifest.pairs) {
    for (const r of readLabels(HERE, p)) {
      if (r.judgement) {
        assert.equal(r.label, null);
        assert.ok(['formatting', 'header', 'member-order', 'member-header', 'signature-order', 'duplicate', 'parse-error'].includes(r.judgement), r.judgement);
      } else if (r.label === 'stable') {
        stable++;
        assert.ok(r.after, 'a stable declaration names its partner');
      } else {
        changed++;
        assert.equal(r.label, 'changed');
        assert.ok(r.change === 'body' ? !!r.after : r.after === null && !!r.reason);
      }
    }
  }
  assert.ok(stable > 0 && changed > 0);
});
