/**
 * The offline OSV snapshot script (DT2, cognium-dev #1005): identity,
 * provenance, verification and the MAL- filter. No network.
 */

import { copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
// @ts-expect-error — plain .mjs script without types
import * as snap from '../../scripts/osv-snapshot.mjs';
import { buildAdvisoryIndex, parseOsvRecord, type OsvRecord } from '../../src/analysis/advisories.js';

const FIXTURE = fileURLToPath(new URL('../fixtures/osv-npm/', import.meta.url));
const SCRIPT = fileURLToPath(new URL('../../scripts/osv-snapshot.mjs', import.meta.url));

function copyFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'osv-snap-'));
  for (const n of readdirSync(FIXTURE)) copyFileSync(join(FIXTURE, n), join(dir, n));
  return dir;
}

describe('osv-snapshot', () => {
  it('pins the fixture snapshot: recorded provenance verifies', () => {
    const r = snap.verifySnapshot(FIXTURE);
    expect(r.problems).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('digest covers *.json records only, independent of README and PROVENANCE', () => {
    const dir = copyFixture();
    try {
      const before = snap.snapshotDigest(dir);
      writeFileSync(join(dir, 'README.md'), 'changed');
      writeFileSync(join(dir, 'PROVENANCE'), '{}');
      expect(snap.snapshotDigest(dir)).toBe(before);
      writeFileSync(join(dir, 'GHSA-new.json'), '{"id":"GHSA-new","modified":"2030-01-01T00:00:00Z"}');
      expect(snap.snapshotDigest(dir)).not.toBe(before);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('facts: record count, greatest modified, ecosystems; and the library index agrees on the date', () => {
    const facts = snap.snapshotFacts(FIXTURE);
    expect(facts.records).toBe(7);
    expect(facts.ecosystems).toEqual(['Maven', 'npm']);
    const records: OsvRecord[] = snap
      .recordFiles(FIXTURE)
      .map((n: string) => parseOsvRecord(readFileSync(join(FIXTURE, n), 'utf-8')))
      .filter((r: OsvRecord | null): r is OsvRecord => r !== null);
    expect(buildAdvisoryIndex(records, 'npm').snapshotDate <= facts.snapshotDate).toBe(true);
  });

  it('verify reports a tampered record', () => {
    const dir = copyFixture();
    try {
      writeFileSync(join(dir, 'TEST-PRE-0001.json'), '{"id":"TEST-PRE-0001","modified":"2024-01-01T00:00:00Z"}');
      const r = snap.verifySnapshot(dir);
      expect(r.ok).toBe(false);
      expect(r.problems[0]).toMatch(/^digest /);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('build --from-dir copies records, drops MAL- by default, and writes provenance', () => {
    const work = mkdtempSync(join(tmpdir(), 'osv-build-dir-'));
    try {
      const src = join(work, 'src');
      execFileSync('mkdir', [src]);
      for (const n of snap.recordFiles(FIXTURE)) copyFileSync(join(FIXTURE, n), join(src, n));
      writeFileSync(join(src, 'MAL-2024-1.json'), '{"id":"MAL-2024-1","modified":"2031-01-01T00:00:00Z"}');
      const out = join(work, 'out');
      execFileSync('node', [SCRIPT, 'build', '--ecosystem', 'npm', '--out', out, '--from-dir', src]);
      expect(readdirSync(out).some((n) => n.startsWith('MAL-'))).toBe(false);
      const v = snap.verifySnapshot(out);
      expect(v.ok).toBe(true);
      expect(v.digest).toBe(snap.snapshotDigest(FIXTURE));
      const prov = JSON.parse(readFileSync(join(out, 'PROVENANCE'), 'utf-8'));
      expect(prov.excludedPrefixes).toEqual(['MAL-']);
      expect(prov.records).toBe(7);
      execFileSync('node', [SCRIPT, 'build', '--ecosystem', 'npm', '--out', join(work, 'all'), '--from-dir', src, '--include-malicious']);
      expect(snap.snapshotFacts(join(work, 'all')).records).toBe(8);
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  });

  const hasZip = (() => {
    try {
      execFileSync('zip', ['-v'], { stdio: 'ignore' });
      execFileSync('unzip', ['-v'], { stdio: 'ignore' });
      return true;
    } catch {
      return false;
    }
  })();

  it.skipIf(!hasZip)('build --from-zip unpacks, drops MAL- by default, and writes provenance', () => {
    const work = mkdtempSync(join(tmpdir(), 'osv-build-'));
    try {
      const src = join(work, 'src');
      execFileSync('mkdir', [src]);
      for (const n of snap.recordFiles(FIXTURE)) copyFileSync(join(FIXTURE, n), join(src, n));
      writeFileSync(join(src, 'MAL-2024-1.json'), '{"id":"MAL-2024-1","modified":"2031-01-01T00:00:00Z"}');
      execFileSync('zip', ['-q', '-j', join(work, 'all.zip'), ...readdirSync(src).map((n) => join(src, n))]);
      const out = join(work, 'out');
      execFileSync('node', [SCRIPT, 'build', '--ecosystem', 'npm', '--out', out, '--from-zip', join(work, 'all.zip')]);
      expect(readdirSync(out).some((n) => n.startsWith('MAL-'))).toBe(false);
      const v = snap.verifySnapshot(out);
      expect(v.ok).toBe(true);
      expect(v.digest).toBe(snap.snapshotDigest(FIXTURE)); // same records → same identity
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  });
});
