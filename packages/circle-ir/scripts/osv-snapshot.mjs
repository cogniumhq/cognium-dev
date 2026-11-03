#!/usr/bin/env node
/**
 * Build, pin and verify an offline OSV advisory snapshot (dependency tool,
 * DT2; cognium-dev #1005). Run by a person or a setup step with network
 * (the Mac queue, CI) — never by the library, which reads no files and
 * fetches nothing.
 *
 *   node scripts/osv-snapshot.mjs build  --ecosystem npm --out <dir> [--from-zip <all.zip> | --from-dir <records>] [--include-malicious]
 *   node scripts/osv-snapshot.mjs verify <dir>
 *   node scripts/osv-snapshot.mjs digest <dir>
 *
 * A snapshot is a directory of OSV JSON records exactly as `unzip
 * <Ecosystem>/all.zip` leaves it, plus one `PROVENANCE` file (JSON, no
 * `.json` extension so it is not part of the identity). Identity:
 *
 *   digest       = sha256 over the sorted `<file name>\0<sha256 of file>\n`
 *                  lines of the directory's `*.json` files — the rule the
 *                  dependency tool uses (C4 `analyze_dependencies`), so an
 *                  unzipped tree and its re-zip agree;
 *   snapshotDate = the greatest `modified` across the records.
 *
 * By default `build` drops `MAL-*` records (OSV's malicious-package feed):
 * E02 patches advisories in real packages; malicious packages are a
 * supply-chain check with its own snapshot (pass --include-malicious).
 */

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

export const OSV_BUCKET = 'https://osv-vulnerabilities.storage.googleapis.com';
export const PROVENANCE = 'PROVENANCE';
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** The record files that make up a snapshot's identity. */
export function recordFiles(dir) {
  return readdirSync(dir).filter((n) => n.endsWith('.json')).sort();
}

/** `sha256:<hex>` over the sorted `<name>\0<sha256 of file>\n` lines. */
export function snapshotDigest(dir) {
  const lines = recordFiles(dir).map((n) => `${n}\0${sha256(readFileSync(join(dir, n)))}\n`);
  return `sha256:${sha256(lines.join(''))}`;
}

/** Digest, record count, data date and the ecosystems the records name. */
export function snapshotFacts(dir) {
  let snapshotDate = null;
  let records = 0;
  const ecosystems = new Set();
  for (const n of recordFiles(dir)) {
    let rec;
    try {
      rec = JSON.parse(readFileSync(join(dir, n), 'utf-8'));
    } catch {
      continue;
    }
    if (!rec || typeof rec.id !== 'string') continue;
    records++;
    if (typeof rec.modified === 'string' && (snapshotDate === null || rec.modified > snapshotDate)) snapshotDate = rec.modified;
    for (const a of Array.isArray(rec.affected) ? rec.affected : []) {
      if (a && a.package && typeof a.package.ecosystem === 'string') ecosystems.add(a.package.ecosystem);
    }
  }
  return { digest: snapshotDigest(dir), records, snapshotDate, ecosystems: [...ecosystems].sort() };
}

/** Write the provenance file for an unpacked snapshot and return it. */
export function writeProvenance(dir, meta) {
  const facts = snapshotFacts(dir);
  const provenance = {
    format: 'osv-snapshot/1',
    source: meta.source ?? null,
    ecosystem: meta.ecosystem,
    fetchedAt: meta.fetchedAt ?? null,
    zipSha256: meta.zipSha256 ?? null,
    excludedPrefixes: meta.excludedPrefixes ?? [],
    digest: facts.digest,
    snapshotDate: facts.snapshotDate,
    records: facts.records,
  };
  writeFileSync(join(dir, PROVENANCE), `${JSON.stringify(provenance, null, 2)}\n`);
  return provenance;
}

/** Recompute the digest and compare with the recorded one. */
export function verifySnapshot(dir) {
  const recorded = JSON.parse(readFileSync(join(dir, PROVENANCE), 'utf-8'));
  const facts = snapshotFacts(dir);
  const problems = [];
  if (recorded.digest !== facts.digest) problems.push(`digest ${facts.digest} ≠ recorded ${recorded.digest}`);
  if (recorded.records !== facts.records) problems.push(`records ${facts.records} ≠ recorded ${recorded.records}`);
  if (recorded.snapshotDate !== facts.snapshotDate) problems.push(`snapshotDate ${facts.snapshotDate} ≠ recorded ${recorded.snapshotDate}`);
  return { ok: problems.length === 0, problems, digest: facts.digest };
}

/** Remove records whose file name starts with one of the prefixes; returns the count. */
export function dropPrefixes(dir, prefixes) {
  let dropped = 0;
  for (const n of recordFiles(dir)) {
    if (prefixes.some((p) => n.startsWith(p))) {
      unlinkSync(join(dir, n));
      dropped++;
    }
  }
  return dropped;
}

function arg(argv, name) {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
}

async function build(argv) {
  const ecosystem = arg(argv, '--ecosystem');
  const out = arg(argv, '--out');
  if (!ecosystem || !out) throw new Error('build needs --ecosystem <npm|Maven|…> and --out <dir>');
  mkdirSync(out, { recursive: true });
  if (recordFiles(out).length > 0) throw new Error(`${out} already holds records; use an empty directory`);

  const fromDir = arg(argv, '--from-dir');
  let zipPath = arg(argv, '--from-zip');
  let source = fromDir ? `dir:${fromDir}` : zipPath ? `file:${zipPath}` : `${OSV_BUCKET}/${encodeURIComponent(ecosystem)}/all.zip`;
  let tmp;
  let zipSha256 = null;
  if (fromDir) {
    // An already-unpacked export (e.g. a CI cache): copy its records as they are.
    for (const n of recordFiles(fromDir)) copyFileSync(join(fromDir, n), join(out, n));
  } else {
  if (!zipPath) {
    tmp = mkdtempSync(join(tmpdir(), 'osv-'));
    zipPath = join(tmp, 'all.zip');
    const res = await fetch(source);
    if (!res.ok) throw new Error(`GET ${source}: HTTP ${res.status}`);
    writeFileSync(zipPath, Buffer.from(await res.arrayBuffer()));
  }
  zipSha256 = sha256(readFileSync(zipPath));
  execFileSync('unzip', ['-q', '-o', zipPath, '-d', out], { stdio: 'inherit' });
  if (tmp) rmSync(tmp, { recursive: true, force: true });
  }

  const excludedPrefixes = argv.includes('--include-malicious') ? [] : ['MAL-'];
  const dropped = dropPrefixes(out, excludedPrefixes);
  const provenance = writeProvenance(out, {
    source,
    ecosystem,
    fetchedAt: new Date().toISOString(),
    zipSha256,
    excludedPrefixes,
  });
  process.stdout.write(`${JSON.stringify({ ...provenance, dropped }, null, 2)}\n`);
}

async function main(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === 'build') return build(rest);
  if (cmd === 'digest') {
    process.stdout.write(`${snapshotDigest(rest[0])}\n`);
    return;
  }
  if (cmd === 'verify') {
    const r = verifySnapshot(rest[0]);
    process.stdout.write(r.ok ? `ok ${r.digest}\n` : `MISMATCH\n${r.problems.join('\n')}\n`);
    if (!r.ok) process.exitCode = 1;
    return;
  }
  process.stderr.write('usage: osv-snapshot.mjs build --ecosystem <eco> --out <dir> [--from-zip <zip> | --from-dir <dir>] [--include-malicious] | verify <dir> | digest <dir>\n');
  process.exitCode = 2;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main(process.argv.slice(2)).catch((e) => {
    process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 1;
  });
}
