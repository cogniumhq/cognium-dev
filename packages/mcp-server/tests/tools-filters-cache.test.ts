/**
 * The three files left thin after tools-analysis.test.ts covered the analysis
 * handlers: refresh's single-project branch, scan's filter permutations, and
 * the filesystem error paths in util/files.
 *
 * These are all "second argument" paths — the code runs only when a caller
 * passes an optional filter or when the filesystem misbehaves — so they are
 * exactly the branches a happy-path suite leaves at zero and a user hits
 * first.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, chmodSync, symlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { ProjectCache } from '../src/cache.js';
import type { ToolContext } from '../src/tools/types.js';
import { makeScanHandler } from '../src/tools/scan.js';
import { makeRefreshHandler } from '../src/tools/refresh.js';
import { collectFiles, indexMtimes, mtimesEqual, detectLanguage } from '../src/util/files.js';

interface ToolResultLike { content: Array<{ text: string }>; isError?: boolean }
const parseText = (r: ToolResultLike): any => JSON.parse(r.content[0].text);

let root: string;
let ctx: ToolContext;

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'cognium-mcp-filters-'));
  mkdirSync(join(root, 'src'), { recursive: true });

  // One express route reaching exec cross-file: yields both security findings
  // with taint flows and non-security (architecture/quality) findings, so the
  // category and severity filters have something on each side to select.
  writeFileSync(join(root, 'src', 'runner.js'), `
const { exec } = require('child_process');
function runCommand(cmd) { exec(cmd, (err, out) => out); }
module.exports = { runCommand };
`, 'utf8');

  writeFileSync(join(root, 'src', 'routes.js'), `
const express = require('express');
const { runCommand } = require('./runner');
const app = express();
app.get('/run', (req, res) => {
  const cmd = req.query.cmd;
  runCommand(cmd);
  res.send('ok');
});
app.listen(3000);
`, 'utf8');

  ctx = { cache: new ProjectCache(4) };
  await makeScanHandler(ctx)({ path: root });
}, 60_000);

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
  ctx.cache.clear();
});

describe('refresh', () => {
  it('invalidates a single project and leaves other entries cached', async () => {
    // Prime a second project so a targeted invalidate is distinguishable from
    // a clear-all: the previously covered path could not tell them apart.
    const other = mkdtempSync(join(tmpdir(), 'cognium-mcp-other-'));
    mkdirSync(join(other, 'src'), { recursive: true });
    writeFileSync(join(other, 'src', 'a.js'), 'module.exports = 1;\n', 'utf8');
    await makeScanHandler(ctx)({ path: other });

    const before = ctx.cache.size();
    expect(before).toBeGreaterThanOrEqual(2);

    const p = parseText(await makeRefreshHandler(ctx)({ project_root: root }) as ToolResultLike);

    expect(p.projectRoot).toBe(root);
    expect(p.entriesRemoved).toBeGreaterThan(0);
    expect(p.cacheSizeAfter).toBe(before - p.entriesRemoved);
    // The other project survived, which is the whole point of the branch.
    expect(p.cacheSizeAfter).toBeGreaterThan(0);

    rmSync(other, { recursive: true, force: true });
  }, 60_000);

  it('reports zero removed for a project that was never cached', async () => {
    const p = parseText(
      await makeRefreshHandler(ctx)({ project_root: join(tmpdir(), 'never-scanned-xyz') }) as ToolResultLike,
    );
    expect(p.entriesRemoved).toBe(0);
  });

  it('clears everything when no project_root is given', async () => {
    await makeScanHandler(ctx)({ path: root });
    const p = parseText(await makeRefreshHandler(ctx)({}) as ToolResultLike);
    expect(p.cleared).toBe('all');
    expect(ctx.cache.size()).toBe(0);
    // Re-prime for the scan filter tests below.
    await makeScanHandler(ctx)({ path: root });
  }, 60_000);
});

describe('scan filters', () => {
  it('severity filter returns only the requested severities', async () => {
    const all = parseText(await makeScanHandler(ctx)({ path: root }) as ToolResultLike);
    const sevs = [...new Set(all.findings.map((f: { severity: string }) => f.severity))];
    expect(sevs.length).toBeGreaterThan(0);

    const pick = sevs[0] as 'critical' | 'high' | 'medium' | 'low';
    const filtered = parseText(
      await makeScanHandler(ctx)({ path: root, severity: [pick] }) as ToolResultLike,
    );

    for (const f of filtered.findings) expect(f.severity).toBe(pick);
    expect(filtered.findings.length).toBeLessThanOrEqual(all.findings.length);
  }, 60_000);

  it('categories filter returns only the requested categories', async () => {
    const all = parseText(await makeScanHandler(ctx)({ path: root }) as ToolResultLike);
    const cats = [...new Set(all.findings.map((f: { category: string }) => f.category))];
    expect(cats.length).toBeGreaterThan(0);

    const pick = cats[0] as 'security' | 'reliability' | 'performance' | 'maintainability' | 'architecture';
    const filtered = parseText(
      await makeScanHandler(ctx)({ path: root, categories: [pick] }) as ToolResultLike,
    );

    for (const f of filtered.findings) expect(f.category).toBe(pick);
  }, 60_000);

  // Flows are always security-category, so excluding security must drop every
  // flow — a separate code path from the findings filter above.
  it('excluding security from categories drops all taint flows', async () => {
    const p = parseText(
      await makeScanHandler(ctx)({ path: root, categories: ['maintainability'] }) as ToolResultLike,
    );
    expect(p.taintFlows).toEqual([]);
    for (const f of p.findings) expect(f.category).toBe('maintainability');
  }, 60_000);

  it('including security in categories keeps flows', async () => {
    const p = parseText(
      await makeScanHandler(ctx)({ path: root, categories: ['security'] }) as ToolResultLike,
    );
    expect(Array.isArray(p.taintFlows)).toBe(true);
  }, 60_000);

  it('severity and categories compose', async () => {
    const p = parseText(
      await makeScanHandler(ctx)({
        path: root, categories: ['security'], severity: ['critical', 'high'],
      }) as ToolResultLike,
    );
    for (const f of p.findings) {
      expect(f.category).toBe('security');
      expect(['critical', 'high']).toContain(f.severity);
    }
  }, 60_000);

  it('an empty filter array is treated as no filter', async () => {
    const all = parseText(await makeScanHandler(ctx)({ path: root }) as ToolResultLike);
    const empty = parseText(
      await makeScanHandler(ctx)({ path: root, severity: [] }) as ToolResultLike,
    );
    expect(empty.findings.length).toBe(all.findings.length);
  }, 60_000);

  it('scanning a single file reports no cross-file taint paths', async () => {
    const p = parseText(
      await makeScanHandler(ctx)({ path: join(root, 'src', 'routes.js') }) as ToolResultLike,
    );
    expect(p.crossFileTaintPaths).toEqual([]);
  }, 60_000);
});

describe('util/files', () => {
  it('detectLanguage maps known extensions and rejects unknown ones', () => {
    expect(detectLanguage('a.ts')).toBeTruthy();
    expect(detectLanguage('a.js')).toBeTruthy();
    expect(detectLanguage('a.py')).toBeTruthy();
    expect(detectLanguage('a.unknownext')).toBeNull();
    expect(detectLanguage('noextension')).toBeNull();
  });

  // The two collectors are documented as sharing their walking logic, but they
  // differ on a missing root: indexMtimes guards statSync and returns empty,
  // collectFiles does not and propagates ENOENT. Pinning both so the asymmetry
  // is a decision rather than a surprise — if it is ever unified, this test
  // says which way it changed.
  it('a missing root: indexMtimes returns empty, collectFiles throws', () => {
    const missing = join(tmpdir(), 'cognium-does-not-exist-xyz');
    expect(indexMtimes(missing).size).toBe(0);
    expect(() => collectFiles(missing)).toThrow();
  });

  it('a file root is handled without walking', () => {
    const f = join(root, 'src', 'routes.js');
    expect(collectFiles(f).length).toBe(1);
    expect(indexMtimes(f).size).toBe(1);
  });

  it('a file root with an unsupported extension yields nothing', () => {
    const f = join(root, 'notes.unknownext');
    writeFileSync(f, 'x', 'utf8');
    expect(collectFiles(f)).toEqual([]);
    expect(indexMtimes(f).size).toBe(0);
  });

  it('the language option filters the walk', () => {
    const js = collectFiles(root, { language: 'javascript' });
    expect(js.length).toBeGreaterThan(0);
    for (const f of js) expect(f.language).toBe('javascript');

    // No Java in this fixture, so the filter must exclude everything.
    expect(collectFiles(root, { language: 'java' })).toEqual([]);
  });

  it('collected files carry path, language, code and mtime', () => {
    const [first] = collectFiles(join(root, 'src', 'routes.js'));
    expect(first.filePath).toContain('routes.js');
    expect(first.language).toBe('javascript');
    expect(first.code).toContain('express');
    expect(typeof first.mtimeMs).toBe('number');
  });

  it('maxFiles caps the walk', () => {
    const capped = collectFiles(root, { maxFiles: 1 });
    expect(capped.length).toBeLessThanOrEqual(1);
    expect(indexMtimes(root, { maxFiles: 1 }).size).toBeLessThanOrEqual(1);
  });

  it('dot-directories are skipped', () => {
    const hidden = join(root, '.hidden');
    mkdirSync(hidden, { recursive: true });
    writeFileSync(join(hidden, 'secret.js'), 'module.exports = 1;\n', 'utf8');
    const files = collectFiles(root).map(f => f.filePath);
    expect(files.some(f => f.includes('.hidden'))).toBe(false);
  });

  // readdirSync throws on an unreadable directory; the walk must `continue`
  // past it rather than abort the whole collection.
  it('an unreadable directory is skipped, not fatal', () => {
    const blocked = join(root, 'blocked');
    mkdirSync(blocked, { recursive: true });
    writeFileSync(join(blocked, 'x.js'), 'module.exports = 1;\n', 'utf8');
    let restricted = false;
    try {
      chmodSync(blocked, 0o000);
      restricted = true;
    } catch {
      // Some filesystems/CI users cannot drop permissions; the assertion
      // below still holds, it just no longer exercises the catch.
    }

    try {
      expect(() => collectFiles(root)).not.toThrow();
      expect(() => indexMtimes(root)).not.toThrow();
      expect(collectFiles(root).length).toBeGreaterThan(0);
    } finally {
      if (restricted) chmodSync(blocked, 0o755);
    }
  });

  it('a broken symlink does not abort the walk', () => {
    const link = join(root, 'src', 'dangling.js');
    try {
      symlinkSync(join(root, 'src', 'gone.js'), link);
    } catch {
      return; // symlinks unavailable (e.g. Windows without privilege)
    }
    expect(() => collectFiles(root)).not.toThrow();
    expect(() => indexMtimes(root)).not.toThrow();
    rmSync(link, { force: true });
  });

  it('mtimesEqual distinguishes size, keys and values', () => {
    const a = new Map([['x', 1], ['y', 2]]);
    expect(mtimesEqual(a, new Map([['x', 1], ['y', 2]]))).toBe(true);
    expect(mtimesEqual(a, new Map([['x', 1]]))).toBe(false);
    expect(mtimesEqual(a, new Map([['x', 1], ['z', 2]]))).toBe(false);
    expect(mtimesEqual(a, new Map([['x', 1], ['y', 99]]))).toBe(false);
    expect(mtimesEqual(new Map(), new Map())).toBe(true);
  });
});
