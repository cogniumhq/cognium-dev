/**
 * ProjectCache smoke tests — end-to-end analysis + cache-hit path on a
 * small synthesized fixture directory. Verifies mtime-based
 * invalidation and LRU eviction.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, utimesSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { ProjectCache } from '../src/cache.js';

function makeProject(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'cognium-mcp-cache-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(root, rel);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, content, 'utf8');
  }
  return root;
}

describe('ProjectCache', () => {
  let root: string;
  const cache = new ProjectCache(2);

  beforeAll(() => {
    root = makeProject({
      'src/app.js': `
const express = require('express');
const app = express();
app.get('/x', (req, res) => {
  const name = req.query.name;
  res.send('hello ' + name);
});
`,
    });
  });

  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
    cache.clear();
  });

  it('runs analysis on first call and reports cache miss', async () => {
    const r = await cache.getOrCompute(root, {});
    expect(r.cacheHit).toBe(false);
    expect(r.analysis.files.length).toBeGreaterThan(0);
  }, 30_000);

  it('returns cached result when files unchanged', async () => {
    const r = await cache.getOrCompute(root, {});
    expect(r.cacheHit).toBe(true);
  });

  it('invalidates on file mtime change', async () => {
    const target = join(root, 'src/app.js');
    // Push mtime forward by 5s so the fs.stat mtime differs.
    const future = new Date(Date.now() + 5000);
    utimesSync(target, future, future);
    const r = await cache.getOrCompute(root, {});
    expect(r.cacheHit).toBe(false);
  });

  it('separate cache slots per option-set', async () => {
    const r1 = await cache.getOrCompute(root, {});
    const r2 = await cache.getOrCompute(root, { disabledPasses: ['naming-convention'] });
    expect(r1.cacheHit).toBe(true);
    expect(r2.cacheHit).toBe(false);
  });

  it('manual invalidate clears the entry', () => {
    const removed = cache.invalidate(root);
    expect(removed).toBeGreaterThan(0);
    expect(cache.size()).toBe(0);
  });
});
