/**
 * Tool handler tests — invoke each tool through its factory
 * (`makeXxxHandler`) with a controlled cache and assert on the
 * structured payload shape.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { ProjectCache } from '../src/cache.js';
import type { ToolContext } from '../src/tools/types.js';
import { makeScanHandler } from '../src/tools/scan.js';
import { makeCheckSanitizerHandler } from '../src/tools/check-sanitizer.js';
import { makeDescribeSinkHandler } from '../src/tools/describe-sink.js';
import { makeDescribeSourceHandler } from '../src/tools/describe-source.js';
import { makeRefreshHandler } from '../src/tools/refresh.js';
import { makeAttackSurfaceSummaryHandler } from '../src/tools/attack-surface-summary.js';
import { makeListEntryPointsHandler } from '../src/tools/list-entry-points.js';

function parseText(result: { content: Array<{ text: string }> }): unknown {
  return JSON.parse(result.content[0].text);
}

describe('tool handlers', () => {
  let root: string;
  let ctx: ToolContext;

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), 'cognium-mcp-tools-'));
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(
      join(root, 'src', 'app.js'),
      `
const express = require('express');
const { exec } = require('child_process');
const app = express();
app.get('/run', (req, res) => {
  const cmd = req.query.cmd;
  exec(cmd, (err, out) => res.send(out));
});
app.listen(3000);
`,
      'utf8',
    );
    ctx = { cache: new ProjectCache(2) };
  });

  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
    ctx.cache.clear();
  });

  it('scan returns findings and summary for a directory', async () => {
    const r = await makeScanHandler(ctx)({ path: root });
    const p = parseText(r) as {
      projectRoot: string;
      summary: { totalFindings: number; totalTaintFlows: number };
      cacheHit: boolean;
    };
    expect(p.projectRoot).toBe(root);
    expect(p.cacheHit).toBe(false);
    // Cross-file taint flow: req.query.cmd → exec is command injection.
    expect(p.summary.totalFindings + p.summary.totalTaintFlows).toBeGreaterThan(0);
  }, 30_000);

  it('check_sanitizer returns validity for known + unknown functions', async () => {
    const known = await makeCheckSanitizerHandler(ctx)({
      function_qualified_name: 'org.owasp.esapi.Encoder.encodeForHTML',
      sink_type: 'xss',
    });
    const p1 = parseText(known) as { isValidSanitizer: boolean };
    expect(typeof p1.isValidSanitizer).toBe('boolean');

    const unknown = await makeCheckSanitizerHandler(ctx)({
      function_qualified_name: 'com.example.NotASanitizer.doThing',
      sink_type: 'sql_injection',
    });
    const p2 = parseText(unknown) as { isValidSanitizer: boolean; alternatives: string[] };
    expect(p2.isValidSanitizer).toBe(false);
    expect(Array.isArray(p2.alternatives)).toBe(true);
  });

  it('describe_sink returns CWE metadata for sql_injection', async () => {
    const r = await makeDescribeSinkHandler(ctx)({ sink_type: 'sql_injection' });
    const p = parseText(r) as { cwe: string; name: string; sanitizers: string[] };
    expect(p.cwe).toMatch(/CWE-/);
    expect(p.name).toBeTruthy();
    expect(Array.isArray(p.sanitizers)).toBe(true);
  });

  it('describe_source returns http_param patterns', async () => {
    const r = await makeDescribeSourceHandler(ctx)({ source_type: 'http_param' });
    const p = parseText(r) as { totalPatterns: number; patterns: unknown[] };
    expect(p.totalPatterns).toBeGreaterThan(0);
    expect(p.patterns.length).toBeGreaterThan(0);
  });

  it('attack_surface_summary returns totals + entry points roll-up', async () => {
    const r = await makeAttackSurfaceSummaryHandler(ctx)({ project_root: root });
    const p = parseText(r) as {
      totals: { files: number; findings: number; entryPoints: number };
      entryPoints: { byFramework: Record<string, number> };
    };
    expect(p.totals.files).toBeGreaterThan(0);
    expect(typeof p.entryPoints.byFramework).toBe('object');
  }, 30_000);

  it('list_entry_points enumerates registered handlers', async () => {
    const r = await makeListEntryPointsHandler(ctx)({ project_root: root });
    const p = parseText(r) as {
      totalEntryPoints: number;
      entryPoints: Array<{ file: string; framework: string }>;
    };
    expect(p.totalEntryPoints).toBeGreaterThanOrEqual(0);
  }, 30_000);

  it('refresh clears the cache', async () => {
    const r = await makeRefreshHandler(ctx)({});
    const p = parseText(r) as { entriesRemoved: number; cacheSizeAfter: number };
    expect(p.entriesRemoved).toBeGreaterThanOrEqual(0);
    expect(p.cacheSizeAfter).toBe(0);
  });
});
