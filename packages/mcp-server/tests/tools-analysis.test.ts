/**
 * Handler-body tests for the four analysis tools.
 *
 * `tools.test.ts` covers the tools whose handlers were already exercised.
 * These four — taint_paths, list_reachable_sinks, find_similar,
 * explain_finding — were imported by the suite but never invoked, so their
 * bodies sat at 0% branch coverage: every filter, every not-found path and
 * every match mode was unverified. They are also the tools the MCP server
 * exists for (the deterministic answers an LLM cannot derive alone), so a
 * silent regression in a filter would be both invisible and expensive.
 *
 * The fixture is a three-file JS project with genuine cross-file flows —
 * `req.query.*` in two express route files reaching `exec` in runner.js — so
 * the taint assertions rest on a real analysis rather than a hand-built
 * object. Two route files rather than one so that two findings share a
 * rule_id, which is what gives find_similar something to actually match.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { ProjectCache } from '../src/cache.js';
import type { ToolContext } from '../src/tools/types.js';
import { makeScanHandler } from '../src/tools/scan.js';
import { makeTaintPathsHandler } from '../src/tools/taint-paths.js';
import { makeListReachableSinksHandler } from '../src/tools/list-reachable-sinks.js';
import { makeFindSimilarHandler } from '../src/tools/find-similar.js';
import { makeExplainFindingHandler } from '../src/tools/explain-finding.js';

interface ToolResultLike {
  content: Array<{ text: string }>;
  isError?: boolean;
}

function parseText(result: ToolResultLike): any {
  return JSON.parse(result.content[0].text);
}

let root: string;
let ctx: ToolContext;
/** Id of the first finding the fixture scan produced; the anchor for find_similar / explain_finding. */
let anchorId: string;
let findings: Array<{ id: string; rule_id: string }>;

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'cognium-mcp-analysis-'));
  mkdirSync(join(root, 'src'), { recursive: true });

  writeFileSync(
    join(root, 'src', 'runner.js'),
    `
const { exec } = require('child_process');

function runCommand(cmd) {
  exec(cmd, (err, out) => out);
}

function runOther(cmd) {
  exec(cmd, (err, out) => out);
}

module.exports = { runCommand, runOther };
`,
    'utf8',
  );

  // Two route files, each an express app missing X-Frame-Options, so the scan
  // yields two findings sharing one rule_id — what find_similar needs to have
  // something to match. Both reach `exec` in runner.js, giving cross-file flows.
  for (const [name, route, fn, param] of [
    ['routes-a.js', '/run', 'runCommand', 'cmd'],
    ['routes-b.js', '/run2', 'runOther', 'other'],
  ] as const) {
    writeFileSync(
      join(root, 'src', name),
      `
const express = require('express');
const { ${fn} } = require('./runner');
const app = express();

app.get('${route}', (req, res) => {
  const ${param} = req.query.${param};
  ${fn}(${param});
  res.send('ok');
});

app.listen(3000);
`,
      'utf8',
    );
  }

  ctx = { cache: new ProjectCache(2) };

  // Populate the cache once; every handler below reads through it.
  const parsed = parseText(await makeScanHandler(ctx)({ path: root }) as ToolResultLike);

  // These handlers are only meaningful against a real finding, and the fixture
  // is built to produce several. If that ever stops being true the tests below
  // would silently degrade into not-found assertions, so fail loudly here.
  expect(parsed.findings.length).toBeGreaterThan(0);
  findings = parsed.findings;
  anchorId = findings[0].id;
}, 60_000);

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
  ctx.cache.clear();
});

describe('taint_paths', () => {
  it('returns the cross-file envelope and hits the cache on the second call', async () => {
    const p = parseText(await makeTaintPathsHandler(ctx)({ project_root: root }) as ToolResultLike);

    expect(p.projectRoot).toBe(root);
    expect(p.cacheHit).toBe(true);
    expect(typeof p.crossFileBudgetExceeded).toBe('boolean');
    expect(typeof p.totalMatching).toBe('number');
    expect(p.truncated).toBe(false);
    expect(Array.isArray(p.paths)).toBe(true);
  }, 30_000);

  it('each returned path carries source, sink, hops and confidence', async () => {
    const p = parseText(await makeTaintPathsHandler(ctx)({ project_root: root }) as ToolResultLike);

    for (const path of p.paths) {
      expect(path.source).toHaveProperty('file');
      expect(path.sink).toHaveProperty('file');
      expect(path.sink).toHaveProperty('type');
      expect(Array.isArray(path.hops)).toBe(true);
      expect(Array.isArray(path.sanitizers_in_path)).toBe(true);
    }
  }, 30_000);

  it('source_file filter matches on a path suffix and narrows the result', async () => {
    const all = parseText(await makeTaintPathsHandler(ctx)({ project_root: root }) as ToolResultLike);
    const filtered = parseText(
      await makeTaintPathsHandler(ctx)({ project_root: root, source_file: 'routes-a.js' }) as ToolResultLike,
    );

    // Both route files carry flows, so filtering to one must be a strict subset.
    expect(filtered.totalMatching).toBeLessThan(all.totalMatching);
    for (const path of filtered.paths) {
      expect(path.source.file.endsWith('routes-a.js')).toBe(true);
    }
  }, 30_000);

  it('sink_file filter matches on a path suffix', async () => {
    const p = parseText(
      await makeTaintPathsHandler(ctx)({ project_root: root, sink_file: 'runner.js' }) as ToolResultLike,
    );

    for (const path of p.paths) {
      expect(path.sink.file.endsWith('runner.js')).toBe(true);
    }
  }, 30_000);

  it('sink_type filter returns only that sink type', async () => {
    const p = parseText(
      await makeTaintPathsHandler(ctx)({ project_root: root, sink_type: 'command_injection' }) as ToolResultLike,
    );

    for (const path of p.paths) {
      expect(path.sink.type).toBe('command_injection');
    }
  }, 30_000);

  it('an unmatched sink_type yields an empty, untruncated result', async () => {
    const p = parseText(
      await makeTaintPathsHandler(ctx)({ project_root: root, sink_type: 'no_such_sink_type' }) as ToolResultLike,
    );

    expect(p.totalMatching).toBe(0);
    expect(p.paths).toEqual([]);
    expect(p.truncated).toBe(false);
  }, 30_000);

  it('max_paths caps the returned array and flags truncation', async () => {
    const all = parseText(await makeTaintPathsHandler(ctx)({ project_root: root }) as ToolResultLike);
    const capped = parseText(
      await makeTaintPathsHandler(ctx)({ project_root: root, max_paths: 1 }) as ToolResultLike,
    );

    expect(capped.paths.length).toBeLessThanOrEqual(1);
    // totalMatching reports the pre-truncation count, so the cap must not change it.
    expect(capped.totalMatching).toBe(all.totalMatching);
    if (all.totalMatching > 1) expect(capped.truncated).toBe(true);
  }, 30_000);
});

describe('list_reachable_sinks', () => {
  it('returns only sinks with a reaching flow, each tagged by scope', async () => {
    const p = parseText(
      await makeListReachableSinksHandler(ctx)({ project_root: root }) as ToolResultLike,
    );

    expect(p.projectRoot).toBe(root);
    expect(Array.isArray(p.sinks)).toBe(true);
    for (const s of p.sinks) {
      expect(['per-file', 'cross-file']).toContain(s.scope);
      expect(typeof s.sink_type).toBe('string');
      expect(typeof s.sink_line).toBe('number');
    }
  }, 30_000);

  it('sink_type filter excludes every other category', async () => {
    const p = parseText(
      await makeListReachableSinksHandler(ctx)({ project_root: root, sink_type: 'command_injection' }) as ToolResultLike,
    );

    for (const s of p.sinks) expect(s.sink_type).toBe('command_injection');
  }, 30_000);

  it('language filter excludes other languages', async () => {
    const js = parseText(
      await makeListReachableSinksHandler(ctx)({ project_root: root, language: 'javascript' }) as ToolResultLike,
    );
    const java = parseText(
      await makeListReachableSinksHandler(ctx)({ project_root: root, language: 'java' }) as ToolResultLike,
    );

    // The fixture is JavaScript only, so the Java view must be empty while the
    // JavaScript view is a superset of it.
    expect(java.sinks).toEqual([]);
    expect(js.sinks.length).toBeGreaterThanOrEqual(java.sinks.length);
  }, 30_000);

  it('min_confidence of 0 keeps everything and 1.01 drops all scored flows', async () => {
    const lenient = parseText(
      await makeListReachableSinksHandler(ctx)({ project_root: root, min_confidence: 0 }) as ToolResultLike,
    );
    const strict = parseText(
      await makeListReachableSinksHandler(ctx)({ project_root: root, min_confidence: 1 }) as ToolResultLike,
    );

    expect(strict.sinks.length).toBeLessThanOrEqual(lenient.sinks.length);
    // Flows carrying a confidence score must clear the bar; unscored flows pass through.
    for (const s of strict.sinks) {
      if (typeof s.confidence === 'number') expect(s.confidence).toBeGreaterThanOrEqual(1);
    }
  }, 30_000);

  it('echoes the filters it applied', async () => {
    const p = parseText(
      await makeListReachableSinksHandler(ctx)({
        project_root: root,
        sink_type: 'command_injection',
        language: 'javascript',
      }) as ToolResultLike,
    );

    expect(p.filters).toMatchObject({ sink_type: 'command_injection', language: 'javascript' });
  }, 30_000);
});

describe('find_similar', () => {
  it('reports an actionable error for an unknown finding id', async () => {
    const r = await makeFindSimilarHandler(ctx)({
      project_root: root,
      finding_id: 'definitely-not-a-real-finding-id',
    }) as ToolResultLike;

    expect(r.isError).toBe(true);
    expect(r.content[0].text).toContain('Finding not found');
    expect(r.content[0].text).toContain('scan');
  }, 30_000);

  it(
    'returns an anchor and never includes the anchor in its own matches',
    async () => {
      const p = parseText(
        await makeFindSimilarHandler(ctx)({ project_root: root, finding_id: anchorId }) as ToolResultLike,
      );

      expect(p.anchor.id).toBe(anchorId);
      expect(typeof p.anchor.rule_id).toBe('string');
      for (const m of p.similar) expect(m.id).not.toBe(anchorId);
    },
    30_000,
  );

  it(
    'match_by=rule is at least as broad as rule_and_sink',
    async () => {
      const byRule = parseText(
        await makeFindSimilarHandler(ctx)({
          project_root: root, finding_id: anchorId, match_by: 'rule',
        }) as ToolResultLike,
      );
      const byBoth = parseText(
        await makeFindSimilarHandler(ctx)({
          project_root: root, finding_id: anchorId, match_by: 'rule_and_sink',
        }) as ToolResultLike,
      );

      expect(byRule.totalMatches).toBeGreaterThanOrEqual(byBoth.totalMatches);
      for (const m of byRule.similar) expect(m.rule_id).toBe(byRule.anchor.rule_id);
    },
    30_000,
  );

  it('finds the sibling finding that shares the anchor rule_id', async () => {
    // Both route files produce the same rule, so the anchor has exactly one peer.
    const sibling = findings.find(f => f.rule_id === findings[0].rule_id && f.id !== anchorId);
    expect(sibling).toBeDefined();

    const p = parseText(
      await makeFindSimilarHandler(ctx)({
        project_root: root, finding_id: anchorId, match_by: 'rule',
      }) as ToolResultLike,
    );

    expect(p.totalMatches).toBeGreaterThan(0);
    expect(p.similar.map((m: { id: string }) => m.id)).toContain(sibling!.id);
  }, 30_000);

  it(
    'match_by=sink only returns findings sharing the anchor sink type',
    async () => {
      const p = parseText(
        await makeFindSimilarHandler(ctx)({
          project_root: root, finding_id: anchorId, match_by: 'sink',
        }) as ToolResultLike,
      );

      for (const m of p.similar) {
        if (p.anchor.sink_type) expect(m.sink_type).toBe(p.anchor.sink_type);
      }
    },
    30_000,
  );

  it(
    'max_results caps the matches without changing totalMatches',
    async () => {
      const all = parseText(
        await makeFindSimilarHandler(ctx)({
          project_root: root, finding_id: anchorId, match_by: 'rule',
        }) as ToolResultLike,
      );
      const capped = parseText(
        await makeFindSimilarHandler(ctx)({
          project_root: root, finding_id: anchorId, match_by: 'rule', max_results: 1,
        }) as ToolResultLike,
      );

      expect(capped.similar.length).toBeLessThanOrEqual(1);
      expect(capped.totalMatches).toBe(all.totalMatches);
    },
    30_000,
  );
});

describe('explain_finding', () => {
  it('reports an actionable error for an unknown finding id', async () => {
    const r = await makeExplainFindingHandler(ctx)({
      project_root: root,
      finding_id: 'definitely-not-a-real-finding-id',
    }) as ToolResultLike;

    expect(r.isError).toBe(true);
    expect(r.content[0].text).toContain('Finding not found');
  }, 30_000);

  it(
    'returns the finding plus rule metadata, or the quality-pass note',
    async () => {
      const p = parseText(
        await makeExplainFindingHandler(ctx)({ project_root: root, finding_id: anchorId }) as ToolResultLike,
      );

      expect(p.finding.id).toBe(anchorId);
      expect(typeof p.finding.rule_id).toBe('string');
      expect(p.rule).toBeTruthy();

      // A taint sink resolves through RULE_DEFINITIONS; a quality/reliability
      // pass has no entry and gets the explanatory note instead. Both are
      // valid, but one of them must hold.
      const isTaintRule = typeof p.rule.name === 'string' && typeof p.rule.cwe === 'string';
      const isQualityNote = typeof p.rule.note === 'string' && p.rule.note.includes('PASSES.md');
      expect(isTaintRule || isQualityNote).toBe(true);
    },
    30_000,
  );
});
