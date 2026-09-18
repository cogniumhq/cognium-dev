/**
 * cognium-dev #366 — `analyzeProject` was not bounded, so a large
 * multi-module repo could not be stopped from outside.
 *
 * WHAT THE ISSUE REPORTED vs WHAT IS TRUE. It reported that `analyze()` /
 * `scan()` "hangs (sync-bound, never returns)" on four Maven repos. Measured
 * on the two that actually timed out in that sweep, at the pinned commits:
 *
 *   apache/nifi        5435 java files   per-file ~59s + cross-file ~14s  = ~73s
 *   geoserver/geoserver 8029 java files  per-file ~67s + cross-file ~28s  = ~95s
 *
 * Both COMPLETE. No file in nifi took over 3s; heap on geoserver grew linearly
 * to 732MB with no GC spiral. So there is no infinite loop to find — the
 * analysis is merely slower than the consumer's 120s deadline, and because it
 * is synchronous a `Promise.race` timeout cannot interrupt it, which is why the
 * runner had to SIGKILL and recorded it as a hang. The distinction matters:
 * the fix is a bound, not a loop fix.
 *
 * TWO GAPS, both closed here.
 *
 * 1. `crossFileBudgetMs` existed but was evaluated only BETWEEN the four
 *    sub-phases, so a single phase ran unbounded and the documented "bounded"
 *    contract did not hold. The deadline is now threaded into the three
 *    project-wide walks in `resolution/cross-file.ts` and checked in their
 *    outer per-file loops — the O(F·T·M) walks that file's own header calls
 *    out. One `Date.now()` per file.
 *
 * 2. Nothing bounded the PER-FILE phase, which is the dominant cost (59s of
 *    nifi's 73s). New `perFileBudgetMs`, defaulting to 0 = off so no existing
 *    caller changes behaviour, with `per_file_budget_exceeded` on the result
 *    so a truncated scan can never be mistaken for a clean one.
 *
 * The budgets are checked BETWEEN files/phases, not inside `analyze()`, which
 * is the only interruption point available without worker threads. That is
 * sufficient precisely because no single file is pathological here.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyzeProject, initAnalyzer } from '../../src/analyzer.js';

/** A small Java file that participates in cross-file resolution. */
const file = (i: number) => ({
  filePath: `src/main/java/com/acme/M${i}.java`,
  language: 'java' as const,
  code: [
    'package com.acme;',
    'import java.sql.*;',
    `public class M${i} {`,
    `  public void run${i}(String p) throws Exception {`,
    '    Connection c = DriverManager.getConnection("jdbc:h2:mem:t");',
    '    Statement s = c.createStatement();',
    `    s.executeQuery("SELECT * FROM t WHERE x = '" + p + "'");`,
    '  }',
    '}',
  ].join('\n'),
});

const FILES = Array.from({ length: 60 }, (_, i) => file(i));

describe('#366 analyzeProject is bounded', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('analyses every file and sets no flag by default', async () => {
    const r = await analyzeProject(FILES);
    expect(r.files).toHaveLength(FILES.length);
    expect(r.per_file_budget_exceeded).toBeUndefined();
  });

  it('perFileBudgetMs: 0 is explicitly unbounded', async () => {
    const r = await analyzeProject(FILES, { perFileBudgetMs: 0 });
    expect(r.files).toHaveLength(FILES.length);
    expect(r.per_file_budget_exceeded).toBeUndefined();
  });

  it('stops the per-file phase and flags truncation when the budget is spent', async () => {
    // 1ms is spent after the first file on any machine, which keeps this
    // deterministic rather than timing-sensitive.
    const r = await analyzeProject(FILES, { perFileBudgetMs: 1 });
    expect(r.per_file_budget_exceeded).toBe(true);
    expect(r.files.length).toBeLessThan(FILES.length);
  });

  it('keeps what it analysed rather than discarding the run', async () => {
    const r = await analyzeProject(FILES, { perFileBudgetMs: 1 });
    // Partial, but a real result over the subset — the existing
    // `cross_file_budget_exceeded` semantic, applied to the per-file phase.
    expect(r.files.length).toBeGreaterThan(0);
    expect(r.meta).toBeDefined();
    expect(r.type_hierarchy).toBeDefined();
  });

  it('bounds the cross-file phase, leaving the per-file phase untouched', async () => {
    // Needs a corpus whose cross-file walks actually take measurable time —
    // 60 trivial files complete the whole phase inside 1ms, so a tiny budget
    // is never observed as exceeded there. (The mid-walk interruption itself
    // is measured on nifi in the PR: 7643 paths -> 632 at a 50ms budget,
    // which the pre-fix code could not do at all, since the budget was only
    // read between phases.)
    const many = Array.from({ length: 600 }, (_, i) => file(i));
    const r = await analyzeProject(many, { crossFileBudgetMs: 1 });
    expect(r.files).toHaveLength(many.length); // per-file phase untouched
    expect(r.cross_file_budget_exceeded).toBe(true);
  });

  it('the two budgets are independent', async () => {
    const r = await analyzeProject(FILES, { perFileBudgetMs: 1, crossFileBudgetMs: 0 });
    expect(r.per_file_budget_exceeded).toBe(true);
    expect(r.cross_file_budget_exceeded).toBeUndefined();
  });
});
