/**
 * Environment resolver — maps file paths to a `ProjectEnv` axis value.
 *
 * v1 policy (ADR-008):
 *  - File path matches `**\/test/**` or `**\/tests/**` → `test`. The
 *    engine treats `test` as a no-op equivalent of `unknown` in v1 (see
 *    `project-profile-transform.ts`), but we still emit the axis so users
 *    can see the distinction in `--profile-explain` output.
 *  - File path matches `**\/sample{s,}/**`, `**\/example{s,}/**`,
 *    `**\/demo{s,}/**`, or `**\/fixture{s,}/**` → `sample`.
 *  - File path matches `**\/benchmark{s,}/**` → `benchmark`.
 *  - File path under `src/main/...` → `production`.
 *  - Otherwise → `dev`.
 *
 * Pillar I: pure path classification. No content reads.
 */

import type { ProjectEnv } from './types.js';

const TEST_RE      = /(?:^|\/)tests?\//;
const SAMPLE_RE    = /(?:^|\/)(?:samples?|examples?|demos?|fixtures?)\//;
const BENCHMARK_RE = /(?:^|\/)benchmarks?\//;
const PROD_RE      = /(?:^|\/)src\/main\//;

export function resolveEnv(absoluteFile: string): ProjectEnv {
  // Normalize to forward-slash form for cross-platform regex.
  const f = absoluteFile.replace(/\\/g, '/').toLowerCase();
  if (TEST_RE.test(f))      return 'test';
  if (BENCHMARK_RE.test(f)) return 'benchmark';
  if (SAMPLE_RE.test(f))    return 'sample';
  if (PROD_RE.test(f))      return 'production';
  return 'dev';
}
