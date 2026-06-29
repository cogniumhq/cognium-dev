/**
 * #216 Sprint 65 — bash FP cluster from v3.107.0 scorecard
 *
 * Closes 2 of the 5 bash FPs in cognium-dev #216 (predictable-temp-file shape):
 *   - benign_checksum_verify.sh  (suppress when /tmp/X verified by sha256sum -c)
 *   - benign_fixed_path.sh       (suppress when /tmp/X is an archive output)
 *
 * Plus 1 TP-control assertion so the suppressions don't over-suppress.
 *
 * Rescope notes (probed against 3.120.0 head):
 *   - benign_path_join.sh path_traversal FP no longer reproduces — bash
 *     `cat "/data/$var"` does not emit path_traversal at current head
 *     (Sprint 52 / 3.109.0 was titled "#216 subset" and likely cleared it).
 *     The case-prefix allowlist sanitizer is therefore not needed this
 *     sprint; revisit if/when bash path_traversal coverage is broadened.
 *   - benign_quoted_vars.sh (`grep -- "$pattern"`) and benign_sqlite_param.sh
 *     (sqlite3 first-arg SQL) need command-injection sink-side changes and
 *     are deferred to a follow-up sprint.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

describe('#216 Sprint 65 — bash FP cluster', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TN-1 — benign_checksum_verify.sh: curl -o /tmp/X verified by sha256sum -c', async () => {
    const code = [
      '#!/bin/bash',
      'set -euo pipefail',
      'curl -fsS -o /tmp/install.sh https://releases.example.com/install.sh',
      'echo "deadbeef  /tmp/install.sh" | sha256sum -c -',
    ].join('\n');
    const r = await analyze(code, 'check.sh', 'bash');
    const tmp = (r.findings ?? []).filter((f) => f.rule_id === 'predictable-temp-file');
    expect(tmp.length).toBe(0);
  });

  it('TN-2 — benign_fixed_path.sh: tar czf /tmp/X.tgz archive output', async () => {
    const code = [
      '#!/bin/bash',
      'set -euo pipefail',
      'export PATH="/usr/bin:/bin"',
      'tar czf /tmp/backup.tgz /etc/app',
    ].join('\n');
    const r = await analyze(code, 'backup.sh', 'bash');
    const tmp = (r.findings ?? []).filter((f) => f.rule_id === 'predictable-temp-file');
    expect(tmp.length).toBe(0);
  });

  it('TP-control — predictable-temp-file with NO checksum verify still fires', async () => {
    const code = [
      '#!/bin/bash',
      'curl -o /tmp/install.sh https://example.com/install.sh',
      'bash /tmp/install.sh',
    ].join('\n');
    const r = await analyze(code, 'unsafe.sh', 'bash');
    const tmp = (r.findings ?? []).filter((f) => f.rule_id === 'predictable-temp-file');
    expect(tmp.length).toBeGreaterThanOrEqual(1);
  });
});
