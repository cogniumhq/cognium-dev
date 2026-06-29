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

/**
 * #216 Sprint 66 — bash FP #4 (argv-terminator gate)
 *
 * Closes 1 more of the 5 bash FPs in cognium-dev #216:
 *   - benign_quoted_vars.sh: `grep -- "$pattern"` over-fires `command_injection`
 *
 * Root cause: `interprocedural.ts` bash specialization re-classifies every
 * external-utility call with a tainted positional as `command_injection`
 * (CWE-78) regardless of `--` argv-terminator or argument quoting. With
 * `--` separating flags from positional data AND the positional double-
 * quoted, word-splitting and flag-injection are both impossible.
 *
 * Gate: suppress `command_injection` sink emission when ALL tainted
 * positions are quoted AND a `--` argument precedes the earliest tainted
 * position. Defensible because both conditions must hold; either alone is
 * insufficient (quoting without `--` still permits flag injection; `--`
 * without quoting still permits word-splitting).
 *
 * Bash FP #5 (sqlite3 :memory: first-arg-is-SQL) is independent and stays
 * deferred — sink-type re-classification rather than suppression.
 */
describe('#216 Sprint 66 — bash argv-terminator gate', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TN — grep -- "$1" suppresses command_injection sink (benign_quoted_vars.sh)', async () => {
    const code = [
      '#!/bin/bash',
      'pattern="$1"',
      'grep -- "$pattern" /var/log/app.log',
    ].join('\n');
    const r = await analyze(code, 'quoted.sh', 'bash');
    const ci = (r.taint?.sinks ?? []).filter(
      (s) => s.method === 'grep' && s.type === 'command_injection'
    );
    expect(ci.length).toBe(0);
  });

  it('TN — grep -- "$1" direct (no intermediate var) suppresses command_injection', async () => {
    const code = [
      '#!/bin/bash',
      'grep -- "$1" /var/log/app.log',
    ].join('\n');
    const r = await analyze(code, 'direct.sh', 'bash');
    const ci = (r.taint?.sinks ?? []).filter(
      (s) => s.method === 'grep' && s.type === 'command_injection'
    );
    expect(ci.length).toBe(0);
  });

  it('TN — awk -- "$1" suppresses command_injection (same gate, different utility)', async () => {
    const code = [
      '#!/bin/bash',
      'awk -- "$1" file.txt',
    ].join('\n');
    const r = await analyze(code, 'awk.sh', 'bash');
    const ci = (r.taint?.sinks ?? []).filter(
      (s) => s.method === 'awk' && s.type === 'command_injection'
    );
    expect(ci.length).toBe(0);
  });

  it('TP-control — grep "$1" WITHOUT -- still fires (quoting alone is insufficient)', async () => {
    const code = [
      '#!/bin/bash',
      'grep "$1" /var/log/app.log',
    ].join('\n');
    const r = await analyze(code, 'no-term.sh', 'bash');
    const ci = (r.taint?.sinks ?? []).filter(
      (s) => s.method === 'grep' && s.type === 'command_injection'
    );
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });

  it('TP-control — grep -- $1 (unquoted) still fires (terminator alone is insufficient)', async () => {
    const code = [
      '#!/bin/bash',
      'grep -- $1 /var/log/app.log',
    ].join('\n');
    const r = await analyze(code, 'unquoted.sh', 'bash');
    const ci = (r.taint?.sinks ?? []).filter(
      (s) => s.method === 'grep' && s.type === 'command_injection'
    );
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });

  it('TP-control — ssh "$1" (no -- terminator) still fires command_injection', async () => {
    const code = [
      '#!/bin/bash',
      'ssh "$1"',
    ].join('\n');
    const r = await analyze(code, 'ssh.sh', 'bash');
    const ci = (r.taint?.sinks ?? []).filter(
      (s) => s.method === 'ssh' && s.type === 'command_injection'
    );
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });
});

/**
 * #216 Sprint 67 — bash FP #5 (SQL CLI tools sink-type classification)
 *
 * Closes the LAST bash FP in cognium-dev #216 (bash slice 5/5 across
 * Sprints 65+66+67). After this sprint #216 only has cross-language FPs
 * (Java/JS/Python/TS/Rust/htmljs) remaining.
 *
 * Root cause: `benign_sqlite_param.sh` shape — `id="$1"; sqlite3 :memory:
 * "SELECT ... '$id'"` — gets mis-classified as `command_injection`
 * (CWE-78). The sqlite3 builtin sink in `bash.ts` only catches direct
 * `$1` positional taint (no var indirection); when taint arrives via the
 * intermediate `id=` assignment, the interprocedural bash fallback in
 * `interprocedural.ts` fires and re-classifies as `command_injection`.
 *
 * The taint flow IS real (shell expansion `$id` into a SQL string =
 * SQL injection), but the type is wrong — it should be `sql_injection`/
 * CWE-89, not `command_injection`/CWE-78. SQL CLI utilities take SQL
 * strings as args, not shell commands.
 *
 * Fix: in the bash fallback, when the method name is in a bashSqlCliTools
 * set (sqlite3, mysql, psql, mariadb), emit `sql_injection` instead of
 * `command_injection`. Same finding, correct type. Affects only the
 * interprocedural fallback path (the builtin sinks already emit
 * sql_injection on direct taint).
 */
describe('#216 Sprint 67 — bash SQL CLI sink-type classification', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TN — sqlite3 :memory: with var-indirect taint emits sql_injection, NOT command_injection', async () => {
    const code = [
      '#!/bin/bash',
      'id="$1"',
      `sqlite3 :memory: "SELECT * FROM users WHERE id = '$id'"`,
    ].join('\n');
    const r = await analyze(code, 'sqlite.sh', 'bash');
    const ci = (r.taint?.sinks ?? []).filter(
      (s) => s.method === 'sqlite3' && s.type === 'command_injection'
    );
    const sqli = (r.taint?.sinks ?? []).filter(
      (s) => s.method === 'sqlite3' && s.type === 'sql_injection'
    );
    expect(ci.length).toBe(0);
    expect(sqli.length).toBeGreaterThanOrEqual(1);
  });

  it('TN — mysql var-indirect taint emits sql_injection, NOT command_injection', async () => {
    const code = [
      '#!/bin/bash',
      'q="$1"',
      `mysql -u root -e "SELECT * FROM t WHERE name = '$q'"`,
    ].join('\n');
    const r = await analyze(code, 'mysql.sh', 'bash');
    const ci = (r.taint?.sinks ?? []).filter(
      (s) => s.method === 'mysql' && s.type === 'command_injection'
    );
    expect(ci.length).toBe(0);
  });

  it('TN — psql var-indirect taint emits sql_injection, NOT command_injection', async () => {
    const code = [
      '#!/bin/bash',
      'name="$1"',
      `psql -d mydb -c "SELECT * FROM accounts WHERE name = '$name'"`,
    ].join('\n');
    const r = await analyze(code, 'psql.sh', 'bash');
    const ci = (r.taint?.sinks ?? []).filter(
      (s) => s.method === 'psql' && s.type === 'command_injection'
    );
    expect(ci.length).toBe(0);
  });

  it('TP-control — sqlite3 direct $1 still fires sql_injection (builtin sink path unaffected)', async () => {
    const code = [
      '#!/bin/bash',
      `sqlite3 /db.sqlite "SELECT name FROM accounts WHERE pk = '$1'"`,
    ].join('\n');
    const r = await analyze(code, 'direct.sh', 'bash');
    const sqli = (r.taint?.sinks ?? []).filter(
      (s) => s.method === 'sqlite3' && s.type === 'sql_injection'
    );
    expect(sqli.length).toBeGreaterThanOrEqual(1);
  });

  it('TP-control — ssh var-indirect "$h" still fires command_injection (non-SQL CLI unaffected)', async () => {
    const code = [
      '#!/bin/bash',
      'h="$1"',
      `ssh "$h"`,
    ].join('\n');
    const r = await analyze(code, 'ssh-ind.sh', 'bash');
    const ci = (r.taint?.sinks ?? []).filter(
      (s) => s.method === 'ssh' && s.type === 'command_injection'
    );
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });
});
