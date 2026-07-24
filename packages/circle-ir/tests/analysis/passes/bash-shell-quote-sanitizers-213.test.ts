/**
 * Tests for cognium-dev #213 — twelfth slice: Bash shell-quote sanitizers.
 *
 * Bash has two idiomatic shell-quoting constructs that convert an
 * arbitrary string into a shell-safe form:
 *
 *   safe=$(printf '%q' "$x")   — POSIX/Bash printf %q
 *   safe="${x@Q}"              — Bash 4.4+ Q-transform
 *
 * Both are recognized as `command_injection` + `code_injection`
 * sanitizers via a new `findBashShellQuoteSanitizers` text-scan
 * detector in language-sources-pass.ts.
 *
 * Pairs with the existing bash regex-allowlist sanitizer (Sprint 11
 * #73.2) and realpath prefix-guard sanitizer.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('cognium-dev #213 twelfth slice — Bash shell-quote sanitizers', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // eval in bash is registered as `code_injection` (CWE-94) rather
  // than command_injection. The sanitizer covers both types.
  const hasExecFlow = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows ?? []).some(
      f => f.sink_type === 'command_injection' || f.sink_type === 'code_injection',
    );

  it('TP-suppress — `safe=$(printf %q "$x")` suppresses downstream eval', async () => {
    const code = `#!/bin/bash
read x
safe=$(printf '%q' "$x")
eval "cmd $safe"
`;
    const r = await analyze(code, 'q.sh', 'bash');
    expect(hasExecFlow(r)).toBe(false);
    // Sanitizer must be registered.
    const sans = (r.taint.sanitizers ?? []).filter(
      s => s.method === "printf '%q'",
    );
    expect(sans.length).toBeGreaterThan(0);
  });

  it('TP-suppress — `safe="${x@Q}"` suppresses downstream eval', async () => {
    const code = `#!/bin/bash
read x
safe="\${x@Q}"
eval "cmd $safe"
`;
    const r = await analyze(code, 'atq.sh', 'bash');
    expect(hasExecFlow(r)).toBe(false);
    const sans = (r.taint.sanitizers ?? []).filter(
      s => s.method === '${var@Q}',
    );
    expect(sans.length).toBeGreaterThan(0);
  });

  it('Control — bare `eval "cmd $x"` (no quoting) still fires', async () => {
    // FP-guard on the sanitizer: it must not fire absent a quoting
    // construct, so the unsanitized shape still produces a flow.
    const code = `#!/bin/bash
read x
eval "cmd $x"
`;
    const r = await analyze(code, 'raw.sh', 'bash');
    expect(hasExecFlow(r)).toBe(true);
  });
});
