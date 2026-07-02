import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

/**
 * cognium-dev #222 — FP: CVE A-tier bash safe mirrors fire ssrf.
 *
 * REG-144-15 (`exchange_proxy_ssrf_safe.sh`): host-prefix allowlist
 * `case "$URL" in https://api.internal.example.com/*|https://cdn.example.com/*)`
 * before `curl` — same class of guard as `#221` Java host allowlist.
 *
 * Fix: extend `findBashRealpathPrefixGuardSanitizers` prefixArm regex to
 * recognize literal URL prefixes (`https?://host/`), so the existing
 * case-prefix-guard sanitizer covers URL allowlists in addition to path
 * allowlists. Shipped 3.144.2.
 *
 * Note on REG-144-14 (`daemon_pkg_install_safe.sh`): the GPG-verify
 * happens AFTER curl, so the SSRF surface — arbitrary curl to attacker-
 * controlled URL — is real. That fixture is not a genuine safe mirror
 * and continues to fire ssrf correctly.
 */
describe('#222 bash case URL allowlist sanitizer', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  async function countSsrfFlows(code: string, file = 'x.sh') {
    const ir = await analyze(code, file, 'bash');
    const flows = ((ir.taint.flows ?? []) as Array<{ sink_type: string }>).filter(
      f => f.sink_type === 'ssrf',
    );
    return flows.length;
  }

  it('SAFE: case "$URL" in https://host/*) curl "$URL" is sanitized', async () => {
    const code = `#!/usr/bin/env bash
URL="$1"
case "$URL" in
    https://api.internal.example.com/*|https://cdn.example.com/*)
        curl -fsSL "$URL"
        ;;
    *)
        echo "blocked" >&2
        exit 1
        ;;
esac
`;
    expect(await countSsrfFlows(code, 'exchange_proxy_ssrf_safe.sh')).toBe(0);
  });

  it('SAFE: http:// scheme also recognized', async () => {
    const code = `#!/usr/bin/env bash
URL="$1"
case "$URL" in
    http://internal.example.com/*)
        curl -fsSL "$URL"
        ;;
    *)
        exit 1
        ;;
esac
`;
    expect(await countSsrfFlows(code)).toBe(0);
  });

  it('UNSAFE: unguarded curl still fires ssrf', async () => {
    const code = `#!/usr/bin/env bash
URL="$1"
curl -fsSL "$URL"
`;
    expect(await countSsrfFlows(code, 'unsafe.sh')).toBeGreaterThan(0);
  });

  it('UNSAFE: case with no catch-all terminator does NOT sanitize (recall guard)', async () => {
    const code = `#!/usr/bin/env bash
URL="$1"
case "$URL" in
    https://api.example.com/*)
        curl -fsSL "$URL"
        ;;
    *)
        echo "not internal"
        ;;
esac
`;
    // The catch-all lacks a terminator (no exit/return/die), so the
    // guard is not conservatively enforced — curl still fires.
    expect(await countSsrfFlows(code, 'no_terminator.sh')).toBeGreaterThan(0);
  });

  it('UNSAFE: leading wildcard arm does NOT count as prefix guard', async () => {
    const code = `#!/usr/bin/env bash
URL="$1"
case "$URL" in
    *api.example.com*)
        curl -fsSL "$URL"
        ;;
    *)
        exit 1
        ;;
esac
`;
    // Leading wildcard is a substring guard, not a prefix — must still fire.
    expect(await countSsrfFlows(code, 'substring.sh')).toBeGreaterThan(0);
  });
});
