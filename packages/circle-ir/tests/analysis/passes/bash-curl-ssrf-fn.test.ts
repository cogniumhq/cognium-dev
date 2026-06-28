import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

/**
 * Sprint 57 — #200: bash `curl`/`wget` with positional or env-var URL does not
 * fire `ssrf` (CWE-918), only `cleartext-transmission`.
 *
 * Root cause: `canSourceReachSink('io_input', 'ssrf') === false` in
 * `src/analysis/findings.ts:175`. Bash positional `$1`/`$@` register as
 * `io_input` sources (per `language-sources-pass.ts:1232`) and `curl`/`wget`
 * register as `ssrf` sinks (per `bash.ts:218-232`), but the source→sink
 * matrix gates them out.
 *
 * Fix: add `ssrf` to `io_input` allowed sinks. Real-world precedent —
 * CVE-2022-41040 ProxyShell-class scripts, CGI/webhook handlers that take a
 * URL on stdin or as a CLI arg and curl it server-side, are textbook SSRF.
 */
describe('Sprint 57 — #200 bash curl/wget ssrf', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const countFlows = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
    (r.taint?.flows ?? []).filter(f => f.sink_type === type).length;

  it('FN — `curl -s "$1"` fires ssrf', async () => {
    const code = `#!/bin/bash
curl -s "$1"
`;
    const r = await analyze(code, 'a.sh', 'bash');
    expect(countFlows(r, 'ssrf')).toBeGreaterThanOrEqual(1);
  });

  it('FN — `wget "$1"` fires ssrf', async () => {
    const code = `#!/bin/bash
wget "$1"
`;
    const r = await analyze(code, 'b.sh', 'bash');
    expect(countFlows(r, 'ssrf')).toBeGreaterThanOrEqual(1);
  });

  it('FN — `curl -fsSL "${1}/autodiscover/x"` (ProxyShell-class) fires ssrf', async () => {
    const code = `#!/bin/bash
curl -fsSL "\${1}/autodiscover/x"
`;
    const r = await analyze(code, 'c.sh', 'bash');
    expect(countFlows(r, 'ssrf')).toBeGreaterThanOrEqual(1);
  });

  it('recall — `curl -s "https://example.com"` (literal URL, no taint) fires no ssrf flow', async () => {
    const code = `#!/bin/bash
curl -s "https://example.com"
`;
    const r = await analyze(code, 'd.sh', 'bash');
    expect(countFlows(r, 'ssrf')).toBe(0);
  });

  it('recall — JS `axios.get(req.query.url)` still fires ssrf (cross-language regression lock)', async () => {
    const code = `const axios = require('axios');
function handler(req) {
  axios.get(req.query.url);
}`;
    const r = await analyze(code, 'e.js', 'javascript');
    expect(countFlows(r, 'ssrf')).toBeGreaterThanOrEqual(1);
  });
});
