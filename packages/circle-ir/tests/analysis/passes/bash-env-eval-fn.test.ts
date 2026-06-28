import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

/**
 * Sprint 57 — #198 (partial): bash CVE-class environment variables
 * (`RPC_EXPR`, `XMLRPC_*`, `JSONRPC_*`, `CMD_*`, `EXEC_*`, `EVAL_*`,
 * `SHELL_*`) flowing into `eval` are not detected as `code_injection`
 * because the env var name does not match `BASH_UNTRUSTED_ENV_PATTERNS`
 * in `src/analysis/passes/language-sources-pass.ts:1169-1180`.
 *
 * Existing patterns cover CGI-class names (`USER_INPUT`, `QUERY_STRING`,
 * `REQUEST_*`, `HTTP_*`, `REMOTE_*`, `CONTENT_TYPE`, `CONTENT_LENGTH`,
 * `PATH_INFO`, `SCRIPT_NAME`, `SERVER_NAME`) but miss the RPC/CMD/EXEC
 * classes used by recent CVE intake (CVE-2025-67038 HTTP RPC pattern).
 *
 * The propagation `expr="${X}"; eval "$expr"` already works for
 * recognized env vars (verified in debug). Only the source registration
 * is missing for these name classes — once the pattern matches, the
 * existing dataflow handles the rest.
 *
 * Deferred (still on #198): generic env-var taint when the var name
 * doesn't match any recognized pattern — requires either a much broader
 * default or a per-script "unknown env vars are tainted at dangerous
 * sinks" backward-flow inference. Out of scope for Sprint 57.
 */
describe('Sprint 57 — #198 bash CVE-class env vars into eval', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const countFlows = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
    (r.taint?.flows ?? []).filter(f => f.sink_type === type).length;

  it('FN — `eval "$RPC_EXPR"` (direct) fires code_injection', async () => {
    const code = `#!/bin/bash
eval "$RPC_EXPR"
`;
    const r = await analyze(code, 'a.sh', 'bash');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — `expr="${RPC_EXPR}"; eval "$expr"` (propagated) fires code_injection', async () => {
    const code = `#!/bin/bash
expr="\${RPC_EXPR}"
eval "$expr"
`;
    const r = await analyze(code, 'b.sh', 'bash');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — `eval "$CMD_DATA"` fires code_injection', async () => {
    const code = `#!/bin/bash
eval "$CMD_DATA"
`;
    const r = await analyze(code, 'c.sh', 'bash');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — `eval "$XMLRPC_PAYLOAD"` fires code_injection', async () => {
    const code = `#!/bin/bash
eval "$XMLRPC_PAYLOAD"
`;
    const r = await analyze(code, 'd.sh', 'bash');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — `eval "$JSONRPC_BODY"` fires code_injection', async () => {
    const code = `#!/bin/bash
eval "$JSONRPC_BODY"
`;
    const r = await analyze(code, 'e.sh', 'bash');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('recall — `eval "$HTTP_USER_AGENT"` still fires (existing pattern)', async () => {
    const code = `#!/bin/bash
eval "$HTTP_USER_AGENT"
`;
    const r = await analyze(code, 'f.sh', 'bash');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('recall — `eval "$1"` (positional) still fires', async () => {
    const code = `#!/bin/bash
eval "$1"
`;
    const r = await analyze(code, 'g.sh', 'bash');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('TN — `eval "$HOME/.config"` (benign env var) fires no code_injection', async () => {
    const code = `#!/bin/bash
eval "$HOME/.config"
`;
    const r = await analyze(code, 'h.sh', 'bash');
    expect(countFlows(r, 'code_injection')).toBe(0);
  });
});
