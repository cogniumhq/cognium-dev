/**
 * Bash: positional parameters inside a function are that function's own
 * arguments (false-positive class: a script-level `$2` source reached every
 * `"$2"` inside every helper function of a local CI script).
 */
import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

const cmdi = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'command_injection' || f.sink_type === 'code_injection');

describe('bash function positional scope', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('a script argument does not reach "$2" inside an unrelated helper', async () => {
    const code = `#!/usr/bin/env bash
BASELINE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --baseline) BASELINE="\${2:-}"; shift 2 ;;
  esac
done
summarise() {
  grep -cE 'error TS' "$2" 2>/dev/null
}
record() { NAMES+=("$1"); RESULTS+=("$2"); }
summarise tsc /tmp/tsc.log
record "install" "ok"
`;
    const r = await analyze(code, 'local-ci.sh', 'bash');
    expect(cmdi(r)).toHaveLength(0);
    // The one-line function body is not a top-level positional source.
    expect(r.taint.sources.filter(s => s.line === 11)).toHaveLength(0);
  });

  it('a helper that is only ever called with literals is not reached by "$1"', async () => {
    const code = `#!/bin/bash\nMODE="$1"\nlist() {\n  ls $1\n}\nlist /tmp\necho "$MODE"\n`;
    const r = await analyze(code, 'literal.sh', 'bash');
    expect(cmdi(r)).toHaveLength(0);
  });

  it('a call to a function defined in the script is not itself a shell-utility sink', async () => {
    const code = `#!/bin/bash\nlog() {\n  printf '%s\\n' "$1" >&2\n}\nlog "$1"\n`;
    const r = await analyze(code, 'log.sh', 'bash');
    expect((r.taint.sinks ?? []).filter(s => s.method === 'log')).toHaveLength(0);
  });

  it('$1 inside a single-quoted awk program is not a positional source', async () => {
    const r = await analyze(`#!/bin/bash\nawk '$1 ~ /x/ { print $1 }' f\n`, 'awk.sh', 'bash');
    expect(r.taint.sources).toHaveLength(0);
  });

  it('still fires: a script argument passed to a function that evals it', async () => {
    const r = await analyze(`#!/bin/bash\nrun() {\n  eval "$1"\n}\nrun "$1"\n`, 'eval.sh', 'bash');
    expect(cmdi(r).length).toBeGreaterThan(0);
  });

  it('still fires: an unquoted argument inside a function', async () => {
    const r = await analyze(`#!/bin/bash\nh(){ grep $1 f; }\nh "$1"\n`, 'unq.sh', 'bash');
    expect(cmdi(r).length).toBeGreaterThan(0);
  });

  it('still fires: a quoted argument to a tool with exec-capable options', async () => {
    const r = await analyze(`#!/bin/bash\nfind . -name "$1"\n`, 'find.sh', 'bash');
    expect(cmdi(r).length).toBeGreaterThan(0);
  });

  it('still fires through shift: the function renumbers its parameters', async () => {
    const r = await analyze(`#!/bin/bash\nf(){\n  shift\n  bash -c "$1"\n}\nf a "$1"\n`, 'shift.sh', 'bash');
    expect(cmdi(r).length).toBeGreaterThan(0);
  });
});
