/**
 * Tests for cognium-dev #213 — Bash stdin/CLI builtin sources.
 *
 * Third slice extension: bash `read` / `mapfile` / `readarray` / `getopts`
 * builtin sources. All are stdin-driven or attacker-controlled CLI-arg
 * driven and should register as `io_input` sources with the assigned
 * variable name as `variable` field so downstream sinks that consume
 * `$var` are flagged.
 *
 * FP-guard: `read() { ... }` function definitions must NOT register a
 * source (the recognizer excludes anything containing `(` on the line).
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('cognium-dev #213 — Bash `read` / `mapfile` / `getopts` sources', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const hasFlow = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows?.length ?? 0) > 0;

  const findVar = (r: Awaited<ReturnType<typeof analyze>>, v: string) =>
    r.taint.sources.some(s => s.variable === v);

  it('TP — `read name` registers $name as io_input source', async () => {
    const code = `#!/bin/bash
read name
eval "$name"
`;
    const r = await analyze(code, 'read.sh', 'bash');
    expect(findVar(r, 'name')).toBe(true);
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — `read -r cmd` (raw mode) registers $cmd', async () => {
    const code = `#!/bin/bash
read -r cmd
bash -c "$cmd"
`;
    const r = await analyze(code, 'read-r.sh', 'bash');
    expect(findVar(r, 'cmd')).toBe(true);
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — `read -p "prompt> " x` registers $x (prompt takes arg)', async () => {
    const code = `#!/bin/bash
read -p "cmd> " userCmd
bash -c "$userCmd"
`;
    const r = await analyze(code, 'read-p.sh', 'bash');
    expect(findVar(r, 'userCmd')).toBe(true);
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — bare `read` registers $REPLY as io_input source', async () => {
    const code = `#!/bin/bash
read
eval "$REPLY"
`;
    const r = await analyze(code, 'read-reply.sh', 'bash');
    expect(findVar(r, 'REPLY')).toBe(true);
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — `getopts` registers flag var and $OPTARG', async () => {
    const code = `#!/bin/bash
while getopts "u:" flag; do
  case "$flag" in
    u) eval "$OPTARG" ;;
  esac
done
`;
    const r = await analyze(code, 'getopts.sh', 'bash');
    expect(findVar(r, 'flag')).toBe(true);
    expect(findVar(r, 'OPTARG')).toBe(true);
  });

  it('TP — `mapfile -t lines` registers $lines array (t takes no arg)', async () => {
    const code = `#!/bin/bash
mapfile -t lines
eval "\${lines[0]}"
`;
    const r = await analyze(code, 'mapfile.sh', 'bash');
    expect(findVar(r, 'lines')).toBe(true);
    expect(hasFlow(r)).toBe(true);
  });

  it('FP-guard — `read() { ... }` function definition does NOT register a source', async () => {
    // Recognizer excludes any line containing `(`. The function's body
    // may itself contain `read x` — those calls are still recognized.
    const code = `#!/bin/bash
read() {
  echo "shadow"
}
read x
eval "$x"
`;
    const r = await analyze(code, 'read-fn.sh', 'bash');
    // No source on the function-definition line (line 2).
    const line2 = r.taint.sources.filter(s => s.line === 2);
    expect(line2.length).toBe(0);
    // But `read x` on line 5 still registers $x.
    expect(findVar(r, 'x')).toBe(true);
  });
});
