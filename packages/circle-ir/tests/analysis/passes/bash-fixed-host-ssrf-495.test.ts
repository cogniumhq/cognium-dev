/**
 * cognium-dev #495 / #669 — bash `curl` / `wget` whose URL has a literal
 * scheme and host, closed by `/`, cannot be pointed at another host by the
 * interpolated path. It is not SSRF. A variable host, a whole-URL variable,
 * or a path glued to the host without `/` (`…example.com${p}`, where `$p` may
 * be `@evil.test`) still is.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

async function ssrfSinkLines(code: string): Promise<number[]> {
  const ir = await analyze(code, 'fetch_report.sh', 'bash');
  return (ir.taint.flows ?? []).filter(f => f.sink_type === 'ssrf').map(f => f.sink_line).sort((a, b) => a - b);
}

beforeAll(async () => {
  await initAnalyzer();
});

describe('#495 bash ssrf: fixed host', () => {
  it('allow-listed path on a literal host is clean', async () => {
    const code = `#!/bin/bash
set -euo pipefail
report="$1"
[[ "$report" =~ ^[a-z0-9/_-]+$ ]] || { echo "bad report"; exit 1; }
curl -fsS -- "https://reports.internal.example/\${report}"
`;
    expect(await ssrfSinkLines(code)).toEqual([]);
  });

  it('wget with a literal host and an interpolated path is clean', async () => {
    const code = `#!/bin/bash
page="$1"
wget -q "https://docs.example.org/$page"
`;
    expect(await ssrfSinkLines(code)).toEqual([]);
  });

  it('whole-URL variable still fires', async () => {
    const code = `#!/bin/bash
target="$1"
curl -s "$target"
`;
    expect(await ssrfSinkLines(code)).toEqual([3]);
  });

  it('variable host still fires', async () => {
    const code = `#!/bin/bash
mirror="$1"
curl -s "https://\${mirror}/status"
`;
    expect(await ssrfSinkLines(code)).toEqual([3]);
  });

  it('path glued to the host without a slash still fires', async () => {
    const code = `#!/bin/bash
rest="$1"
curl -s "https://api.example.com\${rest}"
`;
    expect(await ssrfSinkLines(code)).toEqual([3]);
  });

  it('a second, variable URL on the same line still fires', async () => {
    const code = `#!/bin/bash
a="$1"
b="$2"
curl -s "https://docs.example.org/$a" "$b"
`;
    expect(new Set(await ssrfSinkLines(code))).toEqual(new Set([4]));
  });

  it('an unquoted path expansion still fires: word splitting can add a URL', async () => {
    const code = `#!/bin/bash
rel="$1"
curl -s https://api.example.com/$rel
`;
    expect(await ssrfSinkLines(code)).toEqual([3]);
  });

  it('a cleared fixed-host call is not re-reported as command_injection', async () => {
    const code = `#!/bin/bash
seg="$2"
wget -q "http://10.0.0.5:8080/files/\${seg}"
curl -s "https://api.example.com/$seg" -o out.txt
`;
    const ir = await analyze(code, 'mirror_fetch.sh', 'bash');
    expect(ir.taint.flows ?? []).toEqual([]);
  });
});

describe('#669 CWE-88 safe mirror (bash-vuln-demo/safe_arg_injection.sh @ 4dc06ce)', () => {
  it('scans clean', async () => {
    const code = `#!/bin/bash
# SAFE / FP probe for argument-injection (CWE-88). Tainted values are separated from
# option parsing with the "--" terminator and/or shell-escaped, so user data can never
# be interpreted as a flag. The scanner MUST produce ZERO security findings; any
# argument_injection / command_injection finding here is a FALSE POSITIVE.
set -euo pipefail

# 1. "--" terminator — everything after it is treated as operands, never options,
#    so a value like "--exec=..." cannot smuggle a flag into grep/rm/curl.
pattern="$1"
grep -- "$pattern" /var/log/app.log || true

file="$2"
rm -f -- "$file"

# 2. printf %q escapes the value before it is embedded anywhere.
raw="$3"
safe=$(printf '%q' "$raw")
logger "processed: $safe"

# 3. Explicit option/value split — curl URL passed positionally after "--".
url_path="$4"
[[ "$url_path" =~ ^[A-Za-z0-9/_-]+$ ]] || { echo "bad path"; exit 1; }
curl -fsS -- "https://api.example.com/\${url_path}"
`;
    const ir = await analyze(code, 'safe_arg_injection.sh', 'bash');
    expect(ir.taint.flows ?? []).toEqual([]);
  });
});
