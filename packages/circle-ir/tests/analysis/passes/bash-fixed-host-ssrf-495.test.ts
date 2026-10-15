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
});
