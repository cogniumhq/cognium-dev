/**
 * S3 (8 Nov security Request): a line of a few hundred bytes made `scan` run
 * for hours. Eight engine regexes backtracked exponentially; the Go map
 * allow-list guard (`language-sources-pass.ts`) was the one on the Go path:
 * a line with many `||` disjuncts and no `!map[key]` doubled its time with
 * every disjunct (about 4 s at 112 bytes and 39 s at 124 bytes before the
 * fix). The inputs below are generated, short, and each shape was
 * exponential before; each must now finish well inside a second.
 *
 * Also: `analyze()` reports the file it starts and ends through
 * `onFileStart` / `onFileEnd`, which the CLI watchdog uses to bound a step
 * the per-file limit cannot interrupt.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const goFile = (body: string) => `package main

import "net/http"

func h(w http.ResponseWriter, r *http.Request) {
\ta := r.URL.Query().Get("a") != ""
${body}
\t_ = a
}
`;

async function timed<T>(f: () => Promise<T>): Promise<{ ms: number; value: T }> {
  const t = performance.now();
  const value = await f();
  return { ms: performance.now() - t, value };
}

describe('S3: no exponential backtracking on crafted lines', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('Go: an `if` with many `||` disjuncts and no map guard', async () => {
    // 60 disjuncts, about 370 bytes. Before the fix 20 disjuncts took 39 s.
    const line = '\tif ' + 'a ||  '.repeat(60) + 'z';
    const { ms } = await timed(() => analyze(goFile(line), 'main.go', 'go'));
    expect(ms).toBeLessThan(5000);
  });

  it('JavaScript: an unterminated string of backslashes', async () => {
    // The quoted-string matcher `(?:\\.|(?!\1).)*` let both branches take a backslash.
    const code = `const s = "${'\\\\'.repeat(40)}\nconst t = 1;\n`;
    const { ms } = await timed(() => analyze(code, 'a.js', 'javascript'));
    expect(ms).toBeLessThan(5000);
  });

  it('Python: an unterminated f-string of backslashes', async () => {
    const code = `x = f"${'\\\\'.repeat(40)}\ny = 1\n`;
    const { ms } = await timed(() => analyze(code, 'a.py', 'python'));
    expect(ms).toBeLessThan(5000);
  });

  it('the Go map allow-list guard still matches a negated lookup after `||` disjuncts', async () => {
    // #293: `if err != nil || !allowedHosts[u.Host] {` guards the branch below it.
    const code = goFile(`\tu := r.URL
\tif a || !allowedHosts[u.Host] {
\t\treturn
\t}
\thttp.Get(r.URL.Query().Get("url"))`);
    const ir = await analyze(code, 'main.go', 'go');
    expect(ir.taint.sanitizers.some(s => s.type === 'go_map_allowlist_guard')).toBe(true);
  });
});

describe('onFileStart / onFileEnd', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports the file on start and end, also when analysis throws', async () => {
    const seen: string[] = [];
    const opts = { onFileStart: (f: string) => seen.push(`start ${f}`), onFileEnd: (f: string) => seen.push(`end ${f}`) };
    await analyze('package main\n', 'ok.go', 'go', opts);
    expect(seen).toEqual(['start ok.go', 'end ok.go']);
    seen.length = 0;
    await expect(analyze('x', 'bad.unknown', 'cobol' as 'go', opts)).rejects.toThrow();
    expect(seen).toEqual(['start bad.unknown', 'end bad.unknown']);
  });

  it('starts and ends balance on a markup file that analyses its scripts', async () => {
    const depth: number[] = [];
    let open = 0;
    await analyze('<html><script>var a = 1;</script></html>', 'a.html', 'html', {
      onFileStart: () => { open++; depth.push(open); },
      onFileEnd: () => { open--; },
    });
    expect(open).toBe(0);
    expect(depth.length).toBeGreaterThan(0);
  });
});
