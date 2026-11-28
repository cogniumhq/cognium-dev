/**
 * Parse-status for languages with no grammar (#1307).
 *
 * `c` and `cpp` are `SupportedLanguage` values, but no tree-sitter grammar
 * ships for them, so `analyze()` threw ENOENT opening the missing wasm. It now
 * returns an empty IR whose `parse_status.state` is `unsupported`.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { hasGrammar } from '../../src/core/index.js';

const C_SOURCE = `#include <stdlib.h>

int main(int argc, char **argv) {
    return system(argv[1]);
}
`;

const CPP_SOURCE = `#include <cstdlib>

class Runner {
public:
    int run(const char *cmd) { return std::system(cmd); }
};
`;

describe('parse_status for languages with no grammar (#1307)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('has no bundled grammar for c and cpp', () => {
    expect(hasGrammar('c')).toBe(false);
    expect(hasGrammar('cpp')).toBe(false);
    expect(hasGrammar('java')).toBe(true);
  });

  it.each([
    ['main.c', 'c' as const, C_SOURCE],
    ['runner.cpp', 'cpp' as const, CPP_SOURCE],
  ])('reports %s as unsupported instead of throwing', async (file, language, code) => {
    const ir = await analyze(code, file, language);
    expect(ir.parse_status).toEqual({
      state: 'unsupported',
      reason: `no ${language} grammar is available`,
      success: false,
      has_errors: false,
      error_count: 0,
      error_locations: [],
    });
    expect(ir.meta.file).toBe(file);
    expect(ir.meta.language).toBe(language);
    expect(ir.meta.loc).toBeGreaterThan(0);
    expect(ir.types).toEqual([]);
    expect(ir.calls).toEqual([]);
    expect(ir.taint.sources).toEqual([]);
    expect(ir.taint.sinks).toEqual([]);
    expect(ir.findings).toBeUndefined();
  });

  it('reports complete and partial states for languages that parse', async () => {
    const clean = await analyze('class Foo {}', 'Foo.java', 'java');
    expect(clean.parse_status?.state).toBe('complete');
    const broken = await analyze('class Foo {\n    int x = (\n}', 'Foo.java', 'java');
    expect(broken.parse_status?.state).toBe('partial');
  });
});
