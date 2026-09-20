import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: [
        'src/index.ts',        // Bin entry point — wires stdio transport, nothing to assert
        'src/resources/index.ts', // Barrel file (re-exports only)
        'src/tools/types.ts',  // Type definitions only
      ],
      reporter: ['text-summary', 'lcov', 'json-summary'],
      // Thresholds sit just under the measured values, and ratchet: raise
      // them as coverage improves, never lower them to make a PR pass.
      //
      // Measured 2026-09-20 after tests/tools-analysis.test.ts covered the
      // four analysis handlers, which had sat at 0% branch coverage:
      // 86.79 stmts / 70.69 branches / 92.47 funcs / 91.23 lines.
      //
      // What remains is concentrated in refresh.ts (66.66/50 — the cache-miss
      // path), scan.ts (77.77/55.1 — option permutations), and util/files.ts
      // (73.17/57.14 — filesystem error branches).
      thresholds: {
        statements: 84,
        branches: 68,
        functions: 90,
        lines: 89,
      },
    },
  },
});
