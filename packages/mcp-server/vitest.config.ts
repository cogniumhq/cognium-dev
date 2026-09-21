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
      // Measured 2026-09-20 after tools-filters-cache.test.ts covered
      // refresh's single-project branch, scan's filter permutations and the
      // filesystem error paths in util/files:
      // 92.81 stmts / 80.64 branches / 95.69 funcs / 95.50 lines.
      //
      // What remains is mostly describe-source.ts (75/53.84) and the
      // list-entry-points framework branches (57.14).
      thresholds: {
        statements: 91,
        branches: 78,
        functions: 94,
        lines: 94,
      },
    },
  },
});
