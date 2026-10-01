import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: [
        'src/bin.ts',          // Bin entry point — wires stdio transport, nothing to assert
        'src/index.ts',        // Library barrel (re-exports only)
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
      // Re-measured 2026-10-01 with the optional-module seam and its tests:
      // 93.68 stmts / 83.89 branches / 96.74 funcs / 96.05 lines. Ratcheted.
      //
      // What remains is mostly describe-source.ts, attack-surface-summary's
      // roll-up branches and the list-entry-points framework branches.
      thresholds: {
        statements: 93,
        branches: 83,
        functions: 96,
        lines: 95,
      },
    },
  },
});
