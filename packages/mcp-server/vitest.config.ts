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
      // Baseline thresholds, measured on the pristine CI checkout rather than
      // chosen as an aspiration. They are a ratchet: raise them as the
      // tools/* handlers get tests, never lower them to make a PR pass.
      //
      // The gap is concentrated in tools/ — 11 handlers, only some exercised
      // through tests/tools.test.ts — and in the error branches of util/wasm.ts.
      thresholds: {
        statements: 63,
        branches: 46,
        functions: 66,
        lines: 69,
      },
    },
  },
});
