import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['tests/**/*.test.ts'],
    setupFiles: ['tests/setup.ts'],
    testTimeout: 30000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: [
        'src/browser.ts',       // Browser entry point
        'src/worker.ts',        // Cloudflare Workers entry point
        'src/index.ts',         // Re-exports only
        'src/core-lib.ts',      // Re-exports only
        'src/*/index.ts',       // Barrel files (re-exports only)
        'src/*/*/index.ts',     // Nested barrel files (re-exports only)
        'src/types/**',         // Type definitions only
        'src/languages/types.ts',  // Type definitions only
        'src/analysis/constant-propagation/types.ts',  // Type definitions only
        'src/analysis/constant-propagation.ts',        // Pure re-export facade (covered via directory)
        'src/resolution/**',    // Cross-file resolution (covered by integration tests)
      ],
      thresholds: {
        statements: 83,
        branches: 70,  // Limited by WASM-dependent language extraction (calls.ts, java.ts, analyzer.ts)
        functions: 88,
        lines: 85,
      },
    },
  },
});
