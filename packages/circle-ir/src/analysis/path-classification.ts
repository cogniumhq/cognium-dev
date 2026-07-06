/**
 * Path-classification predicates.
 *
 * cognium-dev #239 C.2 — weak-crypto test-file allowlist.
 *
 * Test-file layouts vary across languages/build systems (Maven/Gradle,
 * Python pytest, Go, JS/TS jest+vitest, RSpec). This module owns the
 * zero-dependency regex-only classifier used by passes that want to
 * allowlist findings on test fixtures.
 *
 * Browser + Node.js compatible: no glob library, no `path` module.
 */

/**
 * Test-file conventions matched:
 * - `**\/test\/**`         Java Maven/Gradle
 * - `**\/tests\/**`        Python / JS / Go
 * - `**\/testing\/**`      Bazel/other convention
 * - `**\/__tests__\/**`    Jest convention
 * - `**\/*_test.go`        Go
 * - `**\/*.test.{ts,tsx,js,jsx,mjs,cjs}` JS/TS unit-test naming
 * - `**\/*.spec.{ts,tsx,js,jsx,mjs,cjs}` JS/TS spec naming
 * - `**\/spec\/**`         RSpec convention
 * - `**\/test_*.py`        Python pytest naming
 * - `**\/*_test.py`        Python alt naming
 * - `**\/*.test.{java,kt}` JVM alt naming
 *
 * The `**` is implicit — matches anywhere in the path. Paths are
 * normalised to forward slashes before matching so Windows call sites
 * behave identically.
 */
const TEST_PATH_PATTERNS: readonly RegExp[] = [
  // Directory-based conventions
  /(^|\/)test\//i,
  /(^|\/)tests\//i,
  /(^|\/)testing\//i,
  /(^|\/)__tests__\//i,
  /(^|\/)spec\//i,
  // Go test file suffix
  /_test\.go$/i,
  // Python pytest naming
  /(^|\/)test_[^/]+\.py$/i,
  /_test\.py$/i,
  // JS/TS unit / spec naming
  /\.test\.(?:tsx?|jsx?|mjs|cjs)$/i,
  /\.spec\.(?:tsx?|jsx?|mjs|cjs)$/i,
  // JVM alt naming
  /\.test\.(?:java|kt)$/i,
];

/**
 * Returns true if the given filepath looks like a test / spec file.
 *
 * Callers that want to allowlist crypto / secret / RNG findings on
 * KAT / reproducibility vectors should short-circuit their pass when
 * this predicate fires.
 *
 * `filepath` is expected to be the `graph.ir.meta.file` string
 * (repository-relative or absolute). Backslashes are normalised.
 */
export function isTestPath(filepath: string | undefined | null): boolean {
  if (!filepath) return false;
  const normalized = filepath.replace(/\\/g, '/');
  for (const pattern of TEST_PATH_PATTERNS) {
    if (pattern.test(normalized)) return true;
  }
  return false;
}
