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
 * JVM test-class filename convention. Maven's standard `src/test/java/`
 * classpath dir hosts unit tests AND vulnerability fixtures / KATs /
 * demo sinks under corpora like `fpcorpus/`, `tpcorpus/`, `fncorpus/`.
 * Only classes ending in `Test|Tests|Spec|IT|ITCase|TestCase` follow
 * the JUnit/Spock/Spring naming convention — everything else in that
 * dir is application-shape code (fixtures, harnesses, helpers) that
 * MUST NOT be masked by a test-path allowlist.
 *
 * cognium-dev #246 REG-155-02: `EcbCipherTp.java` under
 * `src/test/java/fpcorpus/` was masked by the broad `(^|/)test/`
 * directory pattern, hiding a weak-crypto TP.
 */
const JVM_TEST_FILE_PATTERNS: readonly RegExp[] = [
  // JUnit/Spock/Spring convention: FooTest.java, FooTests.java,
  // FooSpec.java, FooIT.java, FooITCase.java, FooTestCase.java.
  /(?:^|\/)[A-Za-z_]\w*(?:Test|Tests|Spec|IT|ITCase|TestCase)\.(?:java|kt|scala|groovy)$/,
  // Alt naming: Foo.test.java, Foo.spec.java.
  /(?:^|\/)[A-Za-z_]\w*\.(?:test|spec)\.(?:java|kt|scala|groovy)$/i,
];

/** JVM-family source-file extensions covered by the tightened classifier. */
const JVM_SOURCE_FILE_RE = /\.(?:java|kt|scala|groovy)$/i;

/**
 * Returns true if the given filepath looks like a test / spec file.
 *
 * Callers that want to allowlist crypto / secret / RNG findings on
 * KAT / reproducibility vectors should short-circuit their pass when
 * this predicate fires.
 *
 * `filepath` is expected to be the `graph.ir.meta.file` string
 * (repository-relative or absolute). Backslashes are normalised.
 *
 * JVM-family files (`.java` / `.kt` / `.scala` / `.groovy`) require
 * both a test-dir match AND a JUnit-style filename suffix
 * (`*Test|*Tests|*Spec|*IT|*ITCase|*TestCase`). Maven's
 * `src/test/java/**` layout hosts vulnerability fixtures and demo
 * corpora alongside real unit tests; the filename convention is the
 * only reliable signal.
 */
export function isTestPath(filepath: string | undefined | null): boolean {
  if (!filepath) return false;
  const normalized = filepath.replace(/\\/g, '/');

  // JVM-family: require JUnit-style filename convention. Fixtures and
  // corpora under `src/test/java/` (e.g. `EcbCipherTp.java`,
  // `SqliVulnerable.java`) are NOT unit tests and must not be masked.
  if (JVM_SOURCE_FILE_RE.test(normalized)) {
    for (const pattern of JVM_TEST_FILE_PATTERNS) {
      if (pattern.test(normalized)) return true;
    }
    return false;
  }

  for (const pattern of TEST_PATH_PATTERNS) {
    if (pattern.test(normalized)) return true;
  }
  return false;
}
