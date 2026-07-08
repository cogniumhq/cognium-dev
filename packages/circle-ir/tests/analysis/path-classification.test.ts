/**
 * Path-classification unit tests.
 *
 * cognium-dev #239 C.2 — isTestPath() covers Java/Python/Go/JS/TS/Ruby
 * test-file conventions without a glob library.
 */

import { describe, it, expect } from 'vitest';
import { isTestPath } from '../../src/analysis/path-classification.js';

describe('isTestPath', () => {
  it('returns false for null / undefined / empty', () => {
    expect(isTestPath(null)).toBe(false);
    expect(isTestPath(undefined)).toBe(false);
    expect(isTestPath('')).toBe(false);
  });

  it('recognises Java Maven test/ layout', () => {
    expect(isTestPath('src/test/java/com/foo/BarTest.java')).toBe(true);
    expect(isTestPath('module/src/test/kotlin/BarTest.kt')).toBe(true);
  });

  it('recognises tests/ directory (Python / JS)', () => {
    expect(isTestPath('tests/unit/test_crypto.py')).toBe(true);
    expect(isTestPath('project/tests/foo.js')).toBe(true);
  });

  it('recognises Jest __tests__ convention', () => {
    expect(isTestPath('src/foo/__tests__/bar.test.ts')).toBe(true);
  });

  it('recognises RSpec spec/ convention', () => {
    expect(isTestPath('spec/models/user_spec.rb')).toBe(true);
  });

  it('recognises Go _test.go suffix', () => {
    expect(isTestPath('pkg/crypto/aes_test.go')).toBe(true);
    expect(isTestPath('cmd/foo_test.go')).toBe(true);
  });

  it('recognises Python pytest naming', () => {
    expect(isTestPath('src/test_crypto.py')).toBe(true);
    expect(isTestPath('lib/crypto_test.py')).toBe(true);
  });

  it('recognises JS/TS .test.* and .spec.* suffixes', () => {
    expect(isTestPath('src/foo.test.ts')).toBe(true);
    expect(isTestPath('src/foo.test.tsx')).toBe(true);
    expect(isTestPath('src/foo.test.js')).toBe(true);
    expect(isTestPath('src/foo.spec.ts')).toBe(true);
    expect(isTestPath('src/foo.spec.mjs')).toBe(true);
  });

  it('recognises JVM alt naming (*.test.java / *.test.kt)', () => {
    expect(isTestPath('src/Foo.test.java')).toBe(true);
    expect(isTestPath('src/Foo.test.kt')).toBe(true);
  });

  it('normalises Windows backslashes', () => {
    expect(isTestPath('src\\test\\java\\FooTest.java')).toBe(true);
    expect(isTestPath('pkg\\crypto\\aes_test.go')).toBe(true);
  });

  it('does NOT flag production paths', () => {
    expect(isTestPath('src/main/java/com/foo/Bar.java')).toBe(false);
    expect(isTestPath('src/app/foo.ts')).toBe(false);
    expect(isTestPath('lib/crypto.py')).toBe(false);
    expect(isTestPath('cmd/main.go')).toBe(false);
    expect(isTestPath('src/foo.tsx')).toBe(false);
  });

  it('does NOT match substrings inside filenames (e.g. "attestation")', () => {
    // The "test" substring in "attestation.java" is not a directory,
    // so isTestPath must return false.
    expect(isTestPath('src/main/java/AttestationService.java')).toBe(false);
    expect(isTestPath('src/latest.ts')).toBe(false);
  });

  // cognium-dev #246 REG-155-02 — JVM-family fixture recall guard.
  it('does NOT mask JVM vulnerability fixtures under src/test/java/', () => {
    // TP corpus — must fire, must not be classified as test.
    expect(isTestPath('src/test/java/fpcorpus/EcbCipherTp.java')).toBe(false);
    expect(isTestPath('java-vuln-demo/src/test/java/fpcorpus/EcbCipherTp.java')).toBe(false);
    expect(isTestPath('src/test/java/corpus/SqliVulnerable.java')).toBe(false);
    expect(isTestPath('src/test/java/cve/Cve2021xxxxx.java')).toBe(false);
    expect(isTestPath('src/test/kotlin/fpcorpus/MyBad.kt')).toBe(false);
  });

  it('preserves JVM JUnit convention (Test|Tests|Spec|IT|ITCase|TestCase)', () => {
    expect(isTestPath('src/test/java/FooTest.java')).toBe(true);
    expect(isTestPath('src/test/java/FooTests.java')).toBe(true);
    expect(isTestPath('src/test/java/FooSpec.java')).toBe(true);
    expect(isTestPath('src/test/java/FooIT.java')).toBe(true);
    expect(isTestPath('src/test/java/FooITCase.java')).toBe(true);
    expect(isTestPath('src/test/java/FooTestCase.java')).toBe(true);
    expect(isTestPath('src/test/kotlin/FooTest.kt')).toBe(true);
    expect(isTestPath('src/test/scala/FooSpec.scala')).toBe(true);
    expect(isTestPath('src/test/groovy/FooSpec.groovy')).toBe(true);
  });

  it('preserves JVM alt naming (Foo.test.java / Foo.spec.java)', () => {
    expect(isTestPath('src/Foo.test.java')).toBe(true);
    expect(isTestPath('src/Foo.spec.java')).toBe(true);
    expect(isTestPath('src/Foo.test.kt')).toBe(true);
  });

  it('rejects JVM main-src files even under `test` if not JUnit-named', () => {
    // Edge case: someone has a `test/` subdir under `src/main/`. Still not
    // a test dir semantically, and the file lacks the JUnit suffix.
    expect(isTestPath('src/main/java/test/HelperUtil.java')).toBe(false);
    // Sanity — a helper class named Helper.java inside a Maven test tree
    // is a fixture / harness, not a unit test.
    expect(isTestPath('src/test/java/util/HelperUtil.java')).toBe(false);
  });
});
