/**
 * Sprint 9 #85 — verify `--exclude-tests` recognizes Go `_test.go` files.
 *
 * Locks in the `_test.go` pattern in TEST_PATTERNS (cli.ts) and the
 * `isTestFile()` predicate that gates per-file inclusion in collectFiles().
 */
import { test, expect } from 'bun:test';
import { isTestFile } from './cli.js';

test('isTestFile: Go _test.go is a test file', () => {
  expect(isTestFile('/proj/foo_test.go')).toBe(true);
  expect(isTestFile('/proj/internal/handler_test.go')).toBe(true);
  expect(isTestFile('foo_test.go')).toBe(true);
});

test('isTestFile: Go production files are NOT test files', () => {
  expect(isTestFile('/proj/foo.go')).toBe(false);
  expect(isTestFile('/proj/main.go')).toBe(false);
  expect(isTestFile('/proj/internal/handler.go')).toBe(false);
});

test('isTestFile: Python _test.py / test_*.py recognized', () => {
  expect(isTestFile('/proj/foo_test.py')).toBe(true);
  expect(isTestFile('/proj/test_foo.py')).toBe(true);
  expect(isTestFile('/proj/foo.py')).toBe(false);
});

test('isTestFile: JS/TS .test.ts / .spec.js recognized', () => {
  expect(isTestFile('/proj/foo.test.ts')).toBe(true);
  expect(isTestFile('/proj/foo.spec.js')).toBe(true);
  expect(isTestFile('/proj/foo.ts')).toBe(false);
});

test('isTestFile: Java *Test.java / *IT.java recognized', () => {
  expect(isTestFile('/proj/FooTest.java')).toBe(true);
  expect(isTestFile('/proj/FooIT.java')).toBe(true);
  expect(isTestFile('/proj/Foo.java')).toBe(false);
});

test('isTestFile: Rust _test.rs recognized', () => {
  expect(isTestFile('/proj/foo_test.rs')).toBe(true);
  expect(isTestFile('/proj/foo.rs')).toBe(false);
});

test('isTestFile: test/ tests/ __tests__/ spec/ directories recognized', () => {
  expect(isTestFile('/proj/test/foo.go')).toBe(true);
  expect(isTestFile('/proj/tests/foo.py')).toBe(true);
  expect(isTestFile('/proj/__tests__/foo.ts')).toBe(true);
  expect(isTestFile('/proj/spec/foo.rb')).toBe(true);
});
