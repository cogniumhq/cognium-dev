/**
 * cognium-dev #1187 — JS/TS project scans: drop cross-file taint paths whose
 * attacker source lives in a test/spec file but whose sink is in production code.
 */
import type { TaintPath } from '../types/index.js';

/** Test-file naming for JS/TS only (issue acceptance: `*.test.*`, `*.spec.*`, `__tests__/`). */
const JS_TS_TEST_FILE = /(?:\.(?:test|spec)\.[cm]?[jt]sx?$)|(?:(?:^|\/)__tests__\/)/i;

const JS_TS_FILE = /\.(?:[cm]?[jt]sx?)$/i;

function normPath(file: string): string {
  return file.replace(/\\/g, '/');
}

export function isJsTsFilePath(file: string): boolean {
  return JS_TS_FILE.test(normPath(file));
}

export function isJsTsTestFilePath(file: string): boolean {
  const p = normPath(file);
  return isJsTsFilePath(p) && JS_TS_TEST_FILE.test(p);
}

/**
 * Removes cross-file paths from test-only sources into production sinks (JS/TS).
 * Production→production and test→test paths are preserved.
 */
export function dropJsTestToProductionTaintPaths(paths: TaintPath[]): TaintPath[] {
  return paths.filter(tp => {
    if (!tp.path_exists) return true;
    if (!isJsTsFilePath(tp.sink.file) && !isJsTsFilePath(tp.source.file)) return true;
    if (isJsTsTestFilePath(tp.source.file) && !isJsTsTestFilePath(tp.sink.file)) {
      return false;
    }
    return true;
  });
}
