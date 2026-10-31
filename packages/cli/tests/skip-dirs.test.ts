/**
 * #1025 — the directory walkers skip dependencies and generated report folders
 * (`coverage/`, `.nyc_output/`, `lcov-report/`, `htmlcov/`) by default, from one
 * shared list, and a config `include` that names such a folder still reads it.
 */
import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, relative, sep } from 'path';
import { collectFiles, collectManifestFiles, collectResourceFiles, includeReach } from '../src/cli';
import { SKIPPED_DIRECTORIES, walk } from '../src/graph-facts';
import {
  BUILD_OUTPUT_DIRECTORIES,
  DEPENDENCY_DIRECTORIES,
  REPORT_DIRECTORIES,
  SCAN_SKIPPED_DIRECTORIES,
  STRUCTURE_SKIPPED_DIRECTORIES,
  isScanSkippedDirectory,
  isStructureSkippedDirectory,
} from '../src/utils/skip-dirs';

let root: string;

function write(rel: string, text = ''): void {
  const abs = join(root, rel);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, text);
}

const rel = (files: string[]): string[] =>
  files.map((f) => relative(root, f).split(sep).join('/')).sort();

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'cog-skip-'));
  // Source the project owns.
  write('src/app.ts', 'export const a = 1;\n');
  write('src/app.properties', 'k=v\n');
  write('bin/deploy.sh', '#!/bin/sh\necho hi\n');
  write('package.json', '{"name":"fixture","version":"1.0.0"}');
  // Coverage output from a test run (Istanbul / Jest / nyc / coverage.py).
  write('coverage/lcov-report/prettify.js', 'var x = eval("1");\n');
  write('coverage/lcov-report/sorter.js', 'document.write(location.hash);\n');
  write('coverage/app.properties', 'k=v\n');
  write('coverage/package.json', '{"name":"report","version":"0.0.0"}');
  write('packages/mobile/coverage/lcov-report/index.js', 'eval(location.hash);\n');
  write('packages/mobile/src/screen.tsx', 'export const S = 1;\n');
  write('reports/lcov-report/block.js', 'eval(location.hash);\n');
  write('.nyc_output/processinfo/x.js', 'eval(1);\n');
  write('htmlcov/coverage_html.js', 'eval(1);\n');
  // Dependencies.
  write('node_modules/dep/index.js', 'eval(1);\n');
  write('vendor/lib/lib.go', 'package lib\n');
  write('venv/lib/site.py', 'x = 1\n');
  // Build output.
  write('dist/bundle.js', 'eval(1);\n');
});

afterAll(() => rmSync(root, { recursive: true, force: true }));

describe('the shared list', () => {
  test('names the coverage report folders', () => {
    for (const d of ['coverage', '.nyc_output', 'lcov-report', 'htmlcov']) {
      expect(REPORT_DIRECTORIES as readonly string[]).toContain(d);
      expect(isScanSkippedDirectory(d)).toBe(true);
      expect(isStructureSkippedDirectory(d)).toBe(true);
    }
  });

  test('scan skips dependencies and reports, not build output', () => {
    expect([...SCAN_SKIPPED_DIRECTORIES].sort()).toEqual([...DEPENDENCY_DIRECTORIES, ...REPORT_DIRECTORIES].sort());
    for (const d of BUILD_OUTPUT_DIRECTORIES) expect(isScanSkippedDirectory(d)).toBe(false);
  });

  test('graph and sbom walkers read the same list plus build output', () => {
    expect(SKIPPED_DIRECTORIES).toBe(STRUCTURE_SKIPPED_DIRECTORIES);
    for (const d of [...SCAN_SKIPPED_DIRECTORIES, ...BUILD_OUTPUT_DIRECTORIES]) {
      expect(STRUCTURE_SKIPPED_DIRECTORIES).toContain(d);
    }
  });

  test('dot-directories are skipped by every walker', () => {
    expect(isScanSkippedDirectory('.cache')).toBe(true);
    expect(isStructureSkippedDirectory('.cache')).toBe(true);
    expect(isScanSkippedDirectory('src')).toBe(false);
  });
});

describe('scan / metrics: collectFiles', () => {
  test('skips coverage, lcov-report, .nyc_output, htmlcov and dependencies by default', async () => {
    expect(rel(await collectFiles(root, { basePath: root }))).toEqual([
      'bin/deploy.sh',
      'dist/bundle.js',
      'packages/mobile/src/screen.tsx',
      'src/app.ts',
    ]);
  });

  test('a config include that names the folder reads it', async () => {
    const files = rel(await collectFiles(root, { basePath: root, includePatterns: ['coverage/**'] }));
    expect(files).toEqual(['coverage/lcov-report/prettify.js', 'coverage/lcov-report/sorter.js']);
  });

  test('an include naming a dependency folder reads only that folder', async () => {
    const files = rel(await collectFiles(root, { basePath: root, includePatterns: ['node_modules/**'] }));
    expect(files).toEqual(['node_modules/dep/index.js']);
  });

  test('a globstar include reaches a nested report folder', async () => {
    const files = rel(await collectFiles(root, { basePath: root, includePatterns: ['**/lcov-report/**'] }));
    expect(files).toEqual([
      'coverage/lcov-report/prettify.js',
      'coverage/lcov-report/sorter.js',
      'packages/mobile/coverage/lcov-report/index.js',
      'reports/lcov-report/block.js',
    ]);
  });

  test('an include that does not name the folder leaves it skipped', async () => {
    const files = rel(await collectFiles(root, { basePath: root, includePatterns: ['**/*.js'] }));
    expect(files).toEqual(['dist/bundle.js']);
  });

  test('the folder passed as the scan path is read', async () => {
    const target = join(root, 'coverage');
    const files = (await collectFiles(target, { basePath: target })).map((f) => relative(target, f).split(sep).join('/'));
    expect(files.sort()).toEqual(['lcov-report/prettify.js', 'lcov-report/sorter.js']);
  });

  test('config exclude still applies on top', async () => {
    const files = rel(await collectFiles(root, { basePath: root, excludePatterns: ['dist/**'] }));
    expect(files).not.toContain('dist/bundle.js');
  });
});

describe('includeReach', () => {
  test('names the directory by its own segment at the right depth', () => {
    expect(includeReach('coverage', ['coverage/**'])).toBe('names');
    expect(includeReach('coverage', ['./coverage/**/*.js'])).toBe('names');
    expect(includeReach('a/b/vendor', ['**/vendor/**'])).toBe('names');
    expect(includeReach('packages/app/coverage', ['packages/*/coverage/*.js'])).toBe('names');
    expect(includeReach('.nyc_output', ['.nyc_output/**'])).toBe('names');
  });

  test('reaches through a skipped parent toward a named one', () => {
    expect(includeReach('coverage', ['**/lcov-report/**'])).toBe('above');
    expect(includeReach('packages/app/coverage', ['packages/*/coverage/lcov-report/*.js'])).toBe('names');
  });

  test('leaves the directory skipped otherwise', () => {
    expect(includeReach('other/coverage', ['packages/*/coverage/*.js'])).toBe('none');
    expect(includeReach('coverage', ['src/**'])).toBe('none');
    expect(includeReach('coverage', ['**/*.js'])).toBe('none');
    expect(includeReach('coverage', ['src/lcov-report/**'])).toBe('none');
    expect(includeReach('coverage', undefined)).toBe('none');
  });
});

test('resource files are not read from report folders', async () => {
  const found = rel([...(await collectResourceFiles(root, { basePath: root })).keys()]);
  expect(found).toEqual(['src/app.properties']);
});

test('sbom does not read manifests from report folders', async () => {
  expect(rel(await collectManifestFiles(root))).toEqual(['package.json']);
});

test('deadcode / reach / entries walk skips reports, dependencies and build output', () => {
  expect(walk(root, (p) => /\.(js|ts|tsx|sh|go|py)$/.test(p))).toEqual([
    'packages/mobile/src/screen.tsx',
    'src/app.ts',
  ]);
});
