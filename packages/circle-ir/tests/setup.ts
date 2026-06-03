/**
 * Test setup file
 *
 * Runs before all tests to initialize the Tree-sitter parser.
 *
 * Why we pre-resolve WASM paths here:
 * The library's auto-discovery in `getDefaultWasmPath()` uses
 * `new Function('m', 'return import(m)')` to hide Node built-in imports from
 * browser bundlers. That pattern fails in Vitest's VM context with
 * "A dynamic import callback was not specified". Passing explicit paths
 * bypasses discovery entirely.
 */

import { beforeAll, afterAll } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { initParser, resetParser, type SupportedLanguage } from '../src/core/parser.js';

const here = dirname(fileURLToPath(import.meta.url));
const wasmDir = join(here, '..', 'dist', 'wasm');

const grammarFile: Partial<Record<SupportedLanguage, string>> = {
  java:       'tree-sitter-java.wasm',
  javascript: 'tree-sitter-javascript.wasm',
  typescript: 'tree-sitter-typescript.wasm',
  python:     'tree-sitter-python.wasm',
  go:         'tree-sitter-go.wasm',
  rust:       'tree-sitter-rust.wasm',
  bash:       'tree-sitter-bash.wasm',
  html:       'tree-sitter-html.wasm',
};

const languagePaths = Object.fromEntries(
  Object.entries(grammarFile).map(([lang, file]) => [lang, join(wasmDir, file)])
) as Partial<Record<SupportedLanguage, string>>;

beforeAll(async () => {
  await initParser({
    wasmPath: join(wasmDir, 'web-tree-sitter.wasm'),
    languagePaths,
  });
});

afterAll(() => {
  resetParser();
});
