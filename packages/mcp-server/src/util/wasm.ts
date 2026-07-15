/**
 * WASM initialization for circle-ir in Node.js.
 *
 * Resolves the tree-sitter grammar files from the installed `circle-ir`
 * package via `createRequire` so the server works regardless of npm
 * hoisting layout.
 */

import { createRequire } from 'module';
import { dirname, join } from 'path';
import { initAnalyzer, isAnalyzerInitialized } from 'circle-ir';

let initPromise: Promise<void> | null = null;

export async function ensureAnalyzer(): Promise<void> {
  if (isAnalyzerInitialized()) return;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    const require = createRequire(import.meta.url);
    const circleIrPkg = require.resolve('circle-ir/package.json');
    const wasmBase = join(dirname(circleIrPkg), 'dist', 'wasm') + '/';
    await initAnalyzer({
      wasmPath: wasmBase + 'web-tree-sitter.wasm',
      languagePaths: {
        bash: wasmBase + 'tree-sitter-bash.wasm',
        go: wasmBase + 'tree-sitter-go.wasm',
        java: wasmBase + 'tree-sitter-java.wasm',
        javascript: wasmBase + 'tree-sitter-javascript.wasm',
        typescript: wasmBase + 'tree-sitter-javascript.wasm',
        python: wasmBase + 'tree-sitter-python.wasm',
        rust: wasmBase + 'tree-sitter-rust.wasm',
        html: wasmBase + 'tree-sitter-html.wasm',
      },
    });
  })();

  return initPromise;
}
