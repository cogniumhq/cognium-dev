/**
 * #473 — a failed Parser.init must not be cached forever.
 *
 * initParser() caches the in-flight promise so concurrent callers share one
 * WASM init. It used to clear that cache only on success, so one rejected
 * init (bad wasmPath, transient fetch failure) made every later call return
 * the same rejection with no way to retry.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';

describe('#473 — initParser retries after a failed init', () => {
  afterEach(() => {
    vi.doUnmock('web-tree-sitter');
    vi.resetModules();
  });

  it('a second call re-runs Parser.init after the first one rejected', async () => {
    vi.resetModules();
    const init = vi.fn()
      .mockRejectedValueOnce(new Error('wasm fetch failed'))
      .mockResolvedValueOnce(undefined);
    vi.doMock('web-tree-sitter', async (importOriginal) => {
      const actual = await importOriginal<typeof import('web-tree-sitter')>();
      class Parser extends actual.Parser {}
      Object.defineProperty(Parser, 'init', { value: init });
      return { ...actual, Parser };
    });
    const { initParser } = await import('../../src/core/parser.js');

    await expect(initParser({ wasmPath: '/nonexistent.wasm' })).rejects.toThrow('wasm fetch failed');
    await expect(initParser({ wasmPath: '/ok.wasm' })).resolves.toBeUndefined();
    expect(init).toHaveBeenCalledTimes(2);
  });

  it('concurrent callers still share one in-flight init', async () => {
    vi.resetModules();
    const init = vi.fn().mockResolvedValue(undefined);
    vi.doMock('web-tree-sitter', async (importOriginal) => {
      const actual = await importOriginal<typeof import('web-tree-sitter')>();
      class Parser extends actual.Parser {}
      Object.defineProperty(Parser, 'init', { value: init });
      return { ...actual, Parser };
    });
    const { initParser } = await import('../../src/core/parser.js');

    await Promise.all([initParser({ wasmPath: '/a.wasm' }), initParser({ wasmPath: '/a.wasm' })]);
    expect(init).toHaveBeenCalledTimes(1);
  });
});
