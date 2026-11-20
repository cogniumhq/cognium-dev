/**
 * cognium-dev#1325: `this.#map.get(key)` on a private class field initialised
 * with `new Map()` must not report sql_injection (residual of #997 / #985).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('#1325 private #map field get()', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TS: readonly #map = new Map() — no sql_injection flow', async () => {
    const code = `export class C<K, V> {
  readonly #map = new Map<K, V>();
  get(key: K): V | undefined {
    const e = this.#map.get(key);
    return e;
  }
}`;
    const ir = await analyze(code, 'cache.ts', 'typescript');
    expect(ir.taint.sources.filter((s) => s.type === 'db_input')).toHaveLength(0);
    expect(ir.taint.flows.filter((f) => f.sink_type === 'sql_injection')).toHaveLength(0);
  });
});