/**
 * #393 — modelled-CWE export.
 *
 * The taint-addressable subset of a CWE-labelled corpus has to be defined by
 * the engine, not by a hand list that drifts or can be tuned. These tests pin
 * that the export is DERIVED from the live registries (so it cannot fall
 * behind them) and that the related-id map never widens scope onto a class the
 * engine does not actually model.
 */

import { describe, it, expect } from 'vitest';
import { getModelledCwes, isModelledCwe, RELATED_CWE } from '../../src/index.js';
import { DEFAULT_SINKS } from '../../src/analysis/config-loader.js';
import { createBuiltinPlugins, registerBuiltinPlugins } from '../../src/languages/plugins/index.js';
import { getLanguageRegistry } from '../../src/languages/registry.js';

describe('#393 — getModelledCwes', () => {
  const m = getModelledCwes();

  it('is well-formed: CWE ids, unique, numerically sorted', () => {
    expect(m.sinkCwes.length).toBeGreaterThan(10);
    expect(m.sinkCwes.every((c) => /^CWE-\d+$/.test(c))).toBe(true);
    expect(new Set(m.sinkCwes).size).toBe(m.sinkCwes.length);
    const nums = m.sinkCwes.map((c) => Number(c.slice(4)));
    expect(nums).toEqual([...nums].sort((a, b) => a - b));
  });

  it('covers the core taint classes', () => {
    for (const c of ['CWE-22', 'CWE-78', 'CWE-79', 'CWE-89', 'CWE-94', 'CWE-502', 'CWE-601', 'CWE-611', 'CWE-918']) {
      expect(m.sinkCwes).toContain(c);
    }
  });

  it('is derived from the live registries — no registered sink CWE is missing', () => {
    const live = new Set<string>();
    for (const s of DEFAULT_SINKS) if (s.cwe) live.add(s.cwe);
    for (const p of createBuiltinPlugins()) for (const s of p.getBuiltinSinks()) if (s.cwe) live.add(s.cwe);
    expect(new Set(m.sinkCwes)).toEqual(live);
  });

  it('never maps a related id onto a class the engine does not model', () => {
    for (const [advisory, modelled] of Object.entries(RELATED_CWE)) {
      expect(m.sinkCwes, `${advisory} -> ${modelled}`).toContain(modelled);
      // An id that is already a sink CWE needs no mapping; one here is dead weight.
      expect(m.sinkCwes, `${advisory} is already modelled directly`).not.toContain(advisory);
    }
  });

  it('isModelledCwe: direct, related, and out-of-scope classes', () => {
    expect(isModelledCwe('CWE-22')).toBe(true);
    expect(isModelledCwe('CWE-23')).toBe(true);   // related -> CWE-22
    expect(isModelledCwe('CWE-917')).toBe(true);  // related -> CWE-94
    for (const c of ['CWE-400', 'CWE-20', 'CWE-362', 'CWE-863', 'CWE-287']) {
      expect(isModelledCwe(c), c).toBe(false);
    }
  });

  it('a related id stops counting once the class it maps to is no longer modelled', () => {
    const without22 = { ...m, sinkCwes: m.sinkCwes.filter((c) => c !== 'CWE-22') };
    expect(isModelledCwe('CWE-23', without22)).toBe(false);
    expect(isModelledCwe('CWE-79', without22)).toBe(true);
  });

  it('enumerates exactly the plugins the analyzer registers', () => {
    registerBuiltinPlugins();
    const registered = [...getLanguageRegistry().getSupportedLanguages()].sort();
    const created = createBuiltinPlugins().map((p) => p.id).sort();
    expect(created).toEqual(registered);
  });
});
