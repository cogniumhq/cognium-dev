/**
 * Catalog loader tests — validate that the shape exposed to the MCP
 * client matches what the check-sanitizer / describe-sink tools depend
 * on. Purely in-memory; no filesystem or WASM required.
 */

import { describe, it, expect } from 'vitest';
import {
  loadSanitizerCatalog,
  loadSinkCatalog,
  loadSourceCatalog,
} from '../src/resources/catalogs.js';

describe('catalog loaders', () => {
  it('loads sanitizer catalog with patterns and sink type mapping', () => {
    const catalog = loadSanitizerCatalog();
    expect(catalog.length).toBeGreaterThan(0);
    for (const entry of catalog) {
      expect(Array.isArray(entry.patterns)).toBe(true);
      expect(entry.patterns.length).toBeGreaterThan(0);
      for (const p of entry.patterns) expect(typeof p).toBe('string');
      expect(entry.source).toBe('circle-ir:default');
    }
    // At least some entries must carry a sinkType.
    expect(catalog.some((e) => e.sinkType)).toBe(true);
  });

  it('loads sink catalog with cwe + severity + arg positions', () => {
    const catalog = loadSinkCatalog();
    expect(catalog.length).toBeGreaterThan(0);
    for (const entry of catalog) {
      expect(entry.method).toBeTruthy();
      expect(entry.type).toBeTruthy();
      expect(entry.cwe).toMatch(/^CWE-/);
      expect(['critical', 'high', 'medium', 'low']).toContain(entry.severity);
      expect(Array.isArray(entry.argPositions)).toBe(true);
    }
  });

  it('loads source catalog with type + severity', () => {
    const catalog = loadSourceCatalog();
    expect(catalog.length).toBeGreaterThan(0);
    for (const entry of catalog) {
      expect(entry.type).toBeTruthy();
      expect(['critical', 'high', 'medium', 'low']).toContain(entry.severity);
    }
  });

  it('caches results across calls (identity check)', () => {
    const a = loadSanitizerCatalog();
    const b = loadSanitizerCatalog();
    expect(a).toBe(b);
  });
});
