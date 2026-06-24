/**
 * Tests for the central `applyLibraryApiSurfaceDowngrade` hook
 * (Sprint 47 / 3.105.0 infrastructure for cognium-dev #161, #165, #168).
 *
 * Pure-function contract:
 *   - Findings without `tags` pass through identical.
 *   - Findings tagged with `LIBRARY_API_SURFACE_TAG` and severity
 *     critical/high are downgraded to `medium` / `warning`.
 *   - Findings already `medium` or `low` are not touched (no upgrade).
 *   - The input array is not mutated; a new array is returned.
 */

import { describe, it, expect } from 'vitest';
import {
  applyLibraryApiSurfaceDowngrade,
  LIBRARY_API_SURFACE_TAG,
} from '../../src/analysis/library-api-surface-downgrade.js';
import type { SastFinding } from '../../src/types/index.js';

const baseFinding = (overrides: Partial<SastFinding>): SastFinding => ({
  id: 'test-finding-1',
  pass: 'test-pass',
  category: 'security',
  rule_id: 'test-rule',
  severity: 'high',
  level: 'error',
  message: 'test',
  file: 'Foo.java',
  line: 1,
  ...overrides,
});

describe('applyLibraryApiSurfaceDowngrade', () => {
  it('does not change findings without tags', () => {
    const input: SastFinding[] = [
      baseFinding({ id: 'a', severity: 'high', level: 'error' }),
      baseFinding({ id: 'b', severity: 'critical', level: 'error' }),
    ];
    const result = applyLibraryApiSurfaceDowngrade(input);
    expect(result[0]).toEqual(input[0]);
    expect(result[1]).toEqual(input[1]);
  });

  it('downgrades critical → medium/warning when tagged', () => {
    const input: SastFinding[] = [
      baseFinding({
        id: 'c',
        severity: 'critical',
        level: 'error',
        tags: [LIBRARY_API_SURFACE_TAG],
      }),
    ];
    const result = applyLibraryApiSurfaceDowngrade(input);
    expect(result[0].severity).toBe('medium');
    expect(result[0].level).toBe('warning');
    expect(result[0].tags).toContain(LIBRARY_API_SURFACE_TAG);
  });

  it('downgrades high → medium/warning when tagged', () => {
    const input: SastFinding[] = [
      baseFinding({
        id: 'h',
        severity: 'high',
        level: 'error',
        tags: [LIBRARY_API_SURFACE_TAG],
      }),
    ];
    const result = applyLibraryApiSurfaceDowngrade(input);
    expect(result[0].severity).toBe('medium');
    expect(result[0].level).toBe('warning');
  });

  it('does not upgrade low → medium when tagged', () => {
    const input: SastFinding[] = [
      baseFinding({
        id: 'l',
        severity: 'low',
        level: 'note',
        tags: [LIBRARY_API_SURFACE_TAG],
      }),
    ];
    const result = applyLibraryApiSurfaceDowngrade(input);
    expect(result[0].severity).toBe('low');
    expect(result[0].level).toBe('note');
  });

  it('does not mutate input findings or their tag arrays', () => {
    const inputTags = [LIBRARY_API_SURFACE_TAG];
    const input: SastFinding[] = [
      baseFinding({
        id: 'imm',
        severity: 'critical',
        level: 'error',
        tags: inputTags,
      }),
    ];
    const snapshot = { ...input[0], tags: [...inputTags] };
    const result = applyLibraryApiSurfaceDowngrade(input);
    // Input untouched.
    expect(input[0]).toEqual(snapshot);
    expect(input[0].severity).toBe('critical');
    expect(input[0].level).toBe('error');
    // New object returned.
    expect(result[0]).not.toBe(input[0]);
  });

  it('exports the canonical tag string verbatim (no LLM-themed wording)', () => {
    expect(LIBRARY_API_SURFACE_TAG).toBe('library-api-surface:caller-responsibility');
    // Pillar I guard — no LLM identifiers in the tag.
    expect(LIBRARY_API_SURFACE_TAG).not.toMatch(/llm|ai|verify/i);
  });
});
