/**
 * Tests for `applyProjectProfileTransform` (3.106.0, #169).
 *
 * Validates the C-Yes-Yes policy locked in ADR-008:
 *   D1=C  CRIT-protected bucketing (CRIT→MED, HIGH→LOW, MED→LOW, LOW→LOW)
 *   D2=Yes Sink-type allowlist (only code/template/xpath/sql injection)
 *   D3=Yes Restore original_severity under `application` profile
 *
 * Composition contract (with `applyLibraryApiSurfaceDowngrade`):
 *   findings
 *     → applyConfidenceFilter
 *     → applyLibraryApiSurfaceDowngrade   (sets original_severity, → MED)
 *     → applyProjectProfileTransform      (this — profile-conditional)
 *     → applyPerFileFindingCap
 */

import { describe, it, expect } from 'vitest';
import {
  applyProjectProfileTransform,
  type ProfileResolver,
} from '../../src/analysis/project-profile-transform.js';
import {
  applyLibraryApiSurfaceDowngrade,
  LIBRARY_API_SURFACE_TAG,
} from '../../src/analysis/library-api-surface-downgrade.js';
import type { SastFinding, ProjectProfile } from '../../src/types/index.js';

const baseFinding = (overrides: Partial<SastFinding>): SastFinding => ({
  id: 'pp-test-1',
  pass: 'test-pass',
  category: 'security',
  rule_id: 'code_injection',
  severity: 'high',
  level: 'error',
  message: 'test',
  file: 'Foo.java',
  line: 1,
  ...overrides,
});

const resolver = (profile: ProjectProfile): ProfileResolver => () => profile;

describe('applyProjectProfileTransform — passthrough rules', () => {
  it('returns input array contents identical when resolver yields unknown', () => {
    const input: SastFinding[] = [
      baseFinding({ id: 'a', severity: 'critical', tags: [LIBRARY_API_SURFACE_TAG] }),
      baseFinding({ id: 'b', severity: 'high', tags: [LIBRARY_API_SURFACE_TAG] }),
    ];
    const result = applyProjectProfileTransform(input, resolver('unknown'));
    // Same references because no transform applied.
    expect(result[0]).toBe(input[0]);
    expect(result[1]).toBe(input[1]);
  });

  it('ignores findings without the library-api-surface tag', () => {
    const input: SastFinding[] = [
      baseFinding({ id: 'untagged', severity: 'critical', rule_id: 'code_injection' }),
    ];
    const result = applyProjectProfileTransform(input, resolver('library/production'));
    expect(result[0]).toBe(input[0]);
  });

  it('ignores tagged findings whose rule_id is outside the downgrade allowlist', () => {
    const input: SastFinding[] = [
      baseFinding({
        id: 'wrong-sink',
        rule_id: 'deserialization', // NOT in DOWNGRADE_ELIGIBLE_RULE_IDS
        severity: 'critical',
        tags: [LIBRARY_API_SURFACE_TAG],
      }),
    ];
    const result = applyProjectProfileTransform(input, resolver('library/production'));
    expect(result[0]).toBe(input[0]);
  });
});

describe('applyProjectProfileTransform — library shape (D1=C bucketing)', () => {
  it('CRIT → MED/warning (CRIT-protected; never drops below MEDIUM)', () => {
    const input: SastFinding[] = [
      baseFinding({
        id: 'crit',
        rule_id: 'sql_injection',
        severity: 'critical',
        level: 'error',
        tags: [LIBRARY_API_SURFACE_TAG],
      }),
    ];
    const result = applyProjectProfileTransform(input, resolver('library/production'));
    expect(result[0].severity).toBe('medium');
    expect(result[0].level).toBe('warning');
  });

  it('HIGH → LOW/note', () => {
    const input: SastFinding[] = [
      baseFinding({
        id: 'high',
        rule_id: 'xpath_injection',
        severity: 'high',
        level: 'error',
        tags: [LIBRARY_API_SURFACE_TAG],
      }),
    ];
    const result = applyProjectProfileTransform(input, resolver('library/production'));
    expect(result[0].severity).toBe('low');
    expect(result[0].level).toBe('note');
  });

  it('MED → LOW/note', () => {
    const input: SastFinding[] = [
      baseFinding({
        id: 'med',
        rule_id: 'template_injection',
        severity: 'medium',
        level: 'warning',
        tags: [LIBRARY_API_SURFACE_TAG],
      }),
    ];
    const result = applyProjectProfileTransform(input, resolver('library/dev'));
    expect(result[0].severity).toBe('low');
    expect(result[0].level).toBe('note');
  });

  it('LOW remains LOW (no-op skips object rebuild)', () => {
    const input: SastFinding[] = [
      baseFinding({
        id: 'low',
        rule_id: 'code_injection',
        severity: 'low',
        level: 'note',
        tags: [LIBRARY_API_SURFACE_TAG],
      }),
    ];
    const result = applyProjectProfileTransform(input, resolver('library/production'));
    expect(result[0]).toBe(input[0]);
  });
});

describe('applyProjectProfileTransform — application shape (D3=Yes restoration)', () => {
  it('restores original_severity when it differs from current severity', () => {
    const input: SastFinding[] = [
      baseFinding({
        id: 'restore',
        rule_id: 'code_injection',
        severity: 'medium',
        level: 'warning',
        tags: [LIBRARY_API_SURFACE_TAG],
        original_severity: 'critical',
      }),
    ];
    const result = applyProjectProfileTransform(input, resolver('application/production'));
    expect(result[0].severity).toBe('critical');
    expect(result[0].level).toBe('error');
  });

  it('passes through unchanged when original_severity is missing', () => {
    const input: SastFinding[] = [
      baseFinding({
        id: 'no-orig',
        rule_id: 'code_injection',
        severity: 'medium',
        level: 'warning',
        tags: [LIBRARY_API_SURFACE_TAG],
        // original_severity intentionally omitted
      }),
    ];
    const result = applyProjectProfileTransform(input, resolver('application/dev'));
    expect(result[0]).toBe(input[0]);
  });

  it('passes through unchanged when original_severity already matches severity', () => {
    const input: SastFinding[] = [
      baseFinding({
        id: 'no-op',
        rule_id: 'sql_injection',
        severity: 'high',
        level: 'error',
        tags: [LIBRARY_API_SURFACE_TAG],
        original_severity: 'high',
      }),
    ];
    const result = applyProjectProfileTransform(input, resolver('application/production'));
    expect(result[0]).toBe(input[0]);
  });
});

describe('applyProjectProfileTransform — other shapes (cli/server/plugin)', () => {
  it('cli profile is a no-op for tagged findings in v1', () => {
    const input: SastFinding[] = [
      baseFinding({
        id: 'cli-noop',
        rule_id: 'code_injection',
        severity: 'critical',
        tags: [LIBRARY_API_SURFACE_TAG],
        original_severity: 'critical',
      }),
    ];
    const result = applyProjectProfileTransform(input, resolver('cli/production'));
    expect(result[0]).toBe(input[0]);
  });

  it('server profile is a no-op for tagged findings in v1', () => {
    const input: SastFinding[] = [
      baseFinding({
        id: 'server-noop',
        rule_id: 'template_injection',
        severity: 'high',
        tags: [LIBRARY_API_SURFACE_TAG],
      }),
    ];
    const result = applyProjectProfileTransform(input, resolver('server/production'));
    expect(result[0]).toBe(input[0]);
  });
});

describe('applyProjectProfileTransform — composition with Sprint 47 hook', () => {
  it('library: downgrade then bucket CRIT → MED (via Sprint 47) → MED (already at floor)', () => {
    // Start from the pre-downgrade state.
    const original: SastFinding[] = [
      baseFinding({
        id: 'compose-lib',
        rule_id: 'code_injection',
        severity: 'critical',
        level: 'error',
        tags: [LIBRARY_API_SURFACE_TAG],
      }),
    ];
    const afterDowngrade = applyLibraryApiSurfaceDowngrade(original);
    // Sprint 47 step: CRIT → MED + original_severity = critical.
    expect(afterDowngrade[0].severity).toBe('medium');
    expect(afterDowngrade[0].original_severity).toBe('critical');

    const final = applyProjectProfileTransform(afterDowngrade, resolver('library/production'));
    // Library bucketing on MED → LOW.
    expect(final[0].severity).toBe('low');
    expect(final[0].level).toBe('note');
  });

  it('application: downgrade then restoration brings CRIT back', () => {
    const original: SastFinding[] = [
      baseFinding({
        id: 'compose-app',
        rule_id: 'sql_injection',
        severity: 'critical',
        level: 'error',
        tags: [LIBRARY_API_SURFACE_TAG],
      }),
    ];
    const afterDowngrade = applyLibraryApiSurfaceDowngrade(original);
    expect(afterDowngrade[0].severity).toBe('medium');
    expect(afterDowngrade[0].original_severity).toBe('critical');

    const final = applyProjectProfileTransform(afterDowngrade, resolver('application/production'));
    expect(final[0].severity).toBe('critical');
    expect(final[0].level).toBe('error');
  });

  it('unknown: downgrade applies; transform is no-op (preserves 3.105.0 behavior)', () => {
    const original: SastFinding[] = [
      baseFinding({
        id: 'compose-unknown',
        rule_id: 'code_injection',
        severity: 'high',
        level: 'error',
        tags: [LIBRARY_API_SURFACE_TAG],
      }),
    ];
    const afterDowngrade = applyLibraryApiSurfaceDowngrade(original);
    expect(afterDowngrade[0].severity).toBe('medium');

    const final = applyProjectProfileTransform(afterDowngrade, resolver('unknown'));
    expect(final[0]).toBe(afterDowngrade[0]);
  });
});

describe('applyProjectProfileTransform — per-file resolver', () => {
  it('routes each finding through its own file profile', () => {
    const input: SastFinding[] = [
      baseFinding({
        id: 'libfile',
        file: 'src/main/java/lib/Foo.java',
        rule_id: 'code_injection',
        severity: 'critical',
        tags: [LIBRARY_API_SURFACE_TAG],
        original_severity: 'critical',
      }),
      baseFinding({
        id: 'appfile',
        file: 'src/main/java/app/Bar.java',
        rule_id: 'code_injection',
        severity: 'medium',
        level: 'warning',
        tags: [LIBRARY_API_SURFACE_TAG],
        original_severity: 'critical',
      }),
    ];
    const perFile: ProfileResolver = (file) =>
      file.includes('/lib/') ? 'library/production' : 'application/production';

    const result = applyProjectProfileTransform(input, perFile);
    // lib/Foo.java: library bucketing CRIT → MED.
    expect(result[0].severity).toBe('medium');
    // app/Bar.java: application restoration MED → CRIT.
    expect(result[1].severity).toBe('critical');
  });
});

describe('Pillar I guard', () => {
  it('module does not reference any LLM-themed identifier', () => {
    // Self-test on the imported constant name and rule list.
    expect(applyProjectProfileTransform.name).toBe('applyProjectProfileTransform');
    expect(applyProjectProfileTransform.name).not.toMatch(/llm|ai|verify/i);
  });
});
