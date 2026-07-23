/**
 * Tests for cognium-dev #143 — note-level finding coalescer.
 *
 * Direct unit tests over `coalesceNoteLevelFindings` — no analyzer
 * pipeline in the loop. Exercises the invariants documented in the
 * source module: level-gated (only pure-note groups fold), determin-
 * istic (lex sort on rule_id), additive (labels[] carries co-located
 * rule_ids), idempotent, mixed-level pass-through.
 */

import { describe, it, expect } from 'vitest';
import { coalesceNoteLevelFindings } from '../../src/analysis/note-coalescer.js';
import type { SastFinding } from '../../src/types/index.js';

function note(rule_id: string, file = 'Foo.java', line = 10): SastFinding {
  return {
    id: `${rule_id}-${file}-${line}`,
    pass: rule_id,
    category: 'maintainability',
    rule_id,
    severity: 'low',
    level: 'note',
    message: `${rule_id} at ${file}:${line}`,
    file,
    line,
  };
}

function warning(rule_id: string, file = 'Foo.java', line = 10): SastFinding {
  return {
    ...note(rule_id, file, line),
    severity: 'medium',
    level: 'warning',
  };
}

function error(rule_id: string, file = 'Foo.java', line = 10): SastFinding {
  return {
    ...note(rule_id, file, line),
    severity: 'critical',
    level: 'error',
  };
}

describe('#143 — coalesceNoteLevelFindings', () => {
  it('empty input passes through', () => {
    expect(coalesceNoteLevelFindings([])).toEqual([]);
  });

  it('single finding passes through unchanged', () => {
    const f = note('naming-convention');
    const out = coalesceNoteLevelFindings([f]);
    expect(out).toHaveLength(1);
    expect(out[0].labels).toBeUndefined();
  });

  it('coalesces the missing-public-doc + naming-convention pair (known collision #1)', () => {
    // Verbatim shape from the #143 reopen: every class declaration
    // triggers both rules at the same (file, line) — 2,740× on OWASP.
    const findings = [
      note('missing-public-doc'),
      note('naming-convention'),
    ];
    const out = coalesceNoteLevelFindings(findings);
    expect(out).toHaveLength(1);
    // Deterministic pick: lex-sorted rule_id → 'missing-public-doc' < 'naming-convention'.
    expect(out[0].rule_id).toBe('missing-public-doc');
    expect(out[0].labels).toEqual(['naming-convention']);
  });

  it('coalesces the security-headers pair (known collision #2)', () => {
    const findings = [
      note('missing-x-frame-options'),
      note('missing-csp-frame-ancestors'),
    ];
    const out = coalesceNoteLevelFindings(findings);
    expect(out).toHaveLength(1);
    expect(out[0].rule_id).toBe('missing-csp-frame-ancestors');
    expect(out[0].labels).toEqual(['missing-x-frame-options']);
  });

  it('coalesces unused-variable + variable-shadowing (known collision #3)', () => {
    const findings = [
      note('unused-variable'),
      note('variable-shadowing'),
    ];
    const out = coalesceNoteLevelFindings(findings);
    expect(out).toHaveLength(1);
    expect(out[0].rule_id).toBe('unused-variable');
    expect(out[0].labels).toEqual(['variable-shadowing']);
  });

  it('coalesces three co-located notes into one primary + two labels', () => {
    const findings = [
      note('naming-convention'),
      note('missing-public-doc'),
      note('missing-override'),
    ];
    const out = coalesceNoteLevelFindings(findings);
    expect(out).toHaveLength(1);
    expect(out[0].rule_id).toBe('missing-override');
    expect(out[0].labels).toEqual(['missing-public-doc', 'naming-convention']);
  });

  it('recall lock — mixed-level group passes through UN-coalesced', () => {
    // A warning at the same (file, line) as a note MUST NOT be
    // folded — higher-severity visibility is never diminished.
    const findings = [
      note('naming-convention'),
      warning('null-deref'),
    ];
    const out = coalesceNoteLevelFindings(findings);
    expect(out).toHaveLength(2);
    expect(out.map((f) => f.rule_id).sort()).toEqual(['naming-convention', 'null-deref']);
    expect(out.every((f) => f.labels === undefined)).toBe(true);
  });

  it('recall lock — error at same location: nothing coalesces', () => {
    const findings = [
      note('naming-convention'),
      note('missing-public-doc'),
      error('sql-injection'),
    ];
    const out = coalesceNoteLevelFindings(findings);
    expect(out).toHaveLength(3);
    expect(out.every((f) => f.labels === undefined)).toBe(true);
  });

  it('duplicate rule_id at same location does NOT coalesce (that is dedup, not multi-rule folding)', () => {
    // Two `naming-convention` at (Foo.java, 10) — the note-coalescer
    // is scoped to multi-rule folding only. Pass through untouched;
    // dedup is a separate concern handled by taint-matcher's sinkMap.
    const findings = [note('naming-convention'), note('naming-convention')];
    const out = coalesceNoteLevelFindings(findings);
    expect(out).toHaveLength(2);
    expect(out.every((f) => f.labels === undefined)).toBe(true);
  });

  it('coalesces PER (file, line) — different lines stay separate', () => {
    const findings = [
      note('naming-convention', 'A.java', 10),
      note('missing-public-doc', 'A.java', 10),
      note('naming-convention', 'A.java', 20),
      note('missing-public-doc', 'A.java', 20),
    ];
    const out = coalesceNoteLevelFindings(findings);
    expect(out).toHaveLength(2);
    expect(out.map((f) => f.line).sort()).toEqual([10, 20]);
    expect(out.every((f) => f.rule_id === 'missing-public-doc')).toBe(true);
    expect(out.every((f) => f.labels?.[0] === 'naming-convention')).toBe(true);
  });

  it('coalesces PER file — same line in different files stays separate', () => {
    const findings = [
      note('naming-convention', 'A.java', 10),
      note('missing-public-doc', 'A.java', 10),
      note('naming-convention', 'B.java', 10),
      note('missing-public-doc', 'B.java', 10),
    ];
    const out = coalesceNoteLevelFindings(findings);
    expect(out).toHaveLength(2);
    expect(out.map((f) => f.file).sort()).toEqual(['A.java', 'B.java']);
  });

  it('preserves interleaved insertion order of primary findings', () => {
    // Groups appear in the output in the same order their first
    // finding appeared in the input.
    const findings = [
      note('naming-convention', 'A.java', 10),
      warning('null-deref', 'B.java', 20),
      note('missing-public-doc', 'A.java', 10), // completes group A
      note('naming-convention', 'C.java', 30),
      note('missing-public-doc', 'C.java', 30), // completes group C
    ];
    const out = coalesceNoteLevelFindings(findings);
    expect(out).toHaveLength(3);
    expect(out.map((f) => f.file)).toEqual(['A.java', 'B.java', 'C.java']);
  });

  it('idempotent — coalescing twice yields the same result', () => {
    const findings = [
      note('naming-convention'),
      note('missing-public-doc'),
      note('missing-override'),
    ];
    const once = coalesceNoteLevelFindings(findings);
    const twice = coalesceNoteLevelFindings(once);
    expect(twice).toEqual(once);
  });

  it('idempotent when input already carries labels[] (labels are unioned, primary rule_id excluded)', () => {
    const pre: SastFinding = {
      ...note('missing-public-doc'),
      labels: ['naming-convention'],
    };
    const also = note('unused-variable');
    const out = coalesceNoteLevelFindings([pre, also]);
    expect(out).toHaveLength(1);
    expect(out[0].rule_id).toBe('missing-public-doc');
    // Union of pre-existing labels + new rule_id, dedup'd, primary excluded.
    expect((out[0].labels ?? []).sort()).toEqual([
      'naming-convention',
      'unused-variable',
    ]);
  });
});
