/**
 * cognium-dev#1067 — the public OSV export carries an `affected[]` entry with
 * no `package` (EEF-CVE-2026-56812: its third entry has only a GIT range).
 * Building the index and matching threw on it; the entry is now skipped and
 * counted, and the record's npm entry still matches.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { parseOsvRecord, buildAdvisoryIndex, matchAdvisories, type OsvRecord } from '../../src/analysis/advisories.js';
import type { Dependency } from '../../src/analysis/sbom.js';

const FIXTURE = fileURLToPath(new URL('../fixtures/osv-1067/EEF-CVE-2026-56812.json', import.meta.url));
const record = parseOsvRecord(readFileSync(FIXTURE, 'utf-8')) as OsvRecord;
const npm = (version: string): Dependency => ({ name: 'phoenix', version, ecosystem: 'npm', scope: 'required', purl: `pkg:npm/phoenix@${version}` });

describe('#1067 an OSV affected entry without a package', () => {
  it('the fixture is the real shape: one of three entries has no package', () => {
    expect(record.affected).toHaveLength(3);
    expect(record.affected!.filter(a => !a.package)).toHaveLength(1);
  });

  it('buildAdvisoryIndex skips and counts it (npm and Maven indexes)', () => {
    const idx = buildAdvisoryIndex([record], 'npm');
    expect(idx.records).toBe(1);
    expect(idx.affectedWithoutPackage).toBe(1);
    expect([...idx.byPackage.keys()]).toEqual(['phoenix']);
    expect(() => buildAdvisoryIndex([record], 'Maven')).not.toThrow();
  });

  it('matchAdvisories still matches the npm entry and fixes', () => {
    const idx = buildAdvisoryIndex([record], 'npm');
    const m = matchAdvisories([npm('1.7.0'), npm('1.8.9')], idx);
    expect(m.map(x => `${x.dependency.version} ${x.advisory.id}`)).toEqual(['1.7.0 EEF-CVE-2026-56812']);
    expect(m[0]!.fixedIn).toContain('1.7.24');
  });
});
