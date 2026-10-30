import { describe, it, expect } from 'vitest';
import { licenseFromPackageJson, applyLicenses, type Dependency } from '../../src/analysis/sbom.js';

const d = (name: string, version: string, license?: string): Dependency => ({
  name, version, ecosystem: 'npm', scope: 'required', purl: `pkg:npm/${name}@${version}`, ...(license ? { license } : {}),
});

describe('licenseFromPackageJson', () => {
  it('reads a license string', () => {
    expect(licenseFromPackageJson(JSON.stringify({ license: 'MIT' }))).toBe('MIT');
  });
  it('reads the legacy { type } object', () => {
    expect(licenseFromPackageJson(JSON.stringify({ license: { type: 'ISC' } }))).toBe('ISC');
  });
  it('joins the legacy licenses array with OR', () => {
    expect(licenseFromPackageJson(JSON.stringify({ licenses: [{ type: 'MIT' }, { type: 'Apache-2.0' }] }))).toBe('(MIT OR Apache-2.0)');
    expect(licenseFromPackageJson(JSON.stringify({ licenses: [{ type: 'BSD-3-Clause' }] }))).toBe('BSD-3-Clause');
  });
  it('is undefined for none, blanks or malformed text', () => {
    expect(licenseFromPackageJson('{}')).toBeUndefined();
    expect(licenseFromPackageJson(JSON.stringify({ license: '  ' }))).toBeUndefined();
    expect(licenseFromPackageJson('not json')).toBeUndefined();
    expect(licenseFromPackageJson('null')).toBeUndefined();
  });
});

describe('applyLicenses', () => {
  it('prefers name@version, falls back to name, never overwrites', () => {
    const out = applyLicenses(
      [d('a', '1.0.0'), d('b', '2.0.0'), d('c', '3.0.0', 'MIT'), d('e', '1.0.0')],
      { 'a@1.0.0': 'Apache-2.0', a: 'GPL-3.0', b: 'ISC', c: 'GPL-3.0' },
    );
    expect(out.map((x) => x.license)).toEqual(['Apache-2.0', 'ISC', 'MIT', undefined]);
  });
  it('returns new objects and leaves the input untouched', () => {
    const input = [d('a', '1.0.0')];
    const out = applyLicenses(input, { a: 'MIT' });
    expect(input[0].license).toBeUndefined();
    expect(out[0]).not.toBe(input[0]);
  });
});
