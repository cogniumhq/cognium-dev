/**
 * Maven version ordering — the cases Maven's version-order specification
 * lists, plus the qualifier shapes common in advisory ranges.
 */

import { describe, it, expect } from 'vitest';
import { compareMavenVersions as cmp, canonicalMavenVersion } from '../../src/analysis/maven-version.js';

const lt = (a: string, b: string): void => {
  expect(cmp(a, b), `${a} < ${b}`).toBe(-1);
  expect(cmp(b, a), `${b} > ${a}`).toBe(1);
};
const eq = (a: string, b: string): void => expect(cmp(a, b), `${a} = ${b}`).toBe(0);

describe('compareMavenVersions', () => {
  it('orders the specification examples', () => {
    lt('1', '1.1');
    lt('1-snapshot', '1');
    lt('1', '1-sp');
    lt('1-foo2', '1-foo10');
    eq('1.foo', '1-foo');
    lt('1-foo', '1-1');
    lt('1-1', '1.1');
    eq('1.ga', '1');
    eq('1-ga', '1-0');
    eq('1.0', '1');
    lt('1-ga', '1-sp');
    lt('1-ga.1', '1-sp.1');
    eq('1-a1', '1-alpha-1');
  });

  it('orders the known qualifiers', () => {
    const order = ['1-alpha1', '1-beta1', '1-milestone1', '1-rc1', '1-snapshot', '1', '1-sp1'];
    for (let i = 1; i < order.length; i++) lt(order[i - 1], order[i]);
    eq('1.0-cr1', '1.0-rc1');
    eq('1.0-final', '1');
    eq('1.0.0.RELEASE', '1');
    eq('2.0.0.RC1', '2.0.0-RC1');
    lt('1-rc1', '1-zzz'); // unknown qualifiers sort after known ones
    lt('31.1-android', '31.1-jre'); // ... lexically among themselves
  });

  it('orders the shapes advisory ranges use', () => {
    lt('2.14.1', '2.15.0');
    lt('2.15.0-rc1', '2.15.0');
    lt('2.0-beta9', '2.0');
    lt('2.0-beta9', '2.3.1');
    lt('2.9.10.8', '2.10.0');
    lt('4.1.99.Final', '4.1.100.Final');
    eq('4.1.108.Final', '4.1.108');
    lt('1.33', '2.0');
    lt('31.0-jre', '31.1-jre');
    lt('1.0-SNAPSHOT', '1.0');
    lt('99999999999999999999', '100000000000000000000'); // beyond 64-bit
  });

  it('is case-insensitive and trims trailing null items', () => {
    eq('1.0-RC1', '1.0-rc1');
    expect(canonicalMavenVersion('1.0.0')).toBe('1');
    expect(canonicalMavenVersion('4.1.100.Final')).toBe('4.1.100');
    expect(canonicalMavenVersion('1rc2')).toBe('1-rc-2');
  });
});
