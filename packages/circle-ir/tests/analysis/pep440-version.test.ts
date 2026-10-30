import { describe, it, expect } from 'vitest';
import { comparePep440, parsePep440, normalizePypiName } from '../../src/analysis/pep440-version.js';

describe('parsePep440', () => {
  it('normalises the spellings PEP 440 allows', () => {
    expect(parsePep440('1.0.0')).toMatchObject({ epoch: 0, release: [1], pre: null, post: null, dev: null, local: [] });
    expect(parsePep440('v1.0-ALPHA.2')).toMatchObject({ pre: ['a', 2] });
    expect(parsePep440('1.0c1')).toMatchObject({ pre: ['rc', 1] });
    expect(parsePep440('1.0preview')).toMatchObject({ pre: ['rc', 0] });
    expect(parsePep440('1.0-1')).toMatchObject({ post: 1 });
    expect(parsePep440('1.0.rev3')).toMatchObject({ post: 3 });
    expect(parsePep440('1.0.post')).toMatchObject({ post: 0 });
    expect(parsePep440('1.0dev')).toMatchObject({ dev: 0 });
    expect(parsePep440('2!1.0+Ubuntu.1')).toMatchObject({ epoch: 2, local: ['ubuntu', 1] });
  });
  it('rejects specifiers and non-versions', () => {
    for (const v of ['>=1.0', '==1.0', '~=2.2', 'latest', '1.0.x', '', 'git+https://x/y']) expect(parsePep440(v)).toBeNull();
  });
});

describe('comparePep440', () => {
  // PEP 440's own ordering example ("Summary of permitted suffixes and relative ordering").
  const ORDERED = [
    '1.dev0',
    '1.0.dev456',
    '1.0a1',
    '1.0a2.dev456',
    '1.0a12.dev456',
    '1.0a12',
    '1.0b1.dev456',
    '1.0b2',
    '1.0b2.post345.dev456',
    '1.0b2.post345',
    '1.0rc1.dev456',
    '1.0rc1',
    '1.0',
    '1.0+abc.5',
    '1.0+abc.7',
    '1.0+5',
    '1.0.post456.dev34',
    '1.0.post456',
    '1.0.15',
    '1.1.dev1',
  ];
  it('orders the PEP 440 example', () => {
    for (let i = 0; i < ORDERED.length; i++) {
      for (let j = 0; j < ORDERED.length; j++) {
        expect([ORDERED[i], ORDERED[j], Math.sign(comparePep440(ORDERED[i], ORDERED[j]))]).toEqual([ORDERED[i], ORDERED[j], Math.sign(i - j)]);
      }
    }
  });
  it('ignores trailing zeros, case and spelling', () => {
    expect(comparePep440('1.0', '1.0.0')).toBe(0);
    expect(comparePep440('1.0RC1', '1.0c1')).toBe(0);
    expect(comparePep440('1.0-1', '1.0.post1')).toBe(0);
    expect(comparePep440('2.10', '2.9')).toBeGreaterThan(0);
  });
  it('puts the epoch first and invalid strings before valid ones', () => {
    expect(comparePep440('1!0.1', '99.0')).toBeGreaterThan(0);
    expect(comparePep440('latest', '0.0.1')).toBeLessThan(0);
    expect(comparePep440('0.0.1', 'latest')).toBeGreaterThan(0);
    expect(comparePep440('a', 'b')).toBeLessThan(0);
    expect(comparePep440('b', 'b')).toBe(0);
  });
  it('orders local segments', () => {
    expect(comparePep440('1.0+1', '1.0+1.1')).toBeLessThan(0);
    expect(comparePep440('1.0+abc', '1.0+abd')).toBeLessThan(0);
    expect(comparePep440('1.0+abc', '1.0+abc')).toBe(0);
    expect(comparePep440('1.0+2', '1.0+10')).toBeLessThan(0);
  });
});

describe('normalizePypiName', () => {
  it('applies PEP 503', () => {
    expect(normalizePypiName('Django')).toBe('django');
    expect(normalizePypiName('zope.interface')).toBe('zope-interface');
    expect(normalizePypiName('Foo__Bar-.baz')).toBe('foo-bar-baz');
  });
});
