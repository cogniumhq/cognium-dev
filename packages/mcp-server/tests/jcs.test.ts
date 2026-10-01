/**
 * RFC 8785 canonicalisation.
 *
 * The licence signature covers the canonical form, so a bug here is a bug in
 * every signature. The cases below are the ones the RFC calls out: key order
 * by UTF-16 code unit, no insignificant whitespace, ECMAScript number
 * formatting, and minimal string escaping.
 */

import { describe, it, expect } from 'vitest';
import { canonicalise, canonicalBytes, JcsError } from '../src/jcs.js';

describe('canonicalise', () => {
  it('sorts object keys by UTF-16 code unit, not by locale', () => {
    expect(canonicalise({ b: 1, a: 2, C: 3, A: 4 })).toBe('{"A":4,"C":3,"a":2,"b":1}');
  });

  it('is the RFC 8785 §3.2.3 ordering for mixed scripts', () => {
    // The RFC's own example set. Ordering is by code unit, which puts the
    // control character first and the astral-plane emoji last.
    const input = {
      '€': 'Euro Sign',
      '\r': 'Carriage Return',
      '\u000a': 'Newline',
      '1': 'One',
      '\u0080': 'Control\u007f',
      '😂': 'Smiley',
      'ö': 'Latin Small Letter O With Diaeresis',
      '➕': 'Heavy Plus Sign',
      'A': 'A',
    };
    const keys = [...canonicalise(input).matchAll(/"((?:[^"\\]|\\.)*)":/g)].map((m) => m[1]);
    expect(keys).toEqual([
      '\\n',
      '\\r',
      '1',
      'A',
      '\u0080',
      'ö',
      '€',
      '➕',
      '😂',
    ]);
  });

  it('emits no insignificant whitespace', () => {
    expect(canonicalise({ a: [1, 2, { b: 3 }] })).toBe('{"a":[1,2,{"b":3}]}');
  });

  it('preserves array order, which is significant', () => {
    expect(canonicalise(['b', 'a', 'c'])).toBe('["b","a","c"]');
  });

  it.each([
    [1, '1'],
    [1.5, '1.5'],
    [0, '0'],
    [-0, '0'],
    [1e21, '1e+21'],
    [333333333.3333333, '333333333.3333333'],
  ])('formats the number %p as %s', (input, expected) => {
    expect(canonicalise(input)).toBe(expected);
  });

  it('escapes only what the RFC requires, leaving other code points literal', () => {
    // Quote, backslash and the C0 controls are escaped — the short forms
    // where they exist. Non-ASCII stays as itself.
    expect(canonicalise('a"b\\c\nd\te\u0001fé')).toBe('"a\\"b\\\\c\\nd\\te\\u0001fé"');
  });

  it('escapes a lone surrogate rather than emitting invalid UTF-8', () => {
    expect(canonicalise('\ud800')).toBe('"\\ud800"');
  });

  it('handles the literals and nesting', () => {
    expect(canonicalise(null)).toBe('null');
    expect(canonicalise(true)).toBe('true');
    expect(canonicalise(false)).toBe('false');
    expect(canonicalise({ a: { b: { c: [] } } })).toBe('{"a":{"b":{"c":[]}}}');
  });

  it('treats an absent field and an undefined one alike', () => {
    expect(canonicalise({ a: 1, b: undefined })).toBe(canonicalise({ a: 1 }));
  });

  it('refuses what JSON cannot represent, instead of emitting something wrong', () => {
    expect(() => canonicalise(Number.NaN)).toThrow(JcsError);
    expect(() => canonicalise(Number.POSITIVE_INFINITY)).toThrow(JcsError);
    expect(() => canonicalise(() => undefined)).toThrow(JcsError);
    expect(() => canonicalise(10n)).toThrow(JcsError);
  });

  it('gives one byte sequence for two spellings of the same value', () => {
    const a = canonicalBytes({ org: 'x', tier: 'team' });
    const b = canonicalBytes({ tier: 'team', org: 'x' });
    expect(a.equals(b)).toBe(true);
  });
});
