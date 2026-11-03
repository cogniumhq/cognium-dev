import { describe, it, expect } from 'bun:test';
import { UsageError, parseFormat, parseSeverity, parseWholeNumber } from './utils/options';

describe('parseFormat (#1006)', () => {
  const allowed = ['text', 'json', 'sarif'] as const;
  it('defaults when absent', () => expect(parseFormat(undefined, allowed, 'text')).toBe('text'));
  it('accepts known formats, case-insensitive', () => expect(parseFormat('JSON', allowed, 'text')).toBe('json'));
  it('refuses an unknown format instead of printing text', () => {
    expect(() => parseFormat('xml', allowed, 'text')).toThrow(UsageError);
  });
  it('refuses a missing value', () => expect(() => parseFormat(true, allowed, 'text')).toThrow(UsageError));
});

describe('parseSeverity (#1006)', () => {
  it('passes through absent', () => expect(parseSeverity(undefined)).toBeUndefined());
  it('accepts one level and lists', () => {
    expect(parseSeverity('High')).toBe('high');
    expect(parseSeverity('critical, high')).toBe('critical,high');
  });
  it('refuses unknown levels up front', () => {
    expect(() => parseSeverity('bogus')).toThrow(UsageError);
    expect(() => parseSeverity('high,nope')).toThrow(UsageError);
  });
  it('refuses a missing value', () => expect(() => parseSeverity(true)).toThrow(UsageError));
});

describe('parseWholeNumber (#1006, #1007)', () => {
  it('defaults when absent', () => expect(parseWholeNumber('threads', undefined, 4, 1)).toBe(4));
  it('accepts a whole number', () => expect(parseWholeNumber('threads', '8', 4, 1)).toBe(8));
  it('refuses --threads 0', () => expect(() => parseWholeNumber('threads', '0', 4, 1)).toThrow(UsageError));
  it('refuses non-numbers and negatives', () => {
    expect(() => parseWholeNumber('threads', 'x', 4, 1)).toThrow(UsageError);
    expect(() => parseWholeNumber('file-timeout-ms', '-5', 0, 0)).toThrow(UsageError);
    expect(() => parseWholeNumber('file-timeout-ms', true, 0, 0)).toThrow(UsageError);
  });
  it('allows 0 where the minimum is 0', () => expect(parseWholeNumber('file-timeout-ms', '0', 0, 0)).toBe(0));
});
