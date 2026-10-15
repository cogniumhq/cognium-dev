import { describe, it, expect } from 'vitest';
import { decodeJavaLiteral, javaReplaceCrLfCoverage } from '../../src/analysis/java-crlf-strip.js';

// Inputs are the raw text between the quotes of a Java literal (String.raw keeps the backslashes).
const both = { cr: true, lf: true };
const none = { cr: false, lf: false };

describe('decodeJavaLiteral', () => {
  it('decodes Java escapes once', () => {
    expect(decodeJavaLiteral(String.raw`\r\n`)).toBe('\r\n');
    expect(decodeJavaLiteral(String.raw`\\r`)).toBe('\\r');
    expect(decodeJavaLiteral(String.raw`\\\\r`)).toBe('\\\\r');
    expect(decodeJavaLiteral(String.raw`\u000a`)).toBe('\n');
    expect(decodeJavaLiteral(String.raw`\12`)).toBe('\n');
  });
});

describe('javaReplaceCrLfCoverage', () => {
  it('replace is a plain-text match of one character', () => {
    expect(javaReplaceCrLfCoverage('replace', String.raw`\n`)).toEqual({ cr: false, lf: true });
    expect(javaReplaceCrLfCoverage('replace', String.raw`\r`)).toEqual({ cr: true, lf: false });
    expect(javaReplaceCrLfCoverage('replace', String.raw`\r\n`)).toEqual(none);
    expect(javaReplaceCrLfCoverage('replace', String.raw`\\n`)).toEqual(none);
  });

  it.each([
    String.raw`[\r\n]+`,
    String.raw`[\\r\\n]`,
    String.raw`\r|\n`,
    String.raw`\\r|\\n`,
    String.raw`(?:\r\n|\r|\n)`,
    String.raw`(?:[\r\n])+`,
    String.raw`(?:\r|\n)*`,
    String.raw`[\r\n]{1,3}`,
    String.raw`[\r\n]{0,1}`,
  ])('replaceAll %s strips both', (p) => {
    expect(javaReplaceCrLfCoverage('replaceAll', p)).toEqual(both);
  });

  it.each([
    String.raw`[\\\\r\\\\n]`,
    String.raw`\\\\r|\\\\n`,
    String.raw`[^\r\n]`,
    String.raw`\r\n`,
    String.raw`\r\n\r\n`,
    String.raw`x\r\ny`,
    String.raw`\r\n|\n`,
    String.raw`[\r\n]{2}`,
    String.raw`[\r\n]{2,}`,
    String.raw`[\r\n]{0}`,
    String.raw`\r{2}|\n`,
    String.raw`(?:\r|\n){2}`,
    String.raw`\s+`,
  ])('replaceAll %s does not strip both', (p) => {
    const c = javaReplaceCrLfCoverage('replaceAll', p);
    expect(c.cr && c.lf).toBe(false);
  });
});
