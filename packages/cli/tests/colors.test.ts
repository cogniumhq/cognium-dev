import { afterEach, describe, expect, test } from 'bun:test';
import { colorEnabled, colors } from '../src/utils/colors.js';
import { spinner } from '../src/utils/spinner.js';

const ORIGINAL_NO_COLOR = process.env.NO_COLOR;
const ORIGINAL_TERM = process.env.TERM;

afterEach(() => {
  if (ORIGINAL_NO_COLOR === undefined) {
    delete process.env.NO_COLOR;
  } else {
    process.env.NO_COLOR = ORIGINAL_NO_COLOR;
  }
  if (ORIGINAL_TERM === undefined) {
    delete process.env.TERM;
  } else {
    process.env.TERM = ORIGINAL_TERM;
  }
});

describe('NO_COLOR / TERM=dumb (cognium-dev#441)', () => {
  test('colorEnabled is false when NO_COLOR is set', () => {
    process.env.NO_COLOR = '1';
    delete process.env.TERM;
    expect(colorEnabled()).toBe(false);
  });

  test('empty NO_COLOR does not disable color (no-color.org)', () => {
    process.env.NO_COLOR = '';
    process.env.TERM = 'xterm';
    expect(colorEnabled()).toBe(true);
  });

  test('colorEnabled is false when TERM=dumb', () => {
    delete process.env.NO_COLOR;
    process.env.TERM = 'dumb';
    expect(colorEnabled()).toBe(false);
  });

  test('colors.red wraps with ANSI when color is enabled', () => {
    delete process.env.NO_COLOR;
    process.env.TERM = 'xterm';
    const out = colors.red('hi');
    expect(out).toContain('\x1b[');
    expect(out).toContain('hi');
  });

  test('colors.red is a no-op when NO_COLOR is set', () => {
    process.env.NO_COLOR = '1';
    expect(colors.red('hi')).toBe('hi');
    expect(colors.green('ok')).toBe('ok');
    expect(colors.bold('x')).toBe('x');
  });

  test('spinner succeed/fail/warn omit ANSI when NO_COLOR is set', () => {
    process.env.NO_COLOR = '1';
    const lines: string[] = [];
    const original = console.error;
    console.error = (...args: unknown[]) => {
      lines.push(args.map(String).join(' '));
    };
    try {
      const s = spinner('working');
      s.succeed('done');
      s.fail('broke');
      s.warn('careful');
    } finally {
      console.error = original;
    }
    expect(lines.join('\n')).not.toContain('\x1b[');
    expect(lines.some(l => l.includes('done'))).toBe(true);
    expect(lines.some(l => l.includes('broke'))).toBe(true);
    expect(lines.some(l => l.includes('careful'))).toBe(true);
  });
});
