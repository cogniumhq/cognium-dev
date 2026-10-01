/**
 * The loader: what it accepts, what it refuses, and the promise that the
 * server comes up either way.
 */

import { describe, it, expect } from 'vitest';
import {
  loadModules,
  moduleSpecifiers,
  checkCircleIrRange,
  majorMinor,
  isToolModule,
  circleIrVersion,
  DEFAULT_MODULE_SPECIFIERS,
  ENV_MODULES,
} from '../src/modules.js';
import { fakeModule } from './fixtures/fake-module.js';

const notFound = (specifier: string): Promise<unknown> => {
  const err = new Error(`Cannot find package '${specifier}'`) as Error & { code: string };
  err.code = 'ERR_MODULE_NOT_FOUND';
  return Promise.reject(err);
};

describe('majorMinor', () => {
  it.each([
    ['4.9.29', '4.9'],
    ['4.9', '4.9'],
    ['10.0.0-rc.1', '10.0'],
    ['nonsense', null],
    ['', null],
    ['4', null],
  ])('reads %s as %s', (input, expected) => {
    expect(majorMinor(input)).toBe(expected);
  });
});

describe('checkCircleIrRange', () => {
  it('accepts the same minor', () => {
    expect(checkCircleIrRange('4.9', '4.9.29')).toEqual({ ok: true });
  });

  it('accepts a patch-level difference, which is the pin gate\'s job and not the loader\'s', () => {
    // Two patch releases of the same minor are compatible by the published
    // contract, so this check passes them on purpose. Catching a pin that
    // drifted is the release-time pin check's job, not the loader's.
    expect(checkCircleIrRange('4.9.27', '4.9.29')).toEqual({ ok: true });
  });

  it('refuses a different minor, naming both versions', () => {
    const result = checkCircleIrRange('4.8', '4.9.29');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain('4.8');
      expect(result.reason).toContain('4.9.29');
    }
  });

  it('refuses a different major', () => {
    expect(checkCircleIrRange('5.0', '4.9.29').ok).toBe(false);
  });

  it('refuses an unreadable declared range rather than assuming it is fine', () => {
    expect(checkCircleIrRange('latest', '4.9.29').ok).toBe(false);
    expect(checkCircleIrRange('4.9', 'unknown').ok).toBe(false);
  });
});

describe('moduleSpecifiers', () => {
  it('defaults to the one documented specifier', () => {
    expect(moduleSpecifiers({})).toEqual(DEFAULT_MODULE_SPECIFIERS);
  });

  it.each([['none'], [''], ['   ']])('loads nothing when the override is %o', (value) => {
    expect(moduleSpecifiers({ [ENV_MODULES]: value })).toEqual([]);
  });

  it('takes a comma-separated override', () => {
    expect(moduleSpecifiers({ [ENV_MODULES]: 'a/mcp, b/mcp ' })).toEqual(['a/mcp', 'b/mcp']);
  });
});

describe('isToolModule', () => {
  it('accepts a well-formed module', () => {
    expect(isToolModule(fakeModule())).toBe(true);
  });

  it.each([
    ['null', null],
    ['a string', 'circle-ir-ai/mcp'],
    ['an object with no register', { id: 'x', version: '1', licence: 'MIT', circleIrRange: '4.9' }],
    ['an object missing circleIrRange', { id: 'x', version: '1', licence: 'MIT', register: () => {} }],
  ])('rejects %s', (_label, value) => {
    expect(isToolModule(value)).toBe(false);
  });
});

describe('loadModules', () => {
  it('loads a module whose declared range matches the installed engine', async () => {
    const result = await loadModules({
      specifiers: ['fixture/mcp'],
      installedCircleIr: '4.9.29',
      importer: () => Promise.resolve({ default: fakeModule({ circleIrRange: '4.9' }) }),
    });
    expect(result.modules).toHaveLength(1);
    expect(result.modules[0]?.id).toBe('fixture/mcp');
    expect(result.refusals).toEqual([]);
  });

  it.each([['default'], ['toolModule'], ['module']])(
    'accepts the module on the %s export',
    async (key) => {
      const result = await loadModules({
        specifiers: ['fixture/mcp'],
        installedCircleIr: '4.9.29',
        importer: () => Promise.resolve({ [key]: fakeModule() }),
      });
      expect(result.modules).toHaveLength(1);
    },
  );

  it('treats "not installed" as the ordinary floor case, not a refusal', async () => {
    const result = await loadModules({
      specifiers: ['circle-ir-ai/mcp'],
      installedCircleIr: '4.9.29',
      importer: notFound,
    });
    expect(result.modules).toEqual([]);
    expect(result.refusals).toEqual([]);
  });

  it('refuses a module built against another circle-ir minor, with one clear line', async () => {
    const result = await loadModules({
      specifiers: ['fixture/mcp'],
      installedCircleIr: '4.9.29',
      importer: () => Promise.resolve({ default: fakeModule({ circleIrRange: '4.8' }) }),
    });
    expect(result.modules).toEqual([]);
    expect(result.refusals).toHaveLength(1);
    expect(result.refusals[0]?.reason).toContain('built against circle-ir 4.8');
    expect(result.refusals[0]?.reason).toContain('4.9.29 is installed');
  });

  it('refuses something that is not a tool module', async () => {
    const result = await loadModules({
      specifiers: ['fixture/mcp'],
      installedCircleIr: '4.9.29',
      importer: () => Promise.resolve({ hello: 'world' }),
    });
    expect(result.modules).toEqual([]);
    expect(result.refusals[0]?.reason).toBe('does not export a tool module');
  });

  it('refuses a module that throws on import, rather than propagating', async () => {
    const result = await loadModules({
      specifiers: ['fixture/mcp'],
      installedCircleIr: '4.9.29',
      importer: () => Promise.reject(new Error('boom')),
    });
    expect(result.modules).toEqual([]);
    expect(result.refusals[0]?.reason).toContain('boom');
  });

  it('keeps the good module when a second one is refused', async () => {
    const result = await loadModules({
      specifiers: ['good/mcp', 'bad/mcp'],
      installedCircleIr: '4.9.29',
      importer: (s) =>
        Promise.resolve({
          default: fakeModule({ id: s, circleIrRange: s === 'good/mcp' ? '4.9' : '3.0' }),
        }),
    });
    expect(result.modules.map((m) => m.id)).toEqual(['good/mcp']);
    expect(result.refusals.map((r) => r.specifier)).toEqual(['bad/mcp']);
  });

  it('loads nothing, and refuses nothing, when there are no specifiers', async () => {
    const result = await loadModules({ specifiers: [], installedCircleIr: '4.9.29' });
    expect(result).toEqual({ modules: [], refusals: [] });
  });
});

describe('circleIrVersion', () => {
  it('reads the installed engine version from its own manifest', () => {
    expect(circleIrVersion()).toMatch(/^\d+\.\d+\.\d+/);
  });
});
