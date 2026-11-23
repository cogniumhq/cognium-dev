import { beforeAll, describe, expect, it } from 'vitest';
import { analyze, initAnalyzer, parse } from '../../src/index.js';
import { deriveStableIds } from '../../src/stable-ids/index.js';

beforeAll(async () => {
  await initAnalyzer();
});

const FIXTURE = `export class ProcessPromise {}
export class ProcessOutput {}
export interface Options {
  sync?: boolean
}

export interface Shell<
  S = false,
  R = S extends true ? ProcessOutput : ProcessPromise,
> {
  (pieces: TemplateStringsArray, ...args: any[]): R
  <O extends Partial<Options> = Partial<Options>, R = O extends { sync: true } ? Shell<true> : Shell>(opts: O): R
}

export function describeShell(_shell: Shell): void {}
`;

describe('cognium-dev#1193 — generic call signature with conditional-type default', () => {
  it('parses without a declaration-hiding error and emits expected types', async () => {
    const tree = await parse(FIXTURE, 'typescript');
    try {
      const ids = await deriveStableIds(FIXTURE, 'src/shell.ts', 'typescript');
      expect(ids.partial).toBe(false);

      const names = new Set(ids.decls.map((d) => d.name));
      expect(names.has('ProcessPromise')).toBe(true);
      expect(names.has('ProcessOutput')).toBe(true);
      expect(names.has('Options')).toBe(true);
      expect(names.has('Shell')).toBe(true);
      expect(names.has('describeShell')).toBe(true);
    } finally {
      tree.delete();
    }
  });

  it('analyze emits ProcessPromise, ProcessOutput, Options, Shell, and describeShell', async () => {
    const ir = await analyze(FIXTURE, 'src/shell.ts', 'typescript');
    const typeNames = new Set((ir.types ?? []).map((t) => t.name));
    expect(typeNames.has('ProcessPromise')).toBe(true);
    expect(typeNames.has('ProcessOutput')).toBe(true);
    expect(typeNames.has('Options')).toBe(true);
    expect(typeNames.has('Shell')).toBe(true);

    const moduleType = ir.types?.find((t) => t.name === '<module>');
    const methodNames = new Set(moduleType?.methods.map((m) => m.name) ?? []);
    expect(methodNames.has('describeShell')).toBe(true);
  });
});
