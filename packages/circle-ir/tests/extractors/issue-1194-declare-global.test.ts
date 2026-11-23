import { beforeAll, describe, expect, it } from 'vitest';
import { analyze, extractTypes, initAnalyzer, parse } from '../../src/index.js';

beforeAll(async () => {
  await initAnalyzer();
});

const FIXTURE = `declare global {
  interface HostRequest {
    id: string;
  }
  function describeHost(): void;
}

export interface LocalFlag {
  ok: boolean;
}

export {};
`;

describe('cognium-dev#1194 — declare global block declarations', () => {
  it('emits HostRequest, describeHost, and keeps LocalFlag', async () => {
    const tree = await parse(FIXTURE, 'typescript');
    try {
      const types = extractTypes(tree, undefined, 'typescript');
    const host = types.find((t) => t.name === 'HostRequest');
    expect(host?.kind).toBe('interface');
    expect(host?.fields.some((f) => f.name === 'id' && f.type === 'string')).toBe(true);

    const local = types.find((t) => t.name === 'LocalFlag');
    expect(local?.kind).toBe('interface');
    expect(local?.fields.some((f) => f.name === 'ok')).toBe(true);

    const moduleType = types.find((t) => t.name === '<module>');
    const describeHost = moduleType?.methods.find((m) => m.name === 'describeHost');
    expect(describeHost?.return_type).toBe('void');
    } finally {
      tree.delete();
    }
  });

  it('analyze includes the same declarations', async () => {
    const ir = await analyze(FIXTURE, 'src/globals.d.ts', 'typescript');
    const names = new Set((ir.types ?? []).map((t) => t.name));
    expect(names.has('HostRequest')).toBe(true);
    expect(names.has('LocalFlag')).toBe(true);
    const moduleType = ir.types?.find((t) => t.name === '<module>');
    expect(moduleType?.methods.some((m) => m.name === 'describeHost')).toBe(true);
  });
});
