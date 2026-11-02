/**
 * cognium-dev#992 — JS/TS: a method call on a receiver of unknown type
 * (`signer.getAddress()`, an ethers Signer) is not a module-level function of
 * the same name in another project file (juice-shop routes/address.ts
 * `getAddress`, which reads req.body). The try defs exposed this as two
 * log_injection FPs in juice-shop's faucet component.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const route = `import { Request, Response } from 'express'
export function getAddress () {
  return async (req: Request, res: Response) => {
    const id = req.body.UserId
    res.status(200).json({ id })
  }
}`;
const component = (call: string, extraImport = '') => `import { ethers } from 'ethers'
${extraImport}
export class Faucet {
  async load (signer: any) {
    try {
      const userAddress = await ${call}
      console.log(userAddress)
    } catch (e) {
      console.log('x')
    }
  }
}`;

const paths = async (code: string) => {
  const r = await analyzeProject([
    { code: route, filePath: 'routes/address.ts', language: 'typescript' },
    { code, filePath: 'app/faucet.ts', language: 'typescript' },
  ]);
  return r.taint_paths.filter(p => p.source.file === 'routes/address.ts' && p.sink.file === 'app/faucet.ts');
};

describe('#992 JS/TS receiver calls do not resolve by name to module functions', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('signer.getAddress() is not routes/address.ts getAddress', async () => {
    expect(await paths(component('signer.getAddress()'))).toHaveLength(0);
  });
});
