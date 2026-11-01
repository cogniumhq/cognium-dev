/**
 * cognium-dev#1049 — destructured Express request parameters are sources.
 * OWASP Juice Shop routes/redirect.ts: `({ query }: Request, res) => { const
 * toUrl = query.to; res.redirect(toUrl) }` had no source.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flows = async (code: string, type: string) =>
  (await analyze(code, 'r.ts', 'typescript')).taint.flows.filter(f => f.sink_type === type);

describe('#1049 destructured Express request parameters', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('({ query }: Request) → query.to → res.redirect is an open redirect', async () => {
    const code = `import { type Request, type Response, type NextFunction } from 'express'
export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string
    res.redirect(toUrl)
  }
}`;
    expect((await flows(code, 'open_redirect')).length).toBeGreaterThan(0);
  });

  it('a renamed field ({ body: b }: Request) is a source too', async () => {
    const code = `import { exec } from 'child_process'
import type { Request, Response } from 'express'
export function run () {
  return ({ body: b }: Request, res: Response) => {
    const cmd = b.cmd
    exec(cmd)
    res.send('ok')
  }
}`;
    expect((await flows(code, 'command_injection')).length).toBeGreaterThan(0);
  });

  it('an object pattern not typed Request is not a source', async () => {
    const code = `export function f ({ query }: { query: { to: string } }, res: any) {
  const toUrl = query.to
  res.redirect(toUrl)
}`;
    expect(await flows(code, 'open_redirect')).toHaveLength(0);
  });
});
