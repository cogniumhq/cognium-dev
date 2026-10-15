/**
 * cognium-dev#680 — fetch(`${API_BASE}/path/${tainted}`) where API_BASE is a
 * `const` literal origin is not SSRF: the authority is constant and closed by
 * `/` before anything tainted. Stage 15i credited only an inline literal host.
 *
 * SAST regression fixture — the "fires" handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const file = (decl: string, call: string) => `
import express from 'express';
${decl}
const app = express();
app.get('/r', async (req, res) => {
  const r = await fetch(${call});
  res.json(await r.json());
});
`;

async function ssrf(code: string) {
  const r = await analyze(code, 'client.ts', 'typescript');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'ssrf');
}

describe('cognium-dev#680 — const literal origin in a fetch template', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('const origin closed by / is clean', async () => {
    expect(await ssrf(file("const REGISTRY_ORIGIN = 'https://registry.example.org';", '`${REGISTRY_ORIGIN}/pkgs/${req.query.owner}`'))).toHaveLength(0);
  });

  it('typed const origin with a base path is clean', async () => {
    expect(await ssrf(file("const REGISTRY_ORIGIN: string = 'https://registry.example.org/v2';", '`${REGISTRY_ORIGIN}/pkgs/${req.query.owner}`'))).toHaveLength(0);
  });

  it('const origin without a semicolon (ASI) is clean', async () => {
    expect(await ssrf(file("const REGISTRY_ORIGIN = 'https://registry.example.org'", '`${REGISTRY_ORIGIN}/pkgs/${req.query.owner}`'))).toHaveLength(0);
  });

  it('const origin followed by a trailing comment and no semicolon is clean', async () => {
    expect(await ssrf(file("const REGISTRY_ORIGIN = 'https://registry.example.org' // registry\n", '`${REGISTRY_ORIGIN}/pkgs/${req.query.owner}`'))).toHaveLength(0);
  });

  it('const origin with `as const` is clean', async () => {
    expect(await ssrf(file("const REGISTRY_ORIGIN = 'https://registry.example.org' as const;", '`${REGISTRY_ORIGIN}/pkgs/${req.query.owner}`'))).toHaveLength(0);
  });

  const T = '`${REGISTRY_ORIGIN}/pkgs/${req.query.owner}`';
  const fires: Array<[string, string, string]> = [
    ['literal + process.env on the same line', "const REGISTRY_ORIGIN = 'https://registry.example.org' + process.env.HOST;", T],
    ['literal + tainted value on the same line', "const REGISTRY_ORIGIN = 'https://registry.example.org' + req.query.host;", T],
    ['literal.concat(tainted)', "const REGISTRY_ORIGIN = 'https://registry.example.org'.concat(req.query.host);", T],
    ['literal then + on the next line', "const REGISTRY_ORIGIN = 'https://registry.example.org'\n  + process.env.HOST;", T],
    ['literal then .concat on the next line', "const REGISTRY_ORIGIN = 'https://registry.example.org'\n  .concat(req.query.host);", T],
    ['literal in a conditional', "const REGISTRY_ORIGIN = 'https://registry.example.org' || req.query.host;", T],
    ['no / closing the authority', "const REGISTRY_ORIGIN = 'https://registry.example.org';", '`${REGISTRY_ORIGIN}${req.query.p}`'],
    ['string concat without a closing /', "const REGISTRY_ORIGIN = 'https://registry.example.org';", 'REGISTRY_ORIGIN + req.query.p'],
    ['base from process.env', 'const REGISTRY_ORIGIN = process.env.REGISTRY_ORIGIN;', '`${REGISTRY_ORIGIN}/pkgs/${req.query.owner}`'],
    ['let base', "let REGISTRY_ORIGIN = 'https://registry.example.org';", '`${REGISTRY_ORIGIN}/pkgs/${req.query.owner}`'],
    ['const that is not a literal origin', "const REGISTRY_ORIGIN = 'registry.example.org';", '`${REGISTRY_ORIGIN}/pkgs/${req.query.owner}`'],
    ['interpolated host', "const REGISTRY_ORIGIN = 'https://registry.example.org';", '`https://${req.query.host}/pkgs`'],
  ];
  for (const [label, decl, call] of fires) {
    it(`still fires: ${label}`, async () => {
      expect((await ssrf(file(decl, call))).length).toBeGreaterThanOrEqual(1);
    });
  }
});
