/**
 * cognium-dev#681 — `new RegExp(`…${CONST}…`)` whose interpolations are all
 * module `const` string literals has a constant pattern; a tainted subject
 * alone is not ReDoS.
 *
 * SAST regression fixture — the "fires" handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const masker = (decl: string, pattern: string) => `
const fs = require('fs');
${decl}

function maskCredentialLines(body) {
  const rx = new RegExp(${pattern}, 'gm');
  return body.replace(rx, '$1***');
}

function main(raw = process.env.CRED_DUMP) {
  fs.writeFileSync('masked.txt', maskCredentialLines(raw));
}
module.exports = { main };
`;

async function redos(code: string) {
  const r = await analyze(code, 'masker.js', 'javascript');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'redos');
}

describe('cognium-dev#681 — constant template RegExp pattern', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('pattern built only from a const string literal is clean', async () => {
    const code = masker("const CRED_KEY = '(?:apikey|passwd)';", '`^(\\\\s*${CRED_KEY}\\\\s*=\\\\s*).*$`');
    expect(await redos(code)).toHaveLength(0);
  });

  it('still fires: constant pattern with a nested quantifier on a tainted subject', async () => {
    const code = masker("const CRED_KEY = '(\\\\w+)+';", '`^${CRED_KEY}=`');
    expect((await redos(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: whitespace inside ${ } with a nested-quantifier constant', async () => {
    const code = masker("const CRED_KEY = '(\\\\w+)+';", '`^${ CRED_KEY }`');
    expect((await redos(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('whitespace inside ${ } with a safe constant is still clean', async () => {
    const code = masker("const CRED_KEY = '(?:apikey|passwd)';", '`^(\\\\s*${ CRED_KEY }\\\\s*=\\\\s*).*$`');
    expect(await redos(code)).toHaveLength(0);
  });

  it('const string without a semicolon (ASI) is still clean', async () => {
    const code = masker("const CRED_KEY = '(?:apikey|passwd)'", '`^(\\\\s*${CRED_KEY}\\\\s*=\\\\s*).*$`');
    expect(await redos(code)).toHaveLength(0);
  });

  const tpl = '`^${CRED_KEY}=`';
  const continuations: Array<[string, string]> = [
    ['literal split across lines with + (nested quantifier)', "const CRED_KEY = '('\n  + '\\\\w+)+';"],
    ['literal + tainted value on the next line', "const CRED_KEY = '(?:apikey|passwd)'\n  + req.query.suffix;"],
    ['literal + tainted value on the same line', "const CRED_KEY = '(?:apikey|passwd)' + req.query.suffix;"],
    ['literal.concat(...) on the next line', "const CRED_KEY = '(?:apikey|passwd)'\n  .concat(process.env.SUFFIX);"],
    ['literal then `in` on the next line', "const CRED_KEY = '(?:apikey|passwd)'\n  in flags || req.query.suffix;"],
    ['literal then `as string` + tainted on the next line', "const CRED_KEY = '(?:apikey|passwd)'\n  as string + req.query.suffix;"],
    ['literal then `instanceof` on the next line', "const CRED_KEY = '(?:apikey|passwd)'\n  instanceof String || req.query.suffix;"],
    ['\\x28 escape producing a nested quantifier', "const CRED_KEY = '\\x28\\\\w+)+';"],
    ['\\u0028 escape producing a nested quantifier', "const CRED_KEY = '\\u0028\\\\w+)+';"],
  ];
  for (const [label, decl] of continuations) {
    it(`still fires: ${label}`, async () => {
      expect((await redos(masker(decl, tpl))).length).toBeGreaterThanOrEqual(1);
    });
  }

  it('still fires: attacker-controlled pattern in an express handler', async () => {
    const code = `
const express = require('express');
const app = express();
app.get('/find', function (req, res) {
  const userPattern = req.query.pattern;
  const rx = new RegExp(userPattern);
  res.send('ok');
});
`;
    const r = await analyze(code, 'find.js', 'javascript');
    expect((r.taint.flows ?? []).filter((f) => f.sink_type === 'redos').length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: tainted value interpolated into the template', async () => {
    const code = `
const express = require('express');
const app = express();
const CRED_KEY = '(?:apikey|passwd)';
app.get('/find', function (req, res) {
  const suffix = req.query.suffix;
  const rx = new RegExp(\`^\${CRED_KEY}\${suffix}\`);
  res.send('ok');
});
`;
    const r = await analyze(code, 'find.js', 'javascript');
    expect((r.taint.flows ?? []).filter((f) => f.sink_type === 'redos').length).toBeGreaterThanOrEqual(1);
  });
});
