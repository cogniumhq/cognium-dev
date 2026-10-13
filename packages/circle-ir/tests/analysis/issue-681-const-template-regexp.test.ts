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
