/**
 * cognium-dev #315 (from cognium-ai#198) — `blocking-main-thread` cell.
 *
 * The pass built its handler line-ranges exclusively from
 * `graph.ir.types[].methods`, so it only ever saw handlers that are methods:
 * a NestJS `@Get()` class method, or a named `function handler(req, res)`
 * (top-level functions land in the synthetic `<module>` type). An inline route
 * callback — `app.get('/x', (req, res) => …)`, the most common Express/Koa
 * shape there is — produces no type and no method at all, so it had no range
 * and every blocking call inside it was silently exempt.
 *
 * Fixed without line ranges: the calls extractor already tags the enclosing
 * function of that shape as `<property>_handler` (`findJSEnclosingFunction`),
 * so a blocking call inside `app.get(…)` carries `in_method === 'get_handler'`.
 *
 * The tag alone is not enough to act on, which is what the negative cases
 * below pin. The extractor applies it to *any* function argument of *any*
 * member-expression call, so `items.map(x => …)` is also `map_handler`. Two
 * conditions are therefore required: a router verb, and callback parameters
 * that look like a request handler's.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';

const bmt = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.findings ?? []).filter(f => f.rule_id === 'blocking-main-thread');

const js = (code: string, file = 'server.js') => analyze(code, file, 'javascript');

describe('#315 blocking-main-thread: inline route callbacks', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('fires on an Express inline arrow handler (the regression)', async () => {
    const r = await js([
      "const express = require('express');",
      "const { readFileSync } = require('fs');",
      'const app = express();',
      "app.get('/report', (req, res) => {",
      "  const data = readFileSync('/var/big.csv', 'utf8');",
      '  res.send(data);',
      '});',
    ].join('\n'));
    const hits = bmt(r);
    expect(hits.length).toBe(1);
    expect(hits[0].line).toBe(5);
    expect(hits[0].evidence?.handler).toBe('get_handler');
  });

  it('fires on Koa middleware taking ctx', async () => {
    const r = await js([
      "const Koa = require('koa');",
      "const { readFileSync } = require('fs');",
      'const app = new Koa();',
      'app.use(async (ctx) => {',
      "  ctx.body = readFileSync('/var/big.csv', 'utf8');",
      '});',
    ].join('\n'));
    expect(bmt(r).length).toBe(1);
  });

  it('fires on synchronous crypto inside a POST handler', async () => {
    const r = await js([
      "const express = require('express');",
      "const crypto = require('crypto');",
      'const app = express();',
      "app.post('/login', (req, res) => {",
      "  const h = crypto.createHash('sha256').update(req.body.pw).digest('hex');",
      '  res.send(h);',
      '});',
    ].join('\n'));
    const hits = bmt(r);
    expect(hits.length).toBe(1);
    expect(hits[0].evidence?.reason).toBe('crypto');
  });

  it('still fires on the shapes that already worked: named function', async () => {
    const r = await js([
      "const { readFileSync } = require('fs');",
      'function handler(req, res) {',
      "  const data = readFileSync('/var/big.csv', 'utf8');",
      '  res.send(data);',
      '}',
      'module.exports = handler;',
    ].join('\n'));
    expect(bmt(r).length).toBe(1);
  });

  it('still fires on a NestJS decorated method', async () => {
    const r = await analyze([
      "import { readFileSync } from 'fs';",
      "import { Controller, Get } from '@nestjs/common';",
      "@Controller('x')",
      'export class XController {',
      '  @Get()',
      '  findAll() {',
      "    return readFileSync('/etc/hosts', 'utf8');",
      '  }',
      '}',
    ].join('\n'), 'x.controller.ts', 'typescript');
    expect(bmt(r).length).toBe(1);
  });

  it('stays silent on the async equivalent (control)', async () => {
    const r = await js([
      "const express = require('express');",
      "const fs = require('fs/promises');",
      'const app = express();',
      "app.get('/report', async (req, res) => {",
      "  const data = await fs.readFile('/var/big.csv', 'utf8');",
      '  res.send(data);',
      '});',
    ].join('\n'));
    expect(bmt(r).length).toBe(0);
  });
});

describe('#315 the `<verb>_handler` tag alone must not be trusted', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('stays silent on a non-router callback (items.map)', async () => {
    // The extractor tags this `map_handler`; `map` is not a router verb.
    const r = await js([
      "const { readFileSync } = require('fs');",
      "const files = ['a', 'b'];",
      "const out = files.map(f => readFileSync(f, 'utf8'));",
      'module.exports = out;',
    ].join('\n'));
    expect(bmt(r).length).toBe(0);
  });

  it('stays silent on cache.get(key, () => …) — router verb, no handler params', async () => {
    // `get` IS a router verb, so only the parameter test rules this out.
    const r = await js([
      "const { readFileSync } = require('fs');",
      "const cache = require('./cache');",
      "const v = cache.get('key', () => readFileSync('/tmp/x', 'utf8'));",
      'module.exports = v;',
    ].join('\n'));
    expect(bmt(r).length).toBe(0);
  });

  it('stays silent on a router mount whose callback takes no parameters', async () => {
    // Conservative on purpose: a zero-parameter callback offers no evidence it
    // is a request handler, matching the parameter-name rule already used for
    // methods. Worth revisiting only with corpus evidence.
    const r = await js([
      "const { readFileSync } = require('fs');",
      "const router = require('./r');",
      "router.get('/x', function () {",
      "  return readFileSync('/tmp/x', 'utf8');",
      '});',
    ].join('\n'));
    expect(bmt(r).length).toBe(0);
  });

  it('stays silent on a module-scope Sync call in a file that also mounts routes', async () => {
    // This is the real-corpus shape: nodegoat/server.js and juice-shop/server.ts
    // both read files synchronously at startup while mounting routes elsewhere
    // in the same file. Neither may be attributed to a handler.
    const r = await js([
      "const express = require('express');",
      "const fs = require('fs');",
      'const app = express();',
      "const key = fs.readFileSync('./cert/server.key');",
      'app.use((req, res, next) => { next(); });',
      'module.exports = { app, key };',
    ].join('\n'));
    expect(bmt(r).length).toBe(0);
  });
});
