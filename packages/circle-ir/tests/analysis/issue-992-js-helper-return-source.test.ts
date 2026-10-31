/**
 * cognium-dev#992 — with try defs, `v = pick(req.query.x)` inside a try made
 * `v` tainted even when the same-file `pick` returns a literal slot of a local
 * array (`['safe', x][0]`). A request value passed into a helper that returns
 * none of its parameters is not a source; one that can return it still is.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const handler = (ret: string) => `const db = require('mysql').createConnection({});
function pick(x) {
  const list = ['safe', x];
  return ${ret};
}
module.exports = function handler(req, res) {
  let v;
  try {
    v = pick(req.query.x);
  } finally {
    console.log('done');
  }
  db.query('SELECT * FROM t WHERE id = ' + v);
  res.end();
};`;

const sql = async (code: string) =>
  (await analyze(code, 'h.js', 'javascript')).taint.flows.filter(f => f.sink_type === 'sql_injection');

describe('#992 JS helper that returns no parameter', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('drops the flow when the helper returns the literal slot', async () => {
    expect(await sql(handler('list[0]'))).toHaveLength(0);
  });

  it('keeps it when the helper returns the parameter slot', async () => {
    expect((await sql(handler('list[1]'))).length).toBeGreaterThan(0);
  });

  it('keeps it when the helper returns the parameter', async () => {
    expect((await sql(handler('x.trim()'))).length).toBeGreaterThan(0);
  });
});

describe('#992 helper judge on odd call names', () => {
  it('does not throw on a non-identifier name (minified code)', async () => {
    const { jsHelperReturnsNoParam } = await import('../../src/analysis/js-helper-return.js');
    expect(jsHelperReturnsNoParam('function(){return 1}', 'function(){var e=Array.prototype.forEach')).toBe(false);
    expect(jsHelperReturnsNoParam("function $x(a) { return 'k'; }", '$x')).toBe(true);
  });
});
