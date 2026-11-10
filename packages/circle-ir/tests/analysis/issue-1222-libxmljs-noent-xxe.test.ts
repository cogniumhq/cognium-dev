/**
 * cognium-dev#1222 — libxmljs `parseXmlString` / `parseXml` with `noent: false`
 * (or default-safe inline options) must not produce an `xxe` taint flow.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const flows = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'xxe');

const SAFE_NOENT_FALSE = `const libxmljs = require('libxmljs');
module.exports.bulk = function (req, res) {
  var products = libxmljs.parseXmlString(req.files.products.data.toString('utf8'), {noent:false,noblanks:true})
  res.send('ok')
}
`;

const SAFE_OMIT_NOENT = `const libxmljs = require('libxmljs');
module.exports.bulk = function (req, res) {
  var products = libxmljs.parseXmlString(req.files.products.data.toString('utf8'), {noblanks:true})
  res.send('ok')
}
`;

const UNSAFE_NOENT_TRUE = `const libxmljs = require('libxmljs');
module.exports.bulk = function (req, res) {
  var products = libxmljs.parseXmlString(req.files.products.data.toString('utf8'), {noent:true,noblanks:true})
  res.send('ok')
}
`;

const UNKNOWN_OPTS_VAR = `const libxmljs = require('libxmljs');
module.exports.bulk = function (req, res) {
  const opts = { noent: false };
  var products = libxmljs.parseXmlString(req.files.products.data.toString('utf8'), opts)
  res.send('ok')
}
`;

describe('#1222 libxmljs noent and xxe taint flows', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('noent:false does not emit xxe flow', async () => {
    const r = await analyze(SAFE_NOENT_FALSE, 'h.js', 'javascript');
    expect(flows(r)).toHaveLength(0);
  });

  it('inline options without noent does not emit xxe flow', async () => {
    const r = await analyze(SAFE_OMIT_NOENT, 'h2.js', 'javascript');
    expect(flows(r)).toHaveLength(0);
  });

  it('noent:true still emits xxe flow', async () => {
    const r = await analyze(UNSAFE_NOENT_TRUE, 'v.js', 'javascript');
    expect(flows(r).length).toBeGreaterThan(0);
  });

  it('dynamic options variable keeps xxe flow (unknown config)', async () => {
    const r = await analyze(UNKNOWN_OPTS_VAR, 'dyn.js', 'javascript');
    expect(flows(r).length).toBeGreaterThan(0);
  });
});
