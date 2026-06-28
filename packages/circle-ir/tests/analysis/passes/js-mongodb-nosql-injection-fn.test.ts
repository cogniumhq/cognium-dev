/**
 * Sprint 54 — cognium-dev #195: JS mongodb `col.find({name: tainted})`
 * object-value `nosql_injection` FN.
 *
 * `db.collection('u').find({ name: q })` with tainted `q` (from
 * `req.query.q`) does not flag CWE-943. Sinks are registered
 * (`config-loader.ts:1489` Collection.find JS + classless variants at
 * :1513), `arg_positions: [0]` correctly targets the filter object.
 * Same root-cause hypothesis as Python (#194): nested object-property
 * value taint is not surfaced to the sink matcher.
 *
 * Recall lock: literal-only `col.find({name: "alice"})` produces zero
 * flows. Aliased `const filter = {name: q}; col.find(filter)` must also
 * flag.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countNosqlFlows = (flows: Array<{ sink_type?: string }> | undefined) =>
  (flows ?? []).filter(f => f.sink_type === 'nosql_injection').length;
const countNosqlSinks = (sinks: Array<{ type?: string }> | undefined) =>
  (sinks ?? []).filter(s => s.type === 'nosql_injection').length;

describe('cognium-dev #195 — JS mongodb object-value nosql_injection FN', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('FN — col.find({name: q}) inline object-value taint fires nosql_injection', async () => {
    const code = `const express = require('express');
const { MongoClient } = require('mongodb');
const app = express();
const db = new MongoClient('mongodb://localhost').db('app');

app.get('/lookup', async (req, res) => {
  const q = req.query.q || '';
  const col = db.collection('u');
  const out = await col.find({ name: q }).toArray();
  res.json(out);
});
`;
    const r = await analyze(code, 'lookup.js', 'javascript');
    expect(countNosqlSinks(r.taint?.sinks)).toBeGreaterThan(0);
    expect(countNosqlFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('FN — const filter = {name: q}; col.find(filter) aliased fires', async () => {
    const code = `const express = require('express');
const { MongoClient } = require('mongodb');
const app = express();
const db = new MongoClient('mongodb://localhost').db('app');

app.get('/lookup2', async (req, res) => {
  const q = req.query.q || '';
  const col = db.collection('u');
  const filter = { name: q };
  const out = await col.find(filter).toArray();
  res.json(out);
});
`;
    const r = await analyze(code, 'lookup2.js', 'javascript');
    expect(countNosqlFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('recall — col.find({name: "alice"}) literal-only produces zero flows', async () => {
    const code = `const { MongoClient } = require('mongodb');
const db = new MongoClient('mongodb://localhost').db('app');
const col = db.collection('u');
col.find({ name: 'alice' }).toArray();
`;
    const r = await analyze(code, 'noop.js', 'javascript');
    expect(countNosqlFlows(r.taint?.flows)).toBe(0);
  });
});
