/**
 * #667 — a lookup in a constant table selects a value the program wrote.
 *
 * `const fn = EXPORTERS[req.query.kind]` lets the request choose the key, not
 * the value. When the table is a top-level `const` object or array literal the
 * file never writes to, the result is not request data: it is not a source and
 * taint does not flow into it. Before, the handler reported
 * external_taint_escape on `res.json(fn())`.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { constLookupTables, isConstTableLookup } from '../../src/analysis/const-table-lookup.js';

const app = (decls: string[], ...body: string[]) =>
  [
    "'use strict';",
    "const express = require('express');",
    'const app = express();',
    ...decls,
    '',
    "app.get('/export', (req, res) => {",
    ...body.map((l) => '  ' + l),
    '});',
    'module.exports = app;',
  ].join('\n');

const flowTypes = async (code: string) => {
  const r = await analyze(code, 'exporters.js', 'javascript');
  return (r.taint.flows ?? []).map((f) => f.sink_type);
};

describe('#667 — constant-table lookup is not request data', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('a function picked from a constant registry and called is clean', async () => {
    const code = app(
      ["const EXPORTERS = { xml: () => 'xml-out', yaml: () => 'yaml-out' };"],
      'const fn = EXPORTERS[req.query.kind];',
      "if (!fn) return res.status(404).end('none');",
      'res.json(fn());',
    );
    expect(await flowTypes(code)).toEqual([]);
  });

  it.each([
    ['a frozen route table into a redirect', ["const ROUTES = Object.freeze({ home: '/home', docs: '/docs' });"],
      'const target = ROUTES[req.query.k];', 'res.redirect(target);'],
    ['an array of labels into HTML', ["const SHADES = ['red', 'blue'];"],
      'const shade = SHADES[req.query.i];', "res.send('<b>' + shade + '</b>');"],
    ['a typed TS-style table', ['const TITLES = { a: "Alpha", b: "Beta" };'],
      'const title = TITLES?.[req.params.id];', "res.send('<h1>' + title + '</h1>');"],
  ])('%s is clean', async (_n, decls, ...body) => {
    expect(await flowTypes(app(decls, ...body))).toEqual([]);
  });

  it.each([
    ['a table the handler writes into', ['const CACHE = {};'],
      'CACHE[req.query.k] = req.query.v;', 'const hit = CACHE[req.query.k];', "res.send('<b>' + hit + '</b>');"],
    ['a let table', ["let LABELS = { a: 'A' };"],
      'const lab = LABELS[req.query.k];', "res.send('<b>' + lab + '</b>');"],
    ['a lookup with a request fallback', ["const NAMES = { a: 'Alpha' };"],
      'const name = NAMES[req.query.k] || req.query.k;', "res.send('<b>' + name + '</b>');"],
    ['a table mutated through Object.assign', ['const PREFS = {};', 'Object.assign(PREFS, global.userPrefs);'],
      'const p = PREFS[req.query.k];', "res.send('<b>' + p + '</b>');"],
    ['a table written through a nested member', ['const STORE = { items: [] };'],
      'STORE.items.push(req.query.v);', 'const b = STORE[req.query.k];', "res.send('<b>' + b + '</b>');"],
    ['a table written through an alias', ['const CACHE2 = {};', 'const alias = CACHE2;'],
      'alias[req.query.k] = req.query.v;', 'const hit = CACHE2[req.query.k];', "res.send('<b>' + hit + '</b>');"],
    ['a table passed to a setter helper', ["const _ = require('lodash');", "const SETTINGS = { theme: 'dark' };"],
      '_.set(SETTINGS, req.query.p, req.query.v);', 'const v = SETTINGS[req.query.k];', "res.send('<b>' + v + '</b>');"],
  ])('%s still reports xss', async (_n, decls, ...body) => {
    expect(await flowTypes(app(decls, ...body))).toContain('xss');
  });

  it('dynamic require of the request value still reports code injection', async () => {
    const code = app([], "const kind = req.query.kind || '';", 'const fn = require(kind);', 'res.json(fn());');
    expect(await flowTypes(code)).toContain('code_injection');
  });

  describe('helpers', () => {
    it('finds only never-written const literal tables', () => {
      const code = [
        'const A = { x: 1 };',
        'const B = [1, 2];',
        'let C = { x: 1 };',
        'const D = {};',
        'D.k = 2;',
        'const E = Object.freeze({ k: 1 });',
        'const F = { q: req.query.x };',
        'const G = [];',
        'G.push(3);',
        'const H = { a: [] };',
        'H.a.push(4);',
        'const I = { a: {} };',
        'I[k].x = 5;',
        'const J = { a: 1 };',
        'exported({ J });',
        'const K = { a: 1 };',
        'if (K[k] === 1) use(K[k].toString());',
      ].join('\n');
      expect([...constLookupTables(code, 'javascript')].sort()).toEqual(['A', 'B', 'E', 'K']);
      expect(constLookupTables(code, 'python').size).toBe(0);
    });

    it.each([
      ['T[req.query.k]', true],
      ['T[req.query.k];', true],
      ['T?.[k]', true],
      ['T[k] || k', false],
      ['T[k].call(x)', false],
      ['U[k]', false],
    ])('%s is a whole lookup: %s', (rhs, want) => {
      expect(isConstTableLookup(rhs, new Set(['T']))).toBe(want);
    });
  });
});
