/**
 * cognium-dev#686 (slice) — module-level `let store` written in one Express
 * handler and read in another reaches `res.send` xss sinks.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const flows = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === t);

const STORED = `const express = require('express');
const app = express();
let store = '';
app.post('/save', (req, res) => { store = req.body.comment; res.send('ok'); });
app.get('/show', (req, res) => { res.send(store); });
`;

const STORED_SAFE = `const express = require('express');
const app = express();
let store = '';
app.post('/save', (req, res) => { store = 'fixed'; res.send('ok'); });
app.get('/show', (req, res) => { res.send(store); });
`;

describe('#686 slice: JS module-scope store across handlers', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('CommentLedgerApp: xss flow from body write to later send(store)', async () => {
    const r = await analyze(STORED, 'CommentLedgerApp.js', 'javascript');
    const xss = flows(r, 'xss');
    expect(xss.length).toBeGreaterThan(0);
    expect(xss.some(f => f.sink_line === 5)).toBe(true);
  });

  it('CommentLedgerSafeApp: literal write stays clean at send(store)', async () => {
    const r = await analyze(STORED_SAFE, 'CommentLedgerSafeApp.js', 'javascript');
    expect(flows(r, 'xss')).toHaveLength(0);
  });
});
