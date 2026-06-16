/**
 * Repro for cognium-dev#63 — Python taint lost through LEFT operand of `+` concat.
 *
 * Reporter's matrix (Flask, request.args.get → cursor.execute):
 *   V5 `execute("a" + u)`               (taint on right of 2-part) — FIRES
 *   V6 `execute("a" + u + "b")`          (taint in middle of 3-part) — MISSES
 *   V2 `q = "a"+u+"b"; execute(q)`       (assigned first)            — FIRES
 *   V3 `execute("... %s" % u)`           (%-format)                   — FIRES
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#63 — Python concat LEFT-operand taint propagation', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const hasSqliFlow = (flows: Array<{ sink_type?: string }> | undefined) =>
    (flows ?? []).some((f) => f.sink_type === 'sql_injection');

  it('V5: execute("a" + u) — right-operand 2-part concat — should FIRE (positive control)', async () => {
    const code = `
from flask import request
import sqlite3
def handler():
    u = request.args.get('u')
    conn = sqlite3.connect('db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM t WHERE id = " + u)
`;
    const r = await analyze(code, 'v5.py', 'python');
    expect(hasSqliFlow(r.taint.flows)).toBe(true);
  });

  it('V6: execute("a" + u + "b") — middle-operand 3-part concat — should FIRE (currently MISSES)', async () => {
    const code = `
from flask import request
import sqlite3
def handler():
    u = request.args.get('u')
    conn = sqlite3.connect('db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM t WHERE id = '" + u + "'")
`;
    const r = await analyze(code, 'v6.py', 'python');
    expect(hasSqliFlow(r.taint.flows)).toBe(true);
  });

  it('V2: q = "a"+u+"b"; execute(q) — assigned first — should FIRE (control)', async () => {
    const code = `
from flask import request
import sqlite3
def handler():
    u = request.args.get('u')
    q = "SELECT * FROM t WHERE id = '" + u + "'"
    conn = sqlite3.connect('db')
    cur = conn.cursor()
    cur.execute(q)
`;
    const r = await analyze(code, 'v2.py', 'python');
    expect(hasSqliFlow(r.taint.flows)).toBe(true);
  });

  it('LEFT: execute(u + "suffix") — taint as outer LEFT operand — should FIRE', async () => {
    const code = `
from flask import request
import sqlite3
def handler():
    u = request.args.get('u')
    conn = sqlite3.connect('db')
    cur = conn.cursor()
    cur.execute(u + " AND 1=1")
`;
    const r = await analyze(code, 'left.py', 'python');
    expect(hasSqliFlow(r.taint.flows)).toBe(true);
  });

  it('N-way: execute("a" + u + "b" + "c") — deeply nested left taint — should FIRE', async () => {
    const code = `
from flask import request
import sqlite3
def handler():
    u = request.args.get('u')
    conn = sqlite3.connect('db')
    cur = conn.cursor()
    cur.execute("SELECT" + " * " + u + " FROM t")
`;
    const r = await analyze(code, 'nway.py', 'python');
    expect(hasSqliFlow(r.taint.flows)).toBe(true);
  });
});
