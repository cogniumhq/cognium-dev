/**
 * Regression tests for cognium-ai#279 — JS/TS static-detector FP round 2.
 *
 * Three residual crit/high FP classes reproduced on our engine and fixed as
 * SinkFilter drops (recall-preserving):
 *   R-1 — object-literal ORM query-builder arg (`findOne({ where: … })`) is a
 *         bound parameter, not raw injection (Stage 15h).
 *   R-2 — `.find(fn)` / `.filter(fn)` is Array.prototype iteration, not a Mongo
 *         query (Stage 15g).
 *   R-6 — a template-literal URL with a fixed literal host is not SSRF; only the
 *         path is interpolated (Stage 15i).
 *
 * (R-4/R-7/R-8/R-9 were already clean on the current engine; R-5 is a
 * threat-model/context concern, not a detector bug.)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const HIGH = new Set(['sql_injection', 'nosql_injection', 'ssrf']);
const fires = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint?.flows ?? []).some(f => HIGH.has(f.sink_type));

describe('cognium-ai#279 R-2: Array.find(fn) is not a NoSQL sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does NOT flag user.accounts.find(a => …) as nosql injection', async () => {
    const code = `
export function f(user, req) {
  const pid = req.query.pid;
  return user.accounts.find(a => a.providerId === pid);
}`;
    expect(fires(await analyze(code, 'a.ts', 'typescript'))).toBe(false);
  });

  it('STILL flags a real collection.find({ query }) with an object arg', async () => {
    const code = `
export async function f(collection, req) {
  const q = req.query.q;
  return await collection.find({ name: q });
}`;
    expect(fires(await analyze(code, 'b.ts', 'typescript'))).toBe(true);
  });
});

describe('cognium-ai#279 R-1: ORM query-builder object arg is not injection', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does NOT flag adapter.findOne({ where: [...] }) as nosql injection', async () => {
    const code = `
export async function f(req) {
  const email = req.query.email;
  return await adapter.findOne({ model: "user", where: [{ field: "email", value: email }] });
}`;
    expect(fires(await analyze(code, 'c.ts', 'typescript'))).toBe(false);
  });

  it('STILL flags raw string-concatenated SQL', async () => {
    const code = `
export async function f(client, req) {
  const id = req.query.id;
  return await client.query("SELECT * FROM u WHERE id=" + id);
}`;
    expect(fires(await analyze(code, 'd.ts', 'typescript'))).toBe(true);
  });
});

describe('cognium-ai#279 R-3: SSRF in a browser client component is a category error', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const ssrf = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint?.flows ?? []).some(f => f.sink_type === 'ssrf');

  it('does NOT flag axios.post in a React client component (.jsx + hooks)', async () => {
    const code = `
import React, { useState } from 'react';
import axios from 'axios';
export function Comp(props) {
  const [x, setX] = useState(0);
  const url = props.url;
  return axios.post(url, { data: x });
}`;
    expect(ssrf(await analyze(code, 'App.jsx', 'javascript'))).toBe(false);
  });

  it('does NOT flag fetch in a "use client" .tsx component', async () => {
    const code = `
"use client";
import axios from 'axios';
export function C(props) {
  const u = props.url;
  return axios.post(u, {});
}`;
    expect(ssrf(await analyze(code, 'C.tsx', 'tsx'))).toBe(false);
  });

  it('STILL flags fetch in a server-side .tsx (no client signal) — zero FN', async () => {
    const code = `
export default async function handler(req, res) {
  const u = req.query.url;
  const r = await fetch(u);
  res.json(await r.json());
}`;
    expect(ssrf(await analyze(code, 'Page.tsx', 'tsx'))).toBe(true);
  });

  it('STILL flags fetch when a server signal is present alongside a client one', async () => {
    const code = `
"use client";
import fs from 'fs';
export function M(req) {
  const u = req.query.url;
  return fetch(u);
}`;
    expect(ssrf(await analyze(code, 'M.tsx', 'tsx'))).toBe(true);
  });
});

describe('cognium-ai#279 R-6: fixed-host URL template is not SSRF', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does NOT flag fetch(`https://api.github.com/...${path}`) as SSRF', async () => {
    const code = `
export async function f(req) {
  const owner = req.query.o;
  return await fetch(\`https://api.github.com/repos/\${owner}/x\`);
}`;
    expect(fires(await analyze(code, 'e.ts', 'typescript'))).toBe(false);
  });

  it('STILL flags an interpolated-HOST template as SSRF', async () => {
    const code = `
export async function f(req) {
  const host = req.query.h;
  return await fetch(\`https://\${host}/path\`);
}`;
    expect(fires(await analyze(code, 'f.ts', 'typescript'))).toBe(true);
  });
});
