/**
 * a response the handler marks with a non-HTML Content-Type is not
 * an XSS sink. Only a type a browser renders as a document (HTML, XHTML, SVG,
 * XML), or an unset type, keeps `res.end` / `res.send` / `c.body` an XSS sink.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

async function xss(code: string, file = 'server.ts') {
  const lang = file.endsWith('.ts') ? 'typescript' : 'javascript';
  const r = await analyze(code, file, lang);
  return {
    sinks: r.taint.sinks.filter(s => s.type === 'xss').map(s => s.line),
    flows: (r.taint.flows ?? []).filter(f => f.sink_type === 'xss').map(f => f.sink_line),
  };
}

const NODE_HTTP = (setType: string, body: string) =>
  "const http = require('http');\n" +
  "http.createServer((req, res) => {\n" +
  "  const q = new URL(req.url, 'http://x').searchParams.get('q');\n" +
  `  ${setType}\n` +
  `  res.end(${body});\n` +
  '}).listen(8080);\n';

const EXPRESS = (setType: string, body: string) =>
  "const express = require('express'); const app = express();\n" +
  "app.get('/u', (req, res) => {\n" +
  '  const name = req.query.name;\n' +
  `  ${setType}\n` +
  `  res.send(${body});\n` +
  '});\n';

describe('JSON responses are not XSS sinks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  describe('non-HTML Content-Type drops the sink', () => {
    it('writeHead application/json then res.end', async () => {
      const r = await xss(NODE_HTTP(
        "res.writeHead(200, { 'Content-Type': 'application/json' });",
        'JSON.stringify({ q })'));
      expect(r.sinks).toEqual([]);
      expect(r.flows).toEqual([]);
    });

    it('setHeader application/json then res.end', async () => {
      const r = await xss(NODE_HTTP(
        "res.setHeader('Content-Type', 'application/json; charset=utf-8');",
        'JSON.stringify({ q })'));
      expect(r.flows).toEqual([]);
    });

    it('setHeader text/plain then res.end', async () => {
      const r = await xss(NODE_HTTP("res.setHeader('content-type', 'text/plain');", 'q'));
      expect(r.flows).toEqual([]);
    });

    it("express res.type('json') then res.send", async () => {
      const r = await xss(EXPRESS("res.type('json');", 'JSON.stringify({ name })'));
      expect(r.flows).toEqual([]);
    });

    it("express res.set('Content-Type', 'application/json') then res.send", async () => {
      const r = await xss(EXPRESS("res.set('Content-Type', 'application/json');", 'JSON.stringify({ name })'));
      expect(r.flows).toEqual([]);
    });

    it('express res.set({ Content-Type: json }) object form', async () => {
      const r = await xss(EXPRESS("res.set({ 'Content-Type': 'application/json' });", 'JSON.stringify({ name })'));
      expect(r.flows).toEqual([]);
    });

    it('hono c.body with a JSON content-type header', async () => {
      const code =
        "import { Hono } from 'hono';\nconst app = new Hono();\n" +
        "app.get('/u', (c) => {\n  const name = c.req.query('name');\n" +
        "  return c.body(JSON.stringify({ name }), 200, { 'content-type': 'application/json' });\n});\n";
      const r = await xss(code);
      expect(r.sinks).toEqual([]);
      expect(r.flows).toEqual([]);
    });

    it('static server that sets the type from the file extension', async () => {
      const code =
        "const http = require('http'); const fs = require('fs'); const path = require('path');\n" +
        "const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json' };\n" +
        "http.createServer((req, res) => {\n" +
        "  const file = path.join(__dirname, 'public', path.normalize(req.url));\n" +
        "  const type = TYPES[path.extname(file)] || 'application/octet-stream';\n" +
        "  res.writeHead(200, { 'Content-Type': type });\n" +
        '  res.end(fs.readFileSync(file));\n' +
        '}).listen(8080);\n';
      const r = await xss(code, 'server.js');
      expect(r.sinks).toEqual([]);
      expect(r.flows).toEqual([]);
    });

    it('json helpers (c.json, res.json) are not XSS sinks', async () => {
      const hono =
        "import { Hono } from 'hono';\nconst app = new Hono();\n" +
        "app.get('/u', (c) => {\n  const name = c.req.query('name');\n  return c.json({ name });\n});\n";
      const express =
        "const express = require('express'); const app = express();\n" +
        "app.get('/u', (req, res) => {\n  const name = req.query.name;\n  res.json({ name });\n});\n";
      expect((await xss(hono)).flows).toEqual([]);
      expect((await xss(express, 'server.js')).flows).toEqual([]);
    });
  });

  describe('HTML or unset Content-Type keeps the sink', () => {
    it('writeHead text/html then res.end', async () => {
      const r = await xss(NODE_HTTP(
        "res.writeHead(200, { 'Content-Type': 'text/html' });", "'<p>' + q + '</p>'"));
      expect(r.flows).toContain(5);
    });

    it('setHeader image/svg+xml then res.end', async () => {
      const r = await xss(NODE_HTTP("res.setHeader('Content-Type', 'image/svg+xml');", 'q'));
      expect(r.flows).toContain(5);
    });

    it('express res.send with no type set', async () => {
      const r = await xss(EXPRESS('', "'<p>' + name + '</p>'"));
      expect(r.flows).toContain(5);
    });

    it('express res.send of JSON text with no type set (express sends it as text/html)', async () => {
      const r = await xss(EXPRESS('', 'JSON.stringify({ name })'));
      expect(r.flows).toContain(5);
    });

    it("express res.type('html') then res.send", async () => {
      const r = await xss(EXPRESS("res.type('html');", "'<p>' + name + '</p>'"));
      expect(r.flows).toContain(5);
    });

    it('a type read from a variable with no extension lookup keeps the sink', async () => {
      const r = await xss(NODE_HTTP(
        "res.writeHead(200, { 'Content-Type': req.headers.accept });", 'q'));
      expect(r.flows).toContain(5);
    });

    it('a JSON type in a different handler does not drop the sink', async () => {
      const code =
        "const express = require('express'); const app = express();\n" +
        "app.get('/a', (req, res) => {\n  res.type('json');\n  res.send(JSON.stringify({ ok: true }));\n});\n" +
        "app.get('/b', (req, res) => {\n  const name = req.query.name;\n  res.send('<p>' + name + '</p>');\n});\n";
      const r = await xss(code, 'server.js');
      expect(r.flows).toContain(8);
    });

    it('hono c.html stays an XSS sink', async () => {
      const code =
        "import { Hono } from 'hono';\nconst app = new Hono();\n" +
        "app.get('/u', (c) => {\n  const name = c.req.query('name');\n  return c.html('<p>' + name + '</p>');\n});\n";
      const r = await xss(code);
      expect(r.flows).toContain(5);
    });
  });
});
