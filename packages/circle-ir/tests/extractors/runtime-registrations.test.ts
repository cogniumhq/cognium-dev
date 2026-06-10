/**
 * Tests for the runtime-registrations extractor (issue #15, Phase 1).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractImports } from '../../src/core/extractors/imports.js';
import { extractRuntimeRegistrations } from '../../src/core/extractors/runtime-registrations.js';

describe('Runtime-Registrations Extractor — Phase 1 (Express-family)', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('detects named handler on app.get', async () => {
    const code = `
const express = require('express');
const app = express();

function pingHandler(req, res) {
  res.send('pong');
}

app.get('/ping', pingHandler);
`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');
    const regs = extractRuntimeRegistrations(tree, undefined, 'javascript', imports);

    expect(regs).toHaveLength(1);
    const reg = regs[0];
    expect(reg.kind).toBe('http_route');
    expect(reg.registrar.method).toBe('get');
    expect(reg.registrar.receiver).toBe('app');
    expect(reg.path).toBe('/ping');
    expect(reg.handler.name).toBe('pingHandler');
    // line should point at the function declaration, not the call site
    expect(reg.handler.line).toBeGreaterThan(0);
  });

  it('detects inline arrow handler with name=null', async () => {
    const code = `
const app = require('express')();
app.post('/users', (req, res) => {
  res.status(201).send({});
});
`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');
    const regs = extractRuntimeRegistrations(tree, undefined, 'javascript', imports);

    expect(regs).toHaveLength(1);
    const reg = regs[0];
    expect(reg.registrar.method).toBe('post');
    expect(reg.path).toBe('/users');
    expect(reg.handler.name).toBeNull();
    expect(reg.handler.line).toBeGreaterThan(0);
  });

  it('emits one registration per handler-position arg for middleware chains', async () => {
    const code = `
const app = require('express')();
function authMw(req, res, next) { next(); }
function logMw(req, res, next) { next(); }
function finalHandler(req, res) { res.end(); }

app.post('/x', authMw, logMw, finalHandler);
`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');
    const regs = extractRuntimeRegistrations(tree, undefined, 'javascript', imports);

    expect(regs).toHaveLength(3);
    const names = regs.map(r => r.handler.name);
    expect(names).toEqual(['authMw', 'logMw', 'finalHandler']);
    // All share the same registrar line + path
    for (const r of regs) {
      expect(r.path).toBe('/x');
      expect(r.registrar.method).toBe('post');
    }
  });

  it('detects router.use middleware registration', async () => {
    const code = `
const express = require('express');
const router = express.Router();

function corsMiddleware(req, res, next) { next(); }
router.use(corsMiddleware);
`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');
    const regs = extractRuntimeRegistrations(tree, undefined, 'javascript', imports);

    expect(regs).toHaveLength(1);
    expect(regs[0].kind).toBe('middleware');
    expect(regs[0].registrar.method).toBe('use');
    expect(regs[0].registrar.receiver).toBe('router');
    expect(regs[0].handler.name).toBe('corsMiddleware');
  });

  it('detects event_listener on Express-shaped receiver', async () => {
    const code = `
const server = require('http').createServer();
function onConnection(socket) {}
server.on('connection', onConnection);
`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');
    const regs = extractRuntimeRegistrations(tree, undefined, 'javascript', imports);

    expect(regs).toHaveLength(1);
    expect(regs[0].kind).toBe('event_listener');
    expect(regs[0].registrar.method).toBe('on');
    expect(regs[0].registrar.receiver).toBe('server');
    expect(regs[0].path).toBe('connection');
    expect(regs[0].handler.name).toBe('onConnection');
  });

  it('does not register calls on unrelated receivers without framework imports', async () => {
    const code = `
const cache = new Map();
function loader() {}
cache.get('key');
cache.set('key', loader);
`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');
    const regs = extractRuntimeRegistrations(tree, undefined, 'javascript', imports);

    expect(regs).toHaveLength(0);
  });

  it('returns [] for non-JS languages', async () => {
    const javaCode = `
public class Demo {
  public void handle() {}
}
`;
    const tree = await parse(javaCode, 'java');
    const regs = extractRuntimeRegistrations(tree, undefined, 'java', []);
    expect(regs).toEqual([]);
  });

  it('works for TypeScript with explicit framework import', async () => {
    const code = `
import express from 'express';
const app = express();

const root = (req: any, res: any) => res.send('ok');
app.get('/', root);
`;
    const tree = await parse(code, 'typescript');
    const imports = extractImports(tree, 'typescript');
    const regs = extractRuntimeRegistrations(tree, undefined, 'typescript', imports);

    expect(regs).toHaveLength(1);
    expect(regs[0].registrar.method).toBe('get');
    expect(regs[0].handler.name).toBe('root');
    expect(regs[0].framework).toBe('express');
  });

  it('records path for template-string routes without substitution', async () => {
    const code = `
const app = require('express')();
function h(){}
app.get(\`/static/path\`, h);
`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');
    const regs = extractRuntimeRegistrations(tree, undefined, 'javascript', imports);

    expect(regs).toHaveLength(1);
    expect(regs[0].path).toBe('/static/path');
  });

  it('treats template-string with substitution as no-path', async () => {
    const code = `
const app = require('express')();
const prefix = '/api';
function h(){}
app.get(\`\${prefix}/x\`, h);
`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');
    const regs = extractRuntimeRegistrations(tree, undefined, 'javascript', imports);

    expect(regs).toHaveLength(1);
    // The first arg is dynamic, so the handler-slice still starts at index 1?
    // No — because we did NOT classify the dynamic template as a path. The
    // resolver will read the first arg as a non-path and try to treat it as
    // a handler; the template-string is not a function, so it should be
    // skipped, leaving only the second arg `h`.
    expect(regs[0].path).toBeUndefined();
    expect(regs[0].handler.name).toBe('h');
  });
});
