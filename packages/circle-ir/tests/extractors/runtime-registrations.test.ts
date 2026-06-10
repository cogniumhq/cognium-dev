/**
 * Tests for the runtime-registrations extractor (issue #15, Phases 1, 2, 3).
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

describe('Runtime-Registrations Extractor — Phase 2 (Python decorators)', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('detects Flask @app.route with path extraction', async () => {
    const code = `
from flask import Flask
app = Flask(__name__)

@app.route('/ping')
def ping():
    return 'pong'
`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');
    const regs = extractRuntimeRegistrations(tree, undefined, 'python', imports);

    expect(regs).toHaveLength(1);
    const reg = regs[0];
    expect(reg.kind).toBe('http_route');
    expect(reg.framework).toBe('flask');
    expect(reg.registrar.method).toBe('route');
    expect(reg.registrar.receiver).toBe('app');
    expect(reg.path).toBe('/ping');
    expect(reg.handler.name).toBe('ping');
    expect(reg.handler.line).toBeGreaterThan(0);
  });

  it('emits one registration per decorator for chained @app.route + @auth_required', async () => {
    const code = `
from flask import Flask
app = Flask(__name__)

@app.route('/users/<id>', methods=['GET'])
@auth_required
def get_user(id):
    return {}
`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');
    const regs = extractRuntimeRegistrations(tree, undefined, 'python', imports);

    expect(regs).toHaveLength(2);
    const routeReg = regs.find(r => r.kind === 'http_route');
    expect(routeReg).toBeDefined();
    expect(routeReg!.framework).toBe('flask');
    expect(routeReg!.registrar.method).toBe('route');
    expect(routeReg!.path).toBe('/users/<id>');
    expect(routeReg!.handler.name).toBe('get_user');

    const authReg = regs.find(r => r.registrar.method === 'auth_required');
    expect(authReg).toBeDefined();
    expect(authReg!.kind).toBe('decorator');
    expect(authReg!.handler.name).toBe('get_user');
  });

  it('detects FastAPI-style @router.get', async () => {
    const code = `
from fastapi import APIRouter
router = APIRouter()

@router.get('/x')
async def x_handler():
    pass
`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');
    const regs = extractRuntimeRegistrations(tree, undefined, 'python', imports);

    expect(regs).toHaveLength(1);
    expect(regs[0].kind).toBe('http_route');
    expect(regs[0].registrar.method).toBe('get');
    expect(regs[0].registrar.receiver).toBe('router');
    expect(regs[0].path).toBe('/x');
    expect(regs[0].handler.name).toBe('x_handler');
  });

  it('classifies @app.before_request as middleware', async () => {
    const code = `
from flask import Flask
app = Flask(__name__)

@app.before_request
def hook():
    pass
`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');
    const regs = extractRuntimeRegistrations(tree, undefined, 'python', imports);

    expect(regs).toHaveLength(1);
    expect(regs[0].kind).toBe('middleware');
    expect(regs[0].registrar.method).toBe('before_request');
    expect(regs[0].registrar.receiver).toBe('app');
    expect(regs[0].handler.name).toBe('hook');
  });

  it('classifies @app.errorhandler(404) as event_listener', async () => {
    const code = `
from flask import Flask
app = Flask(__name__)

@app.errorhandler(404)
def not_found(err):
    return 'nf', 404
`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');
    const regs = extractRuntimeRegistrations(tree, undefined, 'python', imports);

    expect(regs).toHaveLength(1);
    expect(regs[0].kind).toBe('event_listener');
    expect(regs[0].registrar.method).toBe('errorhandler');
    expect(regs[0].registrar.receiver).toBe('app');
    expect(regs[0].handler.name).toBe('not_found');
  });

  it('tags @pytest.fixture and @click.command() with their framework', async () => {
    const code = `
import pytest
import click

@pytest.fixture
def setup():
    pass

@click.command()
def main():
    pass
`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');
    const regs = extractRuntimeRegistrations(tree, undefined, 'python', imports);

    expect(regs).toHaveLength(2);
    const fixture = regs.find(r => r.handler.name === 'setup');
    expect(fixture).toBeDefined();
    expect(fixture!.kind).toBe('decorator');
    expect(fixture!.framework).toBe('pytest');
    expect(fixture!.registrar.method).toBe('fixture');

    const cmd = regs.find(r => r.handler.name === 'main');
    expect(cmd).toBeDefined();
    expect(cmd!.kind).toBe('decorator');
    expect(cmd!.framework).toBe('click');
    expect(cmd!.registrar.method).toBe('command');
  });

  it('tags @property as stdlib framework', async () => {
    const code = `
class Foo:
    @property
    def x(self):
        return 1
`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');
    const regs = extractRuntimeRegistrations(tree, undefined, 'python', imports);

    expect(regs).toHaveLength(1);
    expect(regs[0].kind).toBe('decorator');
    expect(regs[0].framework).toBe('stdlib');
    expect(regs[0].registrar.method).toBe('property');
    expect(regs[0].handler.name).toBe('x');
  });

  it('handles bare unknown decorators with framework=unknown', async () => {
    const code = `
@my_custom_decorator
def custom_fn():
    pass
`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');
    const regs = extractRuntimeRegistrations(tree, undefined, 'python', imports);

    expect(regs).toHaveLength(1);
    expect(regs[0].kind).toBe('decorator');
    expect(regs[0].framework).toBe('unknown');
    expect(regs[0].registrar.method).toBe('my_custom_decorator');
    expect(regs[0].handler.name).toBe('custom_fn');
  });

  it('handles async function decorators', async () => {
    const code = `
from fastapi import FastAPI
app = FastAPI()

@app.post('/items')
async def create_item(payload):
    return payload
`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');
    const regs = extractRuntimeRegistrations(tree, undefined, 'python', imports);

    expect(regs).toHaveLength(1);
    expect(regs[0].kind).toBe('http_route');
    expect(regs[0].registrar.method).toBe('post');
    expect(regs[0].path).toBe('/items');
    expect(regs[0].handler.name).toBe('create_item');
  });

  it('emits nothing for a plain undecorated function', async () => {
    const code = `
def plain():
    return 1
`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');
    const regs = extractRuntimeRegistrations(tree, undefined, 'python', imports);

    expect(regs).toHaveLength(0);
  });
});

describe('Runtime-Registrations Extractor — Phase 3 (Rust trait dispatch)', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('emits trait_impl for each method in an `impl Trait for Type` block', async () => {
    const code = `
trait Handler {
    fn handle(&self) -> String;
    fn name(&self) -> &str;
}

struct PingHandler;

impl Handler for PingHandler {
    fn handle(&self) -> String { String::from("pong") }
    fn name(&self) -> &str { "ping" }
}
`;
    const tree = await parse(code, 'rust');
    const regs = extractRuntimeRegistrations(tree, undefined, 'rust', []);

    expect(regs).toHaveLength(2);
    const names = regs.map(r => r.handler.name).sort();
    expect(names).toEqual(['handle', 'name']);
    for (const r of regs) {
      expect(r.kind).toBe('trait_impl');
      expect(r.framework).toBe('unknown');
      expect(r.registrar.receiver).toBe('PingHandler');
      expect(r.path).toBe('Handler');
    }
  });

  it('skips inherent impls (no trait field)', async () => {
    const code = `
struct Foo;

impl Foo {
    fn new() -> Self { Foo }
    fn run(&self) {}
}
`;
    const tree = await parse(code, 'rust');
    const regs = extractRuntimeRegistrations(tree, undefined, 'rust', []);

    expect(regs).toHaveLength(0);
  });

  it('tags stdlib traits by last-segment match', async () => {
    const code = `
use std::fmt::{self, Display, Debug};

struct Foo;

impl Display for Foo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "foo") }
}

impl Debug for Foo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "Foo") }
}

impl Iterator for Foo {
    type Item = u32;
    fn next(&mut self) -> Option<u32> { None }
}
`;
    const tree = await parse(code, 'rust');
    const regs = extractRuntimeRegistrations(tree, undefined, 'rust', []);

    expect(regs).toHaveLength(3);
    for (const r of regs) {
      expect(r.framework).toBe('stdlib');
    }
    const paths = regs.map(r => r.path).sort();
    expect(paths).toEqual(['Debug', 'Display', 'Iterator']);
  });

  it('tags scoped stdlib trait paths (`std::fmt::Display`) as stdlib', async () => {
    const code = `
struct Bar;

impl std::fmt::Display for Bar {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, "bar") }
}
`;
    const tree = await parse(code, 'rust');
    const regs = extractRuntimeRegistrations(tree, undefined, 'rust', []);

    expect(regs).toHaveLength(1);
    expect(regs[0].framework).toBe('stdlib');
    // We keep the *last* segment as `path` for convenience.
    expect(regs[0].path).toBe('Display');
  });

  it('tags actix_web::FromRequest as actix framework', async () => {
    const code = `
struct MyExtractor;

impl actix_web::FromRequest for MyExtractor {
    type Error = actix_web::Error;
    type Future = futures::future::Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        futures::future::ready(Ok(MyExtractor))
    }
}
`;
    const tree = await parse(code, 'rust');
    const regs = extractRuntimeRegistrations(tree, undefined, 'rust', []);

    expect(regs).toHaveLength(1);
    expect(regs[0].framework).toBe('actix');
    expect(regs[0].registrar.method).toBe('from_request');
    expect(regs[0].registrar.receiver).toBe('MyExtractor');
    expect(regs[0].path).toBe('FromRequest');
    expect(regs[0].handler.name).toBe('from_request');
  });

  it('tags serde::Serialize as serde framework', async () => {
    const code = `
struct Payload;

impl serde::Serialize for Payload {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
        s.serialize_str("payload")
    }
}
`;
    const tree = await parse(code, 'rust');
    const regs = extractRuntimeRegistrations(tree, undefined, 'rust', []);

    expect(regs).toHaveLength(1);
    expect(regs[0].framework).toBe('serde');
    expect(regs[0].handler.name).toBe('serialize');
  });

  it('emits trait_impl for `inventory::submit! { Type::new(...) }`', async () => {
    const code = `
inventory::submit! {
    Plugin::new("ping")
}
`;
    const tree = await parse(code, 'rust');
    const regs = extractRuntimeRegistrations(tree, undefined, 'rust', []);

    expect(regs).toHaveLength(1);
    const r = regs[0];
    expect(r.kind).toBe('trait_impl');
    expect(r.framework).toBe('inventory');
    expect(r.registrar.method).toBe('submit');
    expect(r.registrar.receiver).toBe('inventory');
    expect(r.path).toBe('inventory::submit');
    // First identifier in the token tree
    expect(r.handler.name).toBe('Plugin');
  });

  it('emits trait_impl for `#[linkme::distributed_slice]` on a static item', async () => {
    const code = `
#[linkme::distributed_slice(REGISTRY)]
static REG_FOO: fn() -> u32 = foo_handler;

fn foo_handler() -> u32 { 42 }
`;
    const tree = await parse(code, 'rust');
    const regs = extractRuntimeRegistrations(tree, undefined, 'rust', []);

    expect(regs).toHaveLength(1);
    const r = regs[0];
    expect(r.kind).toBe('trait_impl');
    expect(r.framework).toBe('linkme');
    expect(r.registrar.method).toBe('distributed_slice');
    expect(r.registrar.receiver).toBe('linkme');
    expect(r.path).toBe('linkme::distributed_slice');
    expect(r.handler.name).toBe('REG_FOO');
  });

  it('accepts bare `#[distributed_slice]` (after `use linkme::distributed_slice;`)', async () => {
    const code = `
use linkme::distributed_slice;

#[distributed_slice(REGISTRY)]
fn foo_handler() -> u32 { 42 }
`;
    const tree = await parse(code, 'rust');
    const regs = extractRuntimeRegistrations(tree, undefined, 'rust', []);

    expect(regs).toHaveLength(1);
    expect(regs[0].framework).toBe('linkme');
    expect(regs[0].handler.name).toBe('foo_handler');
  });

  it('ignores unrelated attributes and macros', async () => {
    const code = `
#[derive(Debug, Clone)]
struct Foo;

#[cfg(test)]
fn test_thing() {}

println!("hi");
vec![1, 2, 3];
`;
    const tree = await parse(code, 'rust');
    const regs = extractRuntimeRegistrations(tree, undefined, 'rust', []);

    expect(regs).toHaveLength(0);
  });

  it('handles a mixed file with traits + macros + linkme together', async () => {
    const code = `
trait Plugin {
    fn name(&self) -> &str;
}

struct PingPlugin;

impl Plugin for PingPlugin {
    fn name(&self) -> &str { "ping" }
}

impl PingPlugin {
    fn new() -> Self { PingPlugin }
}

inventory::submit! {
    PingPlugin::new()
}

#[linkme::distributed_slice(PLUGINS)]
static REG: fn() = init_ping;

fn init_ping() {}
`;
    const tree = await parse(code, 'rust');
    const regs = extractRuntimeRegistrations(tree, undefined, 'rust', []);

    // 1 trait_impl method + 1 inventory + 1 linkme = 3 (inherent impl skipped)
    expect(regs).toHaveLength(3);
    const kinds = regs.map(r => `${r.framework}:${r.handler.name}`).sort();
    expect(kinds).toEqual([
      'inventory:PingPlugin',
      'linkme:REG',
      'unknown:name',
    ]);
  });
});
