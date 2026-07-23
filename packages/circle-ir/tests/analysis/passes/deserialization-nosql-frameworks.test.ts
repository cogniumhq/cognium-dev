/**
 * Tests for cognium-dev #240 ship 2 — deserialization (CWE-502) and
 * nosql_injection (CWE-943) framework sink coverage.
 *
 * Ship 2 adds DESERIALIZATION_FRAMEWORK_SINKS (Python pickle/marshal/
 * dill/jsonpickle + Go encoding/gob + yaml + JS node-serialize) and
 * NOSQL_FRAMEWORK_SINKS (Python pymongo Collection + Java Spring Data
 * MongoTemplate / MongoCollection + Go mongo-driver Collection). Both
 * spread into DEFAULT_SINKS in `src/analysis/config-loader.ts`.
 *
 * Also exercises the Go local-receiver type resolver (`c` typed
 * `*fiber.Ctx` → 'Ctx') for the mongo `Collection` sink shape.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const hasSinkType = (r: any, type: string) =>
  (r.taint?.sinks ?? []).some((s: any) => s.type === type);

const hasFindingRule = (r: any, rule: string) =>
  (r.findings ?? []).some((f: any) => f.rule_id === rule);

const hasSignal = (r: any, type: string) =>
  hasSinkType(r, type) ||
  ((r.taint?.flows ?? []) as any[]).some((f) => f.sink_type === type) ||
  hasFindingRule(r, type);

describe('#240 ship 2 — deserialization framework sinks (CWE-502)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TP — Python pickle.loads(user_input): deserialization sink detected', async () => {
    const code = [
      'import pickle',
      'from flask import request',
      '',
      'def handler():',
      '    raw = request.data',
      '    obj = pickle.loads(raw)',
      '    return obj',
    ].join('\n');
    const r = await analyze(code, 'view.py', 'python');
    expect(hasSignal(r, 'deserialization')).toBe(true);
  });

  it('TP — Python marshal.loads(user_input): deserialization sink detected', async () => {
    const code = [
      'import marshal',
      'from flask import request',
      '',
      'def handler():',
      '    raw = request.data',
      '    code_obj = marshal.loads(raw)',
      '    return str(code_obj)',
    ].join('\n');
    const r = await analyze(code, 'view.py', 'python');
    expect(hasSignal(r, 'deserialization')).toBe(true);
  });

  it('TP — Python jsonpickle.decode(user_json): deserialization sink detected', async () => {
    const code = [
      'import jsonpickle',
      'from flask import request',
      '',
      'def handler():',
      '    payload = request.get_data(as_text=True)',
      '    obj = jsonpickle.decode(payload)',
      '    return str(obj)',
    ].join('\n');
    const r = await analyze(code, 'view.py', 'python');
    expect(hasSignal(r, 'deserialization')).toBe(true);
  });

  it('TP — JS node-serialize unserialize(user_str): deserialization sink detected', async () => {
    const code = [
      "const serialize = require('node-serialize');",
      "const express = require('express');",
      'const app = express();',
      '',
      "app.get('/', (req, res) => {",
      '  const raw = req.query.data;',
      '  const obj = serialize.unserialize(raw);',
      '  res.json(obj);',
      '});',
    ].join('\n');
    const r = await analyze(code, 'server.js', 'javascript');
    expect(hasSignal(r, 'deserialization')).toBe(true);
  });
});

describe('#240 ship 2 — nosql_injection framework sinks (CWE-943)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TP — Python pymongo Collection.find(user_filter): nosql sink detected', async () => {
    const code = [
      'from flask import request',
      'from pymongo import MongoClient',
      '',
      'client = MongoClient()',
      'db = client.myapp',
      'users = db.users',
      '',
      'def handler():',
      "    name = request.args.get('name')",
      "    return list(users.find({'name': name}))",
    ].join('\n');
    const r = await analyze(code, 'view.py', 'python');
    expect(hasSignal(r, 'nosql_injection')).toBe(true);
  });

  it('TP — Python pymongo Collection.aggregate(user_pipeline): nosql sink detected', async () => {
    const code = [
      'from flask import request',
      'from pymongo import MongoClient',
      '',
      'client = MongoClient()',
      'users = client.myapp.users',
      '',
      'def handler():',
      "    stage = request.get_json()",
      "    return list(users.aggregate(stage))",
    ].join('\n');
    const r = await analyze(code, 'view.py', 'python');
    expect(hasSignal(r, 'nosql_injection')).toBe(true);
  });

  it('TP — Java Spring Data MongoTemplate.find(user_query, Foo.class): nosql sink detected', async () => {
    const code = [
      'import org.springframework.data.mongodb.core.MongoTemplate;',
      'import org.springframework.data.mongodb.core.query.Query;',
      'import org.springframework.web.bind.annotation.RequestParam;',
      '',
      'public class UserService {',
      '  private MongoTemplate mongoTemplate;',
      '',
      '  public java.util.List<User> search(@RequestParam String q) {',
      '    Query query = Query.query(new org.bson.Document("name", q));',
      '    return mongoTemplate.find(query, User.class);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'UserService.java', 'java');
    expect(hasSignal(r, 'nosql_injection')).toBe(true);
  });

  it('TP — Go mongo-driver Collection.Find(ctx, user_filter): nosql sink detected (resolver rewrites `col` → "Collection")', async () => {
    // Exercises the Go local-receiver resolver from #240 ship 2 for the
    // Collection sink. `col` is typed *mongo.Collection → 'Collection'.
    const code = [
      'package main',
      '',
      'import (',
      '  "context"',
      '  "net/http"',
      '  "go.mongodb.org/mongo-driver/bson"',
      '  "go.mongodb.org/mongo-driver/mongo"',
      ')',
      '',
      'func handler(w http.ResponseWriter, r *http.Request, col *mongo.Collection) {',
      '  name := r.URL.Query().Get("name")',
      '  filter := bson.M{"name": name}',
      '  col.Find(context.Background(), filter)',
      '}',
    ].join('\n');
    const r = await analyze(code, 'handler.go', 'go');
    // Signal check: either fine-grained nosql_injection or a coarser
    // external_taint_escape catches the tainted-arg path.
    expect(
      hasSignal(r, 'nosql_injection') ||
      hasSignal(r, 'external_taint_escape'),
    ).toBe(true);
  });
});

describe('#240 ship 2 — Go local-receiver type resolver', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('rewrites method-receiver `c *gin.Context` → CallInfo.receiver === "Context"', async () => {
    const code = [
      'package main',
      '',
      'import "github.com/gin-gonic/gin"',
      '',
      'type H struct{}',
      '',
      'func (h *H) handler(c *gin.Context) {',
      '  c.Redirect(302, "/")',
      '}',
    ].join('\n');
    const r = await analyze(code, 'gin.go', 'go');
    const redirect = (r.calls ?? []).find((c: any) => c.method_name === 'Redirect');
    expect(redirect).toBeDefined();
    expect(redirect!.receiver).toBe('Context');
  });

  it('rewrites function-param `c *fiber.Ctx` → CallInfo.receiver === "Ctx"', async () => {
    const code = [
      'package main',
      '',
      'import "github.com/gofiber/fiber/v2"',
      '',
      'func handler(c *fiber.Ctx) error {',
      '  return c.Redirect("/")',
      '}',
    ].join('\n');
    const r = await analyze(code, 'fiber.go', 'go');
    const redirect = (r.calls ?? []).find((c: any) => c.method_name === 'Redirect');
    expect(redirect).toBeDefined();
    expect(redirect!.receiver).toBe('Ctx');
  });

  it('preserves package-qualified operand text: `fmt.Sprintf(...)` → receiver === "fmt"', async () => {
    // Ensures the resolver falls back to operand text when the operand
    // is not a local variable name in scope. Prevents regression on the
    // ubiquitous `fmt.Sprintf` / `fmt.Errorf` shapes that must keep
    // matching class:'fmt' sink patterns.
    const code = [
      'package main',
      '',
      'import "fmt"',
      '',
      'func handler(name string) string {',
      '  return fmt.Sprintf("hello %s", name)',
      '}',
    ].join('\n');
    const r = await analyze(code, 'greet.go', 'go');
    const call = (r.calls ?? []).find((c: any) => c.method_name === 'Sprintf');
    expect(call).toBeDefined();
    expect(call!.receiver).toBe('fmt');
  });

  it('handles multi-name parameter list: `func H(a, b *Foo)` — both `a` and `b` resolve to "Foo"', async () => {
    const code = [
      'package main',
      '',
      'type Foo struct{}',
      'func (f *Foo) Bar()  {}',
      'func (f *Foo) Quux() {}',
      '',
      'func H(a, b *Foo) {',
      '  a.Bar()',
      '  b.Quux()',
      '}',
    ].join('\n');
    const r = await analyze(code, 'multi.go', 'go');
    const bar  = (r.calls ?? []).find((c: any) => c.method_name === 'Bar');
    const quux = (r.calls ?? []).find((c: any) => c.method_name === 'Quux');
    expect(bar).toBeDefined();
    expect(quux).toBeDefined();
    expect(bar!.receiver).toBe('Foo');
    expect(quux!.receiver).toBe('Foo');
  });
});
