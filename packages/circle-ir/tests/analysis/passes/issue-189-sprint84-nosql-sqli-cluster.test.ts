/**
 * Sprint 84 — #189 variant-regression: nosql + sqli cluster (12 cells).
 *
 * Engine inventory on 3.133.0 found 4 of 12 FN. Three new pattern detectors
 * close the directly-addressable FN cells:
 *
 *   A. go    `*mongo.Collection.{FindOne|Find|InsertOne|UpdateOne|DeleteOne|
 *            FindOneAndUpdate|Aggregate|...}(ctx, bson.M{...<taint>...})`
 *   B. java  `MongoCollection.{find|findOne|update*|insert*|delete*|aggregate|
 *            ...}(...,<servlet-request taint>,...)` (including Filters.eq /
 *            new Document arg shapes)
 *   C. py    `mongoengine __raw__={'$where': "<JS string concat with tainted
 *            request input>"}` — MongoDB $where JS-injection
 *
 * Two remaining FN cells are corpus-manifest mismatches (engine correctly
 * emits `nosql_injection`; corpus tagged them `sql_injection`):
 *   - js  `User.find({ $where: "this.name == '" + req.query.n + "'" })`
 *   - py  mongoengine `__raw__={"$where": ...}`
 * Both are tracked for manifest correction (Sprint 81 cell 5 precedent).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countNosql = (r: any) =>
  (r.findings ?? []).filter((f: any) => f.rule_id === 'nosql_injection').length;

const hasNosqlFlow = (r: any) =>
  ((r.taint?.flows ?? []) as any[]).some(
    (f) => f.sink_type === 'nosql_injection',
  );

const hasNosqlSignal = (r: any) =>
  hasNosqlFlow(r) || countNosql(r) > 0;

describe('#189 Sprint 84 — nosql + sqli cluster (3 pattern detectors)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // A. Go MongoDB driver
  // -------------------------------------------------------------------------
  it('A-TP go nosql — coll.FindOne(ctx, bson.M{...tainted}) fires', async () => {
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
      'var coll *mongo.Collection',
      '',
      'func handler(w http.ResponseWriter, r *http.Request) {',
      '  username := r.URL.Query().Get("u")',
      '  var result bson.M',
      '  _ = coll.FindOne(context.TODO(), bson.M{"username": username}).Decode(&result)',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'go_mongo.go', 'go');
    expect(hasNosqlSignal(r)).toBe(true);
  });

  it('A-TP2 go nosql — coll.UpdateOne(ctx, bson.M{"_id":id}, bson.M{"$set":body})', async () => {
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
      'var coll *mongo.Collection',
      '',
      'func update(w http.ResponseWriter, r *http.Request) {',
      '  id := r.URL.Query().Get("id")',
      '  body := r.FormValue("body")',
      '  _, _ = coll.UpdateOne(context.TODO(), bson.M{"_id": id}, bson.M{"$set": body})',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'go_update.go', 'go');
    expect(hasNosqlSignal(r)).toBe(true);
  });

  it('A-TN go nosql — literal-only filter does NOT fire', async () => {
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
      'var coll *mongo.Collection',
      '',
      'func handler(w http.ResponseWriter, r *http.Request) {',
      '  _ = r.URL.Query().Get("ignored")',
      '  _ = coll.FindOne(context.TODO(), bson.M{"username": "admin"})',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'go_mongo_literal.go', 'go');
    expect(hasNosqlSignal(r)).toBe(false);
  });

  // -------------------------------------------------------------------------
  // B. Java Mongo driver
  // -------------------------------------------------------------------------
  it('B-TP java nosql — users.find(eq("k", request.getParameter())) fires', async () => {
    const code = [
      'package com.example;',
      '',
      'import com.mongodb.client.MongoCollection;',
      'import org.bson.Document;',
      'import jakarta.servlet.http.HttpServletRequest;',
      'import jakarta.servlet.http.HttpServletResponse;',
      'import static com.mongodb.client.model.Filters.eq;',
      '',
      'public class FindUser {',
      '  private MongoCollection<Document> users;',
      '  public void doGet(HttpServletRequest request, HttpServletResponse response) {',
      '    String u = request.getParameter("u");',
      '    Document doc = users.find(eq("username", u)).first();',
      '  }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'FindUser.java', 'java');
    expect(hasNosqlSignal(r)).toBe(true);
  });

  it('B-TP2 java nosql — users.updateOne with tainted filter fires', async () => {
    const code = [
      'package com.example;',
      '',
      'import com.mongodb.client.MongoCollection;',
      'import org.bson.Document;',
      'import jakarta.servlet.http.HttpServletRequest;',
      'import jakarta.servlet.http.HttpServletResponse;',
      'import static com.mongodb.client.model.Filters.eq;',
      'import static com.mongodb.client.model.Updates.set;',
      '',
      'public class Upd {',
      '  private MongoCollection<Document> users;',
      '  public void doPost(HttpServletRequest request, HttpServletResponse response) {',
      '    String id = request.getParameter("id");',
      '    users.updateOne(eq("_id", id), set("seen", true));',
      '  }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'Upd.java', 'java');
    expect(hasNosqlSignal(r)).toBe(true);
  });

  it('B-TN java nosql — literal-only filter does NOT fire', async () => {
    const code = [
      'package com.example;',
      '',
      'import com.mongodb.client.MongoCollection;',
      'import org.bson.Document;',
      'import jakarta.servlet.http.HttpServletRequest;',
      'import jakarta.servlet.http.HttpServletResponse;',
      'import static com.mongodb.client.model.Filters.eq;',
      '',
      'public class LiteralFind {',
      '  private MongoCollection<Document> users;',
      '  public void doGet(HttpServletRequest request, HttpServletResponse response) {',
      '    String ignored = request.getParameter("ignored");',
      '    Document doc = users.find(eq("username", "admin")).first();',
      '  }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'LiteralFind.java', 'java');
    expect(hasNosqlSignal(r)).toBe(false);
  });

  // -------------------------------------------------------------------------
  // C. Python mongoengine __raw__={'$where': ...}
  // -------------------------------------------------------------------------
  it('C-TP py nosql — mongoengine $where with tainted concat fires', async () => {
    const code = [
      'from flask import Flask, request',
      'from mongoengine import Document, StringField',
      '',
      'app = Flask(__name__)',
      '',
      'class User(Document):',
      '    name = StringField()',
      '',
      "@app.route('/u')",
      'def find_user():',
      "    n = request.args.get('name')",
      '    docs = User.objects(__raw__={"$where": "this.name == \'" + n + "\'"})',
      '    return str(list(docs))',
      '',
    ].join('\n');
    const r = await analyze(code, 'mongoengine_where.py', 'python');
    expect(hasNosqlSignal(r)).toBe(true);
  });

  it('C-TP2 py nosql — $where with f-string tainted interpolation fires', async () => {
    const code = [
      'from flask import Flask, request',
      'from mongoengine import Document, StringField',
      '',
      'app = Flask(__name__)',
      '',
      'class User(Document):',
      '    name = StringField()',
      '',
      "@app.route('/u')",
      'def find_user():',
      "    n = request.args.get('name')",
      '    docs = User.objects(__raw__={"$where": f"this.name == \'{n}\'"})',
      '    return str(list(docs))',
      '',
    ].join('\n');
    const r = await analyze(code, 'mongoengine_where_fstr.py', 'python');
    expect(hasNosqlSignal(r)).toBe(true);
  });

  it('C-TN py nosql — $where with pure literal string does NOT fire', async () => {
    const code = [
      'from flask import Flask, request',
      'from mongoengine import Document, StringField',
      '',
      'app = Flask(__name__)',
      '',
      'class User(Document):',
      '    name = StringField()',
      '',
      "@app.route('/u')",
      'def find_user():',
      "    _ = request.args.get('ignored')",
      '    docs = User.objects(__raw__={"$where": "this.name == \'admin\'"})',
      '    return str(list(docs))',
      '',
    ].join('\n');
    const r = await analyze(code, 'mongoengine_where_literal.py', 'python');
    expect(hasNosqlSignal(r)).toBe(false);
  });
});
