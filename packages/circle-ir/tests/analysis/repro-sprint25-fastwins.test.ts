/**
 * Repro for cognium-dev Sprint 25 "fast wins" — closes #112 and #111.
 *
 *   - **#112** (FN, CWE-331): `java.util.Random` used for security tokens
 *     was only flagged when the Random instance was a typed local variable
 *     (`Random r = new Random(); r.nextInt(...)`). The idiomatic
 *     **chained** form `new Random().nextInt(...)` was missed because for
 *     chained `new C().m()`, the Java IR emits `m` with `receiver_type=null`
 *     (the receiver is an expression, not a typed variable). Fix:
 *     weak-random-pass.ts now also matches when the receiver expression
 *     starts with `new Random(` or `new SplittableRandom(`.
 *
 *   - **#111** (FN, CWE-113): CRLF / header-injection sinks for Go and
 *     Python were not wired:
 *     - Go `w.Header().Set(k, v)` / `Add` sink patterns existed in
 *       config-loader.ts with `class: 'Header'`, but `receiverMightBeClass`
 *       didn't recognize `w.Header()` as a `Header` instance. Fix: extended
 *       `receiverMightBeClass` to also match the chained-method-call shape
 *       `<expr>.ClassName()`.
 *     - Python had no CRLF sinks at all. Fix: added `headers.set`/`add`/
 *       `setdefault`/`extend`/`__setitem__` and `set_cookie` sinks with
 *       `languages: ['python']` to config-loader.ts. Subscript assignment
 *       (`resp.headers['X-A'] = v`) is NOT covered because the IR does not
 *       emit subscript writes as calls — documented limitation.
 *
 * Target release: circle-ir 3.75.0 / cognium-dev 3.75.0.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev Sprint 25 fast wins (#112, #111)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const flowsByType = (
    flows: Array<{ sink_type?: string; sanitized?: boolean }> | undefined,
    sinkType: string,
  ) => (flows ?? []).filter((f) => f.sink_type === sinkType && !f.sanitized);

  // ---------------------------------------------------------------------------
  // #112 — java.util.Random weak-random
  // ---------------------------------------------------------------------------

  it('#112 Java — chained `new Random().nextInt()` fires weak-random', async () => {
    const code = `package com.demo;
import java.util.Random;
public class Tok {
  public int generate() {
    return new Random().nextInt(1000000);
  }
}
`;
    const r = await analyze(code, 'Tok.java', 'java');
    const wr = (r.findings ?? []).filter((f) => f.rule_id === 'weak-random');
    expect(wr.length).toBeGreaterThanOrEqual(1);
    expect(wr[0]?.line).toBe(5);
  });

  it('#112 Java — chained `new SplittableRandom().nextLong()` fires weak-random', async () => {
    const code = `package com.demo;
import java.util.SplittableRandom;
public class Tok2 {
  public long generate() {
    return new SplittableRandom().nextLong();
  }
}
`;
    const r = await analyze(code, 'Tok2.java', 'java');
    const wr = (r.findings ?? []).filter((f) => f.rule_id === 'weak-random');
    expect(wr.length).toBeGreaterThanOrEqual(1);
  });

  it('#112 Java — typed local `Random r; r.nextInt()` still fires (regression)', async () => {
    const code = `package com.demo;
import java.util.Random;
public class Tok3 {
  public int generate() {
    Random r = new Random();
    return r.nextInt(1000000);
  }
}
`;
    const r = await analyze(code, 'Tok3.java', 'java');
    const wr = (r.findings ?? []).filter((f) => f.rule_id === 'weak-random');
    expect(wr.length).toBeGreaterThanOrEqual(1);
  });

  it('#112 Java — SecureRandom does NOT fire (regression)', async () => {
    const code = `package com.demo;
import java.security.SecureRandom;
public class Tok4 {
  public int generate() {
    return new SecureRandom().nextInt(1000000);
  }
}
`;
    const r = await analyze(code, 'Tok4.java', 'java');
    const wr = (r.findings ?? []).filter((f) => f.rule_id === 'weak-random');
    expect(wr.length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // #111 — CRLF / header injection in Go
  // ---------------------------------------------------------------------------

  it('#111 Go — `w.Header().Set(k, tainted)` fires crlf', async () => {
    const code = `package main
import "net/http"
func H(w http.ResponseWriter, r *http.Request) {
  name := r.URL.Query().Get("n")
  w.Header().Set("X-Name", name)
}
`;
    const r = await analyze(code, 'h.go', 'go');
    expect(flowsByType(r.taint?.flows, 'crlf').length).toBeGreaterThanOrEqual(1);
  });

  it('#111 Go — `w.Header().Add(k, tainted)` fires crlf', async () => {
    const code = `package main
import "net/http"
func H(w http.ResponseWriter, r *http.Request) {
  name := r.URL.Query().Get("n")
  w.Header().Add("X-Name", name)
}
`;
    const r = await analyze(code, 'h.go', 'go');
    expect(flowsByType(r.taint?.flows, 'crlf').length).toBeGreaterThanOrEqual(1);
  });

  it('#111 Go — literal header value does NOT fire crlf (regression)', async () => {
    const code = `package main
import "net/http"
func H(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("X-Name", "constant")
}
`;
    const r = await analyze(code, 'h.go', 'go');
    expect(flowsByType(r.taint?.flows, 'crlf').length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // #111 — CRLF / header injection in Python
  // ---------------------------------------------------------------------------

  it('#111 Python — `resp.headers.set(k, tainted)` fires crlf', async () => {
    const code = `from flask import Flask, request, make_response
app = Flask(__name__)
@app.route('/h')
def h():
    name = request.args.get('name')
    resp = make_response('ok')
    resp.headers.set('X-Name', name)
    return resp
`;
    const r = await analyze(code, 'h.py', 'python');
    expect(flowsByType(r.taint?.flows, 'crlf').length).toBeGreaterThanOrEqual(1);
  });

  it('#111 Python — `resp.headers.add(k, tainted)` fires crlf', async () => {
    const code = `from flask import Flask, request, make_response
app = Flask(__name__)
@app.route('/h')
def h():
    name = request.args.get('name')
    resp = make_response('ok')
    resp.headers.add('X-Name', name)
    return resp
`;
    const r = await analyze(code, 'h.py', 'python');
    expect(flowsByType(r.taint?.flows, 'crlf').length).toBeGreaterThanOrEqual(1);
  });

  it('#111 Python — `resp.set_cookie(name, tainted)` fires crlf', async () => {
    const code = `from flask import Flask, request, make_response
app = Flask(__name__)
@app.route('/c')
def c():
    val = request.args.get('v')
    resp = make_response('ok')
    resp.set_cookie('session', val)
    return resp
`;
    const r = await analyze(code, 'c.py', 'python');
    expect(flowsByType(r.taint?.flows, 'crlf').length).toBeGreaterThanOrEqual(1);
  });

  it('#111 Python — literal header value does NOT fire crlf (regression)', async () => {
    const code = `from flask import Flask, make_response
app = Flask(__name__)
@app.route('/h')
def h():
    resp = make_response('ok')
    resp.headers.set('X-Name', 'constant')
    return resp
`;
    const r = await analyze(code, 'h.py', 'python');
    expect(flowsByType(r.taint?.flows, 'crlf').length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // Baseline regression: existing JS / Java CRLF still fires
  // ---------------------------------------------------------------------------

  it('regression — JS `res.setHeader(k, tainted)` still fires crlf', async () => {
    const code = `const express = require('express');
const app = express();
app.get('/h', (req, res) => {
  const name = req.query.name;
  res.setHeader('X-Name', name);
  res.end('ok');
});
`;
    const r = await analyze(code, 'h.js', 'javascript');
    expect(flowsByType(r.taint?.flows, 'crlf').length).toBeGreaterThanOrEqual(1);
  });

  it('regression — Java `response.setHeader(k, tainted)` still fires crlf', async () => {
    const code = `package com.demo;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class H {
  public void handle(HttpServletRequest req, HttpServletResponse resp) {
    String name = req.getParameter("name");
    resp.setHeader("X-Name", name);
  }
}
`;
    const r = await analyze(code, 'H.java', 'java');
    expect(flowsByType(r.taint?.flows, 'crlf').length).toBeGreaterThanOrEqual(1);
  });
});
