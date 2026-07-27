/**
 * Tests for cognium-dev #266 — cross-file reassignment-clobber precision.
 *
 * The cross-file connectivity gates (`findCrossFileTaintFlows` and the
 * interprocedural walker in `findInterproceduralTaintPaths`) were
 * name-based: a tainted variable reassigned to an untainted value before a
 * cross-file call still connected, e.g.
 *
 *     String a = req.getParameter("x");  // tainted
 *     a = "safe";                         // reassigned to a constant
 *     helper.run(a);                      // FP: flow still emitted
 *
 * Fix (#266): a DFG-precise clobber check (`taintClobbered`) with a
 * line-anchored reachable-def set (`collectTaintReachable` /
 * `forwardReachableDefs`). When the DFG *positively proves* the matched
 * variable's reaching def at the call is a redefinition not derived from
 * the source, the flow is rejected. Keyed on the matched variable name so
 * it also covers expression args (Rust `&a`).
 *
 * Conservative by construction — it only removes flows the DFG disproves,
 * so genuine derived flows (a→b→c, `let cmd = q.get(...)`) are preserved.
 *
 * Python residual: Python's per-file DFG is empty, so the def-precise
 * check cannot fire; the Python reassign FP is deferred (needs Python
 * taint-model integration, not DFG) — see the `todo` below.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cognium-dev #266 — cross-file reassignment clobber', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const xfPaths = (r: Awaited<ReturnType<typeof analyzeProject>>, sinkFile: string) =>
    (r.taint_paths ?? []).filter(p =>
      ['http_param', 'http_body', 'http_query', 'http_path', 'http_header'].includes(p.source.type) &&
      p.sink.file === sinkFile,
    ).length;

  // ── Java ──────────────────────────────────────────────────────────────
  const jHelper = {
    code: `package app;
public class Helper { public void run(String a) throws Exception { Runtime.getRuntime().exec(a); } }`,
    filePath: 'Helper.java', language: 'java' as const,
  };

  it('Java — reassign-to-constant does NOT flow cross-file', async () => {
    const r = await analyzeProject([jHelper, {
      code: `package app;
import javax.servlet.http.HttpServletRequest;
public class C { Helper h = new Helper();
  public void handle(HttpServletRequest req) throws Exception {
    String a = req.getParameter("x");
    a = "safe";
    h.run(a);
  } }`, filePath: 'C.java', language: 'java',
    }]);
    expect(xfPaths(r, 'Helper.java')).toBe(0);
  });

  it('Java — multi-hop derivation (a→b→c) still flows cross-file', async () => {
    const r = await analyzeProject([jHelper, {
      code: `package app;
import javax.servlet.http.HttpServletRequest;
public class C { Helper h = new Helper();
  public void handle(HttpServletRequest req) throws Exception {
    String a = req.getParameter("x");
    String b = a;
    String c = b;
    h.run(c);
  } }`, filePath: 'C.java', language: 'java',
    }]);
    expect(xfPaths(r, 'Helper.java')).toBeGreaterThan(0);
  });

  // ── JavaScript ────────────────────────────────────────────────────────
  const jsHelper = {
    code: `import { exec } from 'child_process';\nexport function run(a) { exec(a); }`,
    filePath: 'helper.js', language: 'javascript' as const,
  };

  it('JS — reassign-to-constant does NOT flow cross-file', async () => {
    const r = await analyzeProject([jsHelper, {
      code: `import { run } from './helper';\nimport express from 'express';\nexport function handle(req) {\n  let a = req.query.x;\n  a = "safe";\n  run(a);\n}`,
      filePath: 'controller.js', language: 'javascript',
    }]);
    expect(xfPaths(r, 'helper.js')).toBe(0);
  });

  it('JS — derived (b = a) still flows cross-file', async () => {
    const r = await analyzeProject([jsHelper, {
      code: `import { run } from './helper';\nimport express from 'express';\nexport function handle(req) {\n  let a = req.query.x;\n  let b = a;\n  run(b);\n}`,
      filePath: 'controller.js', language: 'javascript',
    }]);
    expect(xfPaths(r, 'helper.js')).toBeGreaterThan(0);
  });

  // ── Rust (expression arg `&a`) ────────────────────────────────────────
  const rsHelper = {
    code: `use std::process::Command;\npub fn run(a: &str) { Command::new(a).spawn().unwrap(); }`,
    filePath: 'helper.rs', language: 'rust' as const,
  };

  it('Rust — reassign-to-constant does NOT flow cross-file (expression arg &a)', async () => {
    const r = await analyzeProject([rsHelper, {
      code: `mod helper;\nuse helper::run;\nuse actix_web::web;\nuse std::collections::HashMap;\npub async fn handle(q: web::Query<HashMap<String,String>>) {\n    let mut a = q.get("x").unwrap().clone();\n    a = "safe".to_string();\n    run(&a);\n}`,
      filePath: 'controller.rs', language: 'rust',
    }]);
    expect(xfPaths(r, 'helper.rs')).toBe(0);
  });

  it('Rust — derived (let v = q.get(...)) still flows cross-file', async () => {
    const r = await analyzeProject([rsHelper, {
      code: `mod helper;\nuse helper::run;\nuse actix_web::web;\nuse std::collections::HashMap;\npub async fn handle(q: web::Query<HashMap<String,String>>) {\n    let v = q.get("x").unwrap();\n    run(v);\n}`,
      filePath: 'controller.rs', language: 'rust',
    }]);
    expect(xfPaths(r, 'helper.rs')).toBeGreaterThan(0);
  });

  // ── Go ────────────────────────────────────────────────────────────────
  const goHelper = {
    code: `package main\nimport "os/exec"\nfunc run(a string) { exec.Command("sh","-c",a).Run() }`,
    filePath: 'helper.go', language: 'go' as const,
  };

  it('Go — reassign-to-constant does NOT flow cross-file', async () => {
    const r = await analyzeProject([goHelper, {
      code: `package main\nimport "net/http"\nfunc handle(r *http.Request) {\n    a := r.URL.Query().Get("x")\n    a = "safe"\n    run(a)\n}`,
      filePath: 'controller.go', language: 'go',
    }]);
    expect(xfPaths(r, 'helper.go')).toBe(0);
  });

  it('Go — derived (b := a) still flows cross-file', async () => {
    const r = await analyzeProject([goHelper, {
      code: `package main\nimport "net/http"\nfunc handle(r *http.Request) {\n    a := r.URL.Query().Get("x")\n    b := a\n    run(b)\n}`,
      filePath: 'controller.go', language: 'go',
    }]);
    expect(xfPaths(r, 'helper.go')).toBeGreaterThan(0);
  });

  // ── Python residual ───────────────────────────────────────────────────
  // Python's per-file DFG is empty, so the def-precise clobber check
  // cannot fire. The reassign FP persists and is deferred to a Python
  // taint-model integration (not DFG-based). Tracked on #266.
  it.todo('Python — reassign-to-constant should NOT flow cross-file (needs Python taint-model, no DFG)');
});
