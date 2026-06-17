/**
 * Repro for Sprint 13 (cognium-dev v3.63.0) — source-line accuracy + cross-file taint.
 *
 *   #70 — Taint-source line misattributed across methods. Two supplementary
 *         flow detectors in taint-propagation-pass.ts (`detectCollectionFlows`,
 *         `detectArrayElementFlows`) hardcoded `sources[0]`, so flows in the
 *         second/third method reported the first method's source line. Fixed
 *         by picking the closest preceding source whose line falls inside the
 *         same method scope as the sink (`call.in_method`).
 *
 *   #74 — Cross-file taint not tracked for Python. The cases below
 *         demonstrate that `analyzeProject()` already produces the expected
 *         cross-file `TaintPath` entries for source-in-controller /
 *         sink-in-helper layouts. Locked here as positive regression tests.
 *
 * NOTE: SAST regression fixtures — every example is either deliberately
 * vulnerable (must fire) or deliberately safe (must NOT fire). Do not "fix"
 * the fixtures.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze, analyzeProject } from '../../src/analyzer.js';

describe('Sprint 13 — cognium-dev v3.63.0 source-line accuracy + cross-file taint', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ===========================================================================
  // #70 — source-line attribution across methods (Java, single-file analyze)
  // ===========================================================================

  it('#70.1: three methods with distinct sources — each flow reports its own source line', async () => {
    const code = `package com.example;
import javax.servlet.http.*;
import java.sql.*;

public class MultiSource {

  public void handleHeader(HttpServletRequest req) throws Exception {
    String h = req.getHeader("X-User");
    Runtime.getRuntime().exec(h);
  }

  public void handleCookie(HttpServletRequest req) throws Exception {
    String c = req.getCookies()[0].getValue();
    Runtime.getRuntime().exec(c);
  }

  public void handleDb(ResultSet rs) throws Exception {
    String r = rs.getString("name");
    Runtime.getRuntime().exec(r);
  }
}
`;
    const r = await analyze(code, 'MultiSource.java', 'java');
    // Build a map from sink_line → source_line for the three exec calls.
    const flows = (r.taint.flows ?? []).filter(f => f.sink_type === 'command_injection');
    expect(flows.length).toBeGreaterThanOrEqual(3);

    // Each method's exec line should map to the source line *in the same method*.
    // Header (method 1):  source line 8,  sink line 9
    // Cookie (method 2):  source line 13, sink line 14
    // Db     (method 3):  source line 18, sink line 19
    const headerSink = flows.find(f => f.sink_line === 9);
    const cookieSink = flows.find(f => f.sink_line === 14);
    const dbSink     = flows.find(f => f.sink_line === 19);

    expect(headerSink, 'header sink at line 9 missing').toBeTruthy();
    expect(cookieSink, 'cookie sink at line 14 missing').toBeTruthy();
    expect(dbSink,     'db sink at line 19 missing').toBeTruthy();

    expect(headerSink!.source_line).toBe(8);
    // Bug #70: cookieSink.source_line was reported as 8 (header line).
    expect(cookieSink!.source_line).toBe(13);
    // Bug #70: dbSink.source_line was reported as 8 (header line).
    expect(dbSink!.source_line).toBe(18);
  });

  it('#70.2: two methods using the same header source — each flow uses its own call-site line', async () => {
    const code = `package com.example;
import javax.servlet.http.*;

public class TwoHeaders {

  public void first(HttpServletRequest req) throws Exception {
    String a = req.getHeader("X-A");
    Runtime.getRuntime().exec(a);
  }

  public void second(HttpServletRequest req) throws Exception {
    String b = req.getHeader("X-B");
    Runtime.getRuntime().exec(b);
  }
}
`;
    const r = await analyze(code, 'TwoHeaders.java', 'java');
    const flows = (r.taint.flows ?? []).filter(f => f.sink_type === 'command_injection');
    // first():  source 7, sink 8
    // second(): source 12, sink 13
    const f1 = flows.find(f => f.sink_line === 8);
    const f2 = flows.find(f => f.sink_line === 13);
    expect(f1).toBeTruthy();
    expect(f2).toBeTruthy();
    expect(f1!.source_line).toBe(7);
    // Bug #70: f2.source_line was reported as 7 (first method's header).
    expect(f2!.source_line).toBe(12);
  });

  it('#70.3: collection-flow detector reports the in-method source line, not the file-first source', async () => {
    const code = `package com.example;
import javax.servlet.http.*;
import java.util.*;

public class MapFlow {

  public void firstUnrelated(HttpServletRequest req) throws Exception {
    String h = req.getHeader("X-First");
    Runtime.getRuntime().exec(h);
  }

  public void mapPropagation(HttpServletRequest req) throws Exception {
    Map<String,String> m = new HashMap<>();
    m.put("k", req.getParameter("x"));
    Runtime.getRuntime().exec(m.get("k"));
  }
}
`;
    const r = await analyze(code, 'MapFlow.java', 'java');
    const flows = (r.taint.flows ?? []).filter(f => f.sink_type === 'command_injection');
    // firstUnrelated:   source line 8, sink line 9
    // mapPropagation:   source on line 14 (req.getParameter), sink line 15 (m.get)
    const fMap = flows.find(f => f.sink_line === 15);
    expect(fMap, 'map propagation flow missing').toBeTruthy();
    // Bug #70: fMap.source_line was reported as 8 (firstUnrelated's source).
    // After fix: the collection-flow detector picks a source inside mapPropagation.
    expect(fMap!.source_line).toBeGreaterThanOrEqual(13);
    expect(fMap!.source_line).toBeLessThanOrEqual(14);
  });

  // ===========================================================================
  // #74 — cross-file taint (Python, multi-file analyzeProject)
  // ===========================================================================

  it('#74.1: cross-file SQL injection — source in controller.py, sink in db_helper.py', async () => {
    const controller = `from flask import request
from db_helper import run_user_query

def index():
    name = request.args.get("name")
    return run_user_query(name)
`;
    const dbHelper = `import sqlite3

def run_user_query(name):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchall()
`;
    const result = await analyzeProject([
      { code: controller, filePath: 'controller.py', language: 'python' },
      { code: dbHelper,   filePath: 'db_helper.py',  language: 'python' },
    ]);

    const sqlPaths = result.taint_paths.filter(p => p.sink.type === 'sql_injection');
    expect(sqlPaths.length, 'expected at least one cross-file sql_injection taint path').toBeGreaterThanOrEqual(1);
    const xfile = sqlPaths.find(p => p.source.file === 'controller.py' && p.sink.file === 'db_helper.py');
    expect(xfile, 'expected source=controller.py / sink=db_helper.py').toBeTruthy();
  });

  it('#74.2: cross-file command injection — source in controller.py, sink in shell_helper.py', async () => {
    const controller = `from flask import request
from shell_helper import run_cmd

def echo():
    arg = request.args.get("arg")
    return run_cmd(arg)
`;
    const helper = `import os

def run_cmd(arg):
    os.system("echo " + arg)
`;
    const result = await analyzeProject([
      { code: controller, filePath: 'controller.py',   language: 'python' },
      { code: helper,     filePath: 'shell_helper.py', language: 'python' },
    ]);

    const cmdPaths = result.taint_paths.filter(p => p.sink.type === 'command_injection');
    expect(cmdPaths.length, 'expected at least one cross-file command_injection taint path').toBeGreaterThanOrEqual(1);
    const xfile = cmdPaths.find(p => p.source.file === 'controller.py' && p.sink.file === 'shell_helper.py');
    expect(xfile, 'expected source=controller.py / sink=shell_helper.py').toBeTruthy();
  });

});
