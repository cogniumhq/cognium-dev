/**
 * Repro for cognium-dev#83 — inline source expression loses taint.
 *
 * A taint **source used inline** (directly as a call/concat argument) is NOT
 * tracked; assigning it to a local variable first fixes it. Confirmed in three
 * languages with minimal controls (#83 acceptance):
 *
 *   Java   exec("echo " + req.getParameter("u"))          → MISS
 *   JS     eval(req.query.x)                              → MISS
 *   Python for p in request.args.getlist("p"): system(p)  → MISS
 *
 * NOTE: SAST regression fixtures — every literal handler below is *deliberately*
 * vulnerable so the detector can be measured. Do not "fix" the fixtures.
 *
 * Subsumes #76 (Python for-iterable inline case). Distinct from #77.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#83 — inline source expression loses taint (Java + JS + Python)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -----------------------------------------------------------------------
  // Java
  // -----------------------------------------------------------------------

  it('Java: exec("echo " + req.getParameter("u")) — inline source in concat arg should FIRE', async () => {
    const code = `
import javax.servlet.http.*;
public class Cmd extends HttpServlet {
  public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    Runtime.getRuntime().exec("echo " + req.getParameter("u"));
  }
}
`;
    const r = await analyze(code, 'Cmd.java', 'java');
    const ci = (r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection');
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });

  it('Java: exec(req.getParameter("u")) — bare inline source as sole arg should FIRE', async () => {
    const code = `
import javax.servlet.http.*;
public class Cmd2 extends HttpServlet {
  public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    Runtime.getRuntime().exec(req.getParameter("u"));
  }
}
`;
    const r = await analyze(code, 'Cmd2.java', 'java');
    const ci = (r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection');
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });

  it('Java control: var-first variant still fires (regression guard)', async () => {
    const code = `
import javax.servlet.http.*;
public class CmdOK extends HttpServlet {
  public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String u = req.getParameter("u");
    Runtime.getRuntime().exec("echo " + u);
  }
}
`;
    const r = await analyze(code, 'CmdOK.java', 'java');
    const ci = (r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection');
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });

  // -----------------------------------------------------------------------
  // JavaScript / TypeScript
  // -----------------------------------------------------------------------

  it('JS: eval(req.query.x) — inline property-access source should FIRE', async () => {
    const code = `
const express = require('express');
const app = express();
app.get('/x', (req, res) => {
  eval(req.query.x);
});
module.exports = app;
`;
    const r = await analyze(code, 'eval_inline.js', 'javascript');
    const code_inj = (r.taint.flows ?? []).filter((f) => f.sink_type === 'code_injection');
    expect(code_inj.length).toBeGreaterThanOrEqual(1);
  });

  it('JS: child_process.exec(req.body.cmd) — inline source in exec sink should FIRE', async () => {
    const code = `
const express = require('express');
const cp = require('child_process');
const app = express();
app.post('/run', (req, res) => {
  cp.exec(req.body.cmd, (e, out) => res.send(out));
});
module.exports = app;
`;
    const r = await analyze(code, 'exec_inline.js', 'javascript');
    const ci = (r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection');
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });

  // -----------------------------------------------------------------------
  // Python
  // -----------------------------------------------------------------------

  it('Python: os.system("echo " + request.args.get("u")) — inline source in concat should FIRE', async () => {
    const code = `
from flask import Flask, request
import os
app = Flask(__name__)

@app.route("/run")
def run():
    os.system("echo " + request.args.get("u"))
    return "ok"
`;
    const r = await analyze(code, 'sys_inline.py', 'python');
    const ci = (r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection');
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });

  it('Python: for p in request.args.getlist("p"): os.system(p) — inline for-iterable source (#76) should FIRE', async () => {
    const code = `
from flask import Flask, request
import os
app = Flask(__name__)

@app.route("/iter")
def iter_():
    for p in request.args.getlist("p"):
        os.system("echo " + p)
    return "ok"
`;
    const r = await analyze(code, 'for_inline.py', 'python');
    const ci = (r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection');
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });

  it('Python control: var-first variant still fires (regression guard)', async () => {
    const code = `
from flask import Flask, request
import os
app = Flask(__name__)

@app.route("/ok")
def ok():
    u = request.args.get("u")
    os.system("echo " + u)
    return "ok"
`;
    const r = await analyze(code, 'sys_var.py', 'python');
    const ci = (r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection');
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });
});
