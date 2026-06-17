/**
 * Repro for cognium-dev#78 — OOP object flow.
 *
 * Constructor-injected fields and getter/property chains must propagate
 * taint to sinks in OTHER methods of the same class.
 *
 *   Java OopFlow:
 *     ctor: this.name = req.getParameter("u")
 *     5a — direct field read:        st.executeQuery("... " + this.name)
 *     5b — via getter:               st.executeQuery("... " + getName())
 *
 *   Python OopFlow:
 *     ctor: self.host = host  (host = request.args.get(...))
 *     5a — direct attribute:         os.system("... " + self.host)
 *     5b — via @property:            os.system("... " + self.target)
 *
 * All four must report a taint flow.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#78 — OOP constructor-injected field flow', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const hasSqliFlow = (flows: Array<{ sink_type?: string; sink_line?: number }> | undefined, sinkLine?: number) =>
    (flows ?? []).some(
      (f) => f.sink_type === 'sql_injection' && (sinkLine === undefined || f.sink_line === sinkLine),
    );

  const hasCmdFlow = (flows: Array<{ sink_type?: string; sink_line?: number }> | undefined, sinkLine?: number) =>
    (flows ?? []).some(
      (f) => f.sink_type === 'command_injection' && (sinkLine === undefined || f.sink_line === sinkLine),
    );

  it('Java 5a — direct `this.name` field read in sibling method should FIRE', async () => {
    const code = `import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;
public class OopFlow {
  private String name;
  private Statement st;
  public OopFlow(HttpServletRequest req, Statement st) {
    this.name = req.getParameter("u");
    this.st = st;
  }
  public String getName() { return this.name; }
  public void doDirect() throws Exception {
    st.executeQuery("SELECT * FROM users WHERE name = " + this.name);
  }
}
`;
    const r = await analyze(code, 'OopFlow.java', 'java');
    expect(hasSqliFlow(r.taint.flows, 12)).toBe(true);
  });

  it('Java 5b — getter call in sibling method should FIRE', async () => {
    const code = `import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;
public class OopFlow {
  private String name;
  private Statement st;
  public OopFlow(HttpServletRequest req, Statement st) {
    this.name = req.getParameter("u");
    this.st = st;
  }
  public String getName() { return this.name; }
  public void doGetter() throws Exception {
    st.executeQuery("SELECT * FROM users WHERE name = " + getName());
  }
}
`;
    const r = await analyze(code, 'OopFlow.java', 'java');
    expect(hasSqliFlow(r.taint.flows, 12)).toBe(true);
  });

  it('Python 5a — direct `self.host` attribute read in sibling method should FIRE', async () => {
    const code = `import os
from flask import request
class OopFlow:
    def __init__(self, host):
        self.host = host
    @property
    def target(self):
        return self.host
    def do_direct(self):
        os.system("echo " + self.host)
def make_and_run():
    host = request.args.get("host", "")
    f = OopFlow(host)
    f.do_direct()
`;
    const r = await analyze(code, 'oop_flow.py', 'python');
    expect(hasCmdFlow(r.taint.flows, 10)).toBe(true);
  });

  it('Python 5b — `@property` access in sibling method should FIRE', async () => {
    const code = `import os
from flask import request
class OopFlow:
    def __init__(self, host):
        self.host = host
    @property
    def target(self):
        return self.host
    def do_property(self):
        os.system("echo " + self.target)
def make_and_run():
    host = request.args.get("host", "")
    f = OopFlow(host)
    f.do_property()
`;
    const r = await analyze(code, 'oop_flow.py', 'python');
    expect(hasCmdFlow(r.taint.flows, 10)).toBe(true);
  });

  it('Python — non-getter method with non-field return should NOT yield a getter source', async () => {
    // Negative control: a method that returns something other than a
    // tainted field must not be treated as a getter for that field.
    const code = `import os
from flask import request
class OopFlow:
    def __init__(self, host):
        self.host = host
    def compute(self, x):
        return x + 1
    def do_compute(self):
        os.system("echo " + str(self.compute(0)))
def make_and_run():
    host = request.args.get("host", "")
    f = OopFlow(host)
    f.do_compute()
`;
    const r = await analyze(code, 'oop_flow_neg.py', 'python');
    expect(hasCmdFlow(r.taint.flows)).toBe(false);
  });
});
