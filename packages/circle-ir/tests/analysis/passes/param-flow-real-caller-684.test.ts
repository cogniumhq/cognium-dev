/**
 * cognium-dev #684 / #685 — request values that reach a sink through a local
 * helper stopped being reported after #292 gated parameter-only flows.
 *
 * Two mechanisms:
 *  1. A parameter seed claimed definitions a real source also reaches.
 *     `const passthru = async (v) => v;` seeded `passthru` itself, so
 *     `await passthru(req.query.x)` was credited to the parameter and then
 *     dropped as parameter-only. Real sources now win shared definitions, and
 *     a parameter seed covers the parameter binding only.
 *  2. A helper whose parameter (or constructor-injected field) is fed by a
 *     real source in the same file is not speculative. The gate keeps those
 *     flows; a helper called only with constants, or through a sanitizer,
 *     stays gated.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';
import type { SupportedLanguage } from '../../../src/types/index.js';

async function flows(code: string, file: string, lang: SupportedLanguage) {
  const ir = await analyze(code, file, lang);
  return ir.taint.flows ?? [];
}

const has = (fl: Awaited<ReturnType<typeof flows>>, sinkType: string) =>
  fl.some(f => f.sink_type === sinkType);

beforeAll(async () => {
  await initAnalyzer();
});

describe('#684 async / arrow passthrough credits the real source', () => {
  const vuln = `const express = require('express');
const https = require('https');
const app = express();
const passthru = async (v) => v;
app.get('/mirror', async (req, res) => {
  const target = req.query.target || '';
  const resolved = await passthru(target);
  https.get(resolved);
  res.end();
});
module.exports = app;
`;

  it('reports ssrf from the request read, not from the helper parameter', async () => {
    const fl = await flows(vuln, 'mirror_route.js', 'javascript');
    const ssrf = fl.filter(f => f.sink_type === 'ssrf');
    expect(ssrf.length).toBeGreaterThan(0);
    expect(ssrf.every(f => f.source_line === 6 && f.source_type !== 'interprocedural_param')).toBe(true);
  });

  it('safe twin: a constant through the same helper stays clean', async () => {
    const safe = vuln.replace("const target = req.query.target || '';", "const target = 'https://status.example.org/';");
    expect(has(await flows(safe, 'mirror_route_safe.js', 'javascript'), 'ssrf')).toBe(false);
  });

  it('safe twin: a non-async arrow helper given a constant stays clean', async () => {
    const safe = `const express = require('express');
const https = require('https');
const app = express();
const same = (v) => v;
app.get('/mirror', (req, res) => {
  res.set('Cache-Control', 'no-store');
  const u = same('https://status.example.org/');
  https.get(u);
  res.end(req.query.x ? 'a' : 'b');
});
module.exports = app;
`;
    expect(has(await flows(safe, 'mirror_const.js', 'javascript'), 'ssrf')).toBe(false);
  });
});

describe('#684 constructor-injected field fed by a request value', () => {
  const vuln = `const express = require('express');
const fs = require('fs');
const app = express();

class Attachment {
  constructor(name) { this.name = name; }
  get filePath() { return this.name; }
  load() { return fs.readFileSync(this.name); }
  loadViaGetter() { return fs.readFileSync(this.filePath); }
}

app.get('/attachment', (req, res) => {
  const a = new Attachment(req.query.name);
  res.send(a.load());
});
module.exports = app;
`;

  it('reports path_traversal for the field read and the getter read', async () => {
    const fl = await flows(vuln, 'attachment_route.js', 'javascript');
    const sinkLines = new Set(fl.filter(f => f.sink_type === 'path_traversal').map(f => f.sink_line));
    expect(sinkLines.has(8)).toBe(true);
    expect(sinkLines.has(9)).toBe(true);
  });

  it('safe twin: the class constructed with a constant stays clean', async () => {
    const safe = vuln.replace('new Attachment(req.query.name)', "new Attachment('/srv/static/terms.txt')");
    expect(has(await flows(safe, 'attachment_route_safe.js', 'javascript'), 'path_traversal')).toBe(false);
  });

  it('safe twin: a library class nobody constructs in the file stays clean', async () => {
    const lib = vuln.slice(0, vuln.indexOf("app.get('/attachment'")) + 'module.exports = { Attachment };\n';
    expect(has(await flows(lib, 'attachment_lib.js', 'javascript'), 'path_traversal')).toBe(false);
  });
});

describe('#685 san07: sink inside a callee, request value at the call site', () => {
  it('JavaScript: helper called with a request value fires', async () => {
    const code = `const express = require('express');
const { exec } = require('child_process');
const app = express();
function grepLog(term) { exec('grep ' + term + ' /var/log/app.log', () => {}); }
app.get('/search', (req, res) => {
  grepLog(String(req.query.term ?? ''));
  res.end('ok');
});
module.exports = app;
`;
    expect(has(await flows(code, 'log_search.js', 'javascript'), 'command_injection')).toBe(true);
    const safe = code.replace("grepLog(String(req.query.term ?? ''));", "grepLog('timeout');");
    expect(has(await flows(safe, 'log_search_safe.js', 'javascript'), 'command_injection')).toBe(false);
  });

  it('Python: request read passed inline fires; quoted or constant stays clean', async () => {
    const code = `from flask import Flask, request
import subprocess, shlex
app = Flask(__name__)
def grep_log(term): subprocess.call("grep " + term + " /var/log/app.log", shell=True)
@app.route("/search")
def search():
    grep_log(request.args.get("term", ""))
    return "ok"
`;
    expect(has(await flows(code, 'log_search.py', 'python'), 'command_injection')).toBe(true);
    const quoted = code.replace('grep_log(request.args.get("term", ""))', 'grep_log(shlex.quote(request.args.get("term", "")))');
    expect(has(await flows(quoted, 'log_search_quoted.py', 'python'), 'command_injection')).toBe(false);
    const constant = code.replace('grep_log(request.args.get("term", ""))', 'grep_log("timeout")');
    expect(has(await flows(constant, 'log_search_const.py', 'python'), 'command_injection')).toBe(false);
  });

  it('Python: a function handed to an executor with a request value fires', async () => {
    const code = `from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request
app = Flask(__name__)
workers = ThreadPoolExecutor(2)
def banner(name):
    return "<h1>" + name + "</h1>"
@app.route("/banner")
def show_banner():
    name = request.args.get("name", "")
    job = workers.submit(banner, name)
    return job.result()
`;
    expect(has(await flows(code, 'banner_job.py', 'python'), 'xss')).toBe(true);
    const safe = code.replace('job = workers.submit(banner, name)', 'job = workers.submit(banner, "Welcome")');
    expect(has(await flows(safe, 'banner_job_safe.py', 'python'), 'xss')).toBe(false);
  });
});

describe('#292 contract unchanged', () => {
  it('an exported helper with no caller in the file stays gated', async () => {
    const code = `const { exec } = require('child_process');
function grepLog(term) { exec('grep ' + term + ' /var/log/app.log', () => {}); }
module.exports = { grepLog };
`;
    expect(has(await flows(code, 'grep_helper.js', 'javascript'), 'command_injection')).toBe(false);
  });

  it('a request value in one argument does not feed a sibling parameter', async () => {
    const code = `const express = require('express');
const { exec } = require('child_process');
const app = express();
function tagged(label, mode) { exec('tool --mode ' + mode); }
app.post('/tag', (req, res) => {
  res.set('Cache-Control', 'no-store');
  tagged(req.body.label, 'fast');
  res.end();
});
module.exports = app;
`;
    expect(has(await flows(code, 'tagged_tool.js', 'javascript'), 'command_injection')).toBe(false);
    const vuln = code.replace("tagged(req.body.label, 'fast');", "tagged('x', req.body.mode);");
    expect(has(await flows(vuln, 'tagged_tool_vuln.js', 'javascript'), 'command_injection')).toBe(true);
  });

  it('a parameter fed only by another parameter stays gated', async () => {
    const code = `const { exec } = require('child_process');
function grepLog(term) { exec('grep ' + term, () => {}); }
function search(q) { grepLog(q); }
module.exports = { search };
`;
    expect(has(await flows(code, 'grep_chain.js', 'javascript'), 'command_injection')).toBe(false);
  });

  it('a call on another object does not feed a module function of the same name', async () => {
    const code = `const express = require('express');
const { exec } = require('child_process');
const app = express();
function send(cmd) { exec(cmd); }
app.get('/echo', (req, res) => {
  res.send(req.query.msg);
});
send('uptime');
`;
    expect(has(await flows(code, 'send_collision.js', 'javascript'), 'command_injection')).toBe(false);
    const vuln = code.replace("send('uptime');", "app.post('/run', (req, res) => { send(req.body.cmd); res.end(); });");
    expect(has(await flows(vuln, 'send_collision_vuln.js', 'javascript'), 'command_injection')).toBe(true);
  });

  it('a source-bound name in one function does not feed a same-named local elsewhere', async () => {
    const code = `const express = require('express');
const { exec } = require('child_process');
const app = express();
function runCmd(name) { exec('echo ' + name); }
app.get('/a', (req, res) => {
  const name = req.query.name;
  res.send(String(name).length);
});
function warm() {
  const name = 'static';
  runCmd(name);
}
warm();
`;
    expect(has(await flows(code, 'bound_collision.js', 'javascript'), 'command_injection')).toBe(false);
  });
});

describe('#684 review follow-ups: the real-caller key matches one call shape only', () => {
  it('a receiver-less call does not feed a class method of the same name', async () => {
    const code = `const express = require('express');
const { exec } = require('child_process');
const app = express();
class Mailer {
  send(cmd) {
    exec(cmd);
  }
}
function send(msg) { console.log(msg); }
app.get('/notify', (req, res) => {
  send(req.query.msg);
  res.end();
});
module.exports = { app, Mailer };
`;
    expect(has(await flows(code, 'mailer_collision.js', 'javascript'), 'command_injection')).toBe(false);
    // The method itself, called through an instance with the request value, still fires.
    const vuln = code.replace('send(req.query.msg);', 'new Mailer().send(req.query.msg);');
    expect(has(await flows(vuln, 'mailer_collision_vuln.js', 'javascript'), 'command_injection')).toBe(true);
  });

  it('a function passed to a call that never invokes it is not fed by later arguments', async () => {
    const code = `from flask import Flask, request
import audit
app = Flask(__name__)
def banner(name):
    return "<h1>" + name + "</h1>"
@app.route("/banner")
def show_banner():
    name = request.args.get("name", "")
    print(banner, name)
    audit.record(banner, name)
    return "ok"
`;
    expect(has(await flows(code, 'banner_passthrough.py', 'python'), 'xss')).toBe(false);
    // Handed to an executor that calls it with the request value: still fires.
    const vuln = code.replace('audit.record(banner, name)', 'loop.run_in_executor(None, banner, name)');
    expect(has(await flows(vuln, 'banner_executor.py', 'python'), 'xss')).toBe(true);
  });

  it('JavaScript: a function logged next to a request value stays gated', async () => {
    const code = `const express = require('express');
const { exec } = require('child_process');
const app = express();
function load(name) { exec('cat /srv/' + name); }
app.get('/peek', (req, res) => {
  console.log(load, req.query.name);
  res.end();
});
load('motd');
`;
    expect(has(await flows(code, 'load_logged.js', 'javascript'), 'command_injection')).toBe(false);
    const vuln = code.replace('console.log(load, req.query.name);', 'setImmediate(load, req.query.name);');
    expect(has(await flows(vuln, 'load_immediate.js', 'javascript'), 'command_injection')).toBe(true);
  });
});
