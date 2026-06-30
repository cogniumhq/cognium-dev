/**
 * Sprint 73 — #216 Pattern A: external_taint_escape sanitizer-chain
 *                (JS/Java slice) + Pattern B bonus (JS wrappers).
 *
 * Closes 6 of 24 scorecard FPs from #216:
 *   - 4 Pattern A ETE FPs (Jackson readValue / JSON.parse /
 *     bcrypt.hash / csv '-prefix)
 *   - 2 Pattern B wrapper-fn FPs (esc(), redact())
 *
 * 2 TS fixtures (safe_interop_shell/sql_in_string.ts) deferred to
 * Sprint 73b (not in coggiyadmin corpus).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('#216 Sprint 73 — external_taint_escape sanitizer-chain', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('TN-1 — BenignJsonParse.java: mapper.readValue is ETE sanitizer', async () => {
    const code = [
      'package com.demo;',
      'import com.fasterxml.jackson.databind.ObjectMapper;',
      'public class BenignJsonParse {',
      '  private final ObjectMapper mapper = new ObjectMapper();',
      '  public Object parse(String raw) throws Exception {',
      '    return mapper.readValue(raw, Object.class);',
      '  }',
      '}',
    ].join('\n');
    const r: any = await analyze(code, 'BenignJsonParse.java', 'java');
    const ete = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'external_taint_escape');
    expect(ete.length).toBe(0);
  });

  it('TN-2 — safe_sanitizer_wrapped_deserialize.js: JSON.parse is ETE sanitizer', async () => {
    const code = [
      "'use strict';",
      "const express = require('express'); const app = express();",
      "app.post('/wrapped', express.raw({ type: '*/*' }), (req, res) => { JSON.parse(req.body.toString()); res.end('ok'); });",
      'module.exports = app;',
    ].join('\n');
    const r: any = await analyze(code, 'wrap.js', 'javascript');
    const ete = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'external_taint_escape');
    expect(ete.length).toBe(0);
  });

  it('TN-3 — safe_recoverable_password.js: bcrypt.hash is ETE sanitizer', async () => {
    const code = [
      "'use strict';",
      "const express = require('express'); const bcrypt = require('bcrypt');",
      'const app = express();',
      'app.use(express.json());',
      "app.post('/register', async (req, res) => {",
      '  const digest = await bcrypt.hash(req.body.password, 10);',
      '  res.json({ stored: digest });',
      '});',
      'module.exports = app;',
    ].join('\n');
    const r: any = await analyze(code, 'reg.js', 'javascript');
    const ete = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'external_taint_escape');
    expect(ete.length).toBe(0);
  });

  it("TN-4 — safe_csv_formula_injection.js: `'${name}` prefix is ETE sanitizer", async () => {
    const code = [
      "'use strict';",
      "const express = require('express'); const fs = require('fs');",
      'const app = express();',
      "app.get('/export', (req, res) => {",
      "  const name = req.query.name || '';",
      "  const safe = name ? `'${name}` : '';",
      "  fs.appendFileSync('/var/app/export.csv', safe + ',100\\n');",
      "  res.end('exported');",
      '});',
      'module.exports = app;',
    ].join('\n');
    const r: any = await analyze(code, 'csv.js', 'javascript');
    const ete = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'external_taint_escape');
    expect(ete.length).toBe(0);
  });

  it('TN-5 — safe_sanitizer_wrapped_xss.js: esc() wrapper sanitizes xss', async () => {
    const code = [
      "'use strict';",
      "const express = require('express'); const app = express();",
      "function esc(s) { return String(s).replace(/[&<>\"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c])); }",
      "app.get('/wrapped', (req, res) => { res.send(esc(req.query.q || '')); });",
      'module.exports = app;',
    ].join('\n');
    const r: any = await analyze(code, 'xss.js', 'javascript');
    const xss = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'xss');
    const ete = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'external_taint_escape');
    expect(xss.length).toBe(0);
    expect(ete.length).toBe(0);
  });

  it('TN-6 — safe_sanitizer_wrapped_loginj.js: redact() wrapper sanitizes log_injection', async () => {
    const code = [
      "'use strict';",
      "const express = require('express'); const app = express();",
      "function redact(s) { return String(s).replace(/[\\r\\n\\t]/g, '_'); }",
      "app.get('/wrapped', (req, res) => { console.log('user=%s', redact(req.query.user)); res.end('ok'); });",
      'module.exports = app;',
    ].join('\n');
    const r: any = await analyze(code, 'log.js', 'javascript');
    const li = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'log_injection');
    const ete = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'external_taint_escape');
    expect(li.length).toBe(0);
    expect(ete.length).toBe(0);
  });

  it('TP-control 1 — bcrypt.hash does NOT sanitize sql_injection sink', async () => {
    const code = [
      "const express = require('express'); const bcrypt = require('bcrypt'); const db = require('./db');",
      'const app = express(); app.use(express.json());',
      "app.post('/login', async (req, res) => {",
      '  const digest = await bcrypt.hash(req.body.password, 10);',
      '  const q = "SELECT * FROM users WHERE name=\'" + req.body.name + "\'";',
      '  db.query(q);',
      '  res.json({ digest });',
      '});',
    ].join('\n');
    const r: any = await analyze(code, 'login.js', 'javascript');
    const sqli = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'sql_injection');
    expect(sqli.length).toBeGreaterThanOrEqual(1);
  });

  it('TP-control 2 — JSON.parse does NOT sanitize command_injection sink', async () => {
    const code = [
      "const express = require('express'); const cp = require('child_process');",
      'const app = express(); app.use(express.json());',
      "app.post('/run', (req, res) => {",
      '  const cfg = JSON.parse(req.body.toString());',
      "  cp.exec('echo ' + req.query.cmd);",
      "  res.end('ok');",
      '});',
    ].join('\n');
    const r: any = await analyze(code, 'run.js', 'javascript');
    const cmd = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'command_injection');
    expect(cmd.length).toBeGreaterThanOrEqual(1);
  });

  it('TP-control 3 — csv prefix on var A does NOT sanitize raw var B at xss sink', async () => {
    const code = [
      "const express = require('express'); const fs = require('fs');",
      'const app = express();',
      "app.get('/x', (req, res) => {",
      "  const name = req.query.name || '';",
      "  const safe = name ? `'${name}` : '';",
      "  fs.appendFileSync('/var/app/export.csv', safe);",
      '  res.send(req.query.other);',
      '});',
    ].join('\n');
    const r: any = await analyze(code, 'mix.js', 'javascript');
    const xss = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'xss');
    expect(xss.length).toBeGreaterThanOrEqual(1);
  });
});
