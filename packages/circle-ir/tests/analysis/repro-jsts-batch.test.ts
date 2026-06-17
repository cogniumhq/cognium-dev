/**
 * Repro for cognium-dev JS/TS batch (Sprint 10).
 *
 * Phase A — Verification-only regression guards for issues whose fixes were
 * already delivered by Sprint 6–9 widening but are still open in the tracker.
 *
 *   - #88.1 — `.jsx` file recognition: `eval(location.hash)` in a `.jsx`
 *     source must fire `code_injection`. (Was masked at the issue-author's
 *     site by `cognium.config.json include: src/**\/*.ts`.)
 *
 *   - #69    — `exec(req.query.*)` and friends in Node.js: inline member-
 *     expression source, local-var copy, and `req.body` member-expression
 *     source must all fire `command_injection`. Negative control: literal
 *     string argument must NOT fire.
 *
 * #88.3 (Go `text/template`) is already guarded by
 * `repro-issue-88.test.ts` and is intentionally not duplicated here.
 *
 * Phase B/C/D regression tests for the live 3.60.0 fixes (HTML script
 * `taint.flows` merge, TSX grammar swap, `dangerouslySetInnerHTML`,
 * `node-serialize.unserialize`, property-assignment DOM-XSS sinks,
 * prototype-pollution CWE-1321 re-tag) are appended below.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev JS/TS batch — Sprint 10', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const hasFlow = (
    flows: Array<{ sink_type?: string; sink_line?: number }> | undefined,
    sinkType: string,
    sinkLine?: number,
  ) =>
    (flows ?? []).some(
      (f) => f.sink_type === sinkType && (sinkLine === undefined || f.sink_line === sinkLine),
    );

  // ---------------------------------------------------------------------------
  // Phase A.1 — #88.1 `.jsx` file recognition (stale-close)
  // ---------------------------------------------------------------------------

  it('#88.1 — `.jsx` file with `eval(location.hash)` should fire code_injection', async () => {
    const code = `import React from 'react';
export function App() {
  const h = location.hash.slice(1);
  eval(h);
  return <div>x</div>;
}
`;
    const r = await analyze(code, 'App.jsx', 'javascript');
    expect(hasFlow(r.taint.flows, 'code_injection')).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // Phase A.2 — #69 `exec(req.query.*)` (stale-close)
  // ---------------------------------------------------------------------------

  it('#69 case 1 — inline `exec(req.query.host)` should fire command_injection', async () => {
    const code = `const express = require('express');
const { exec } = require('child_process');
const app = express();
app.get('/x', (req, res) => {
  exec(req.query.host);
});
`;
    const r = await analyze(code, 'd1.js', 'javascript');
    expect(hasFlow(r.taint.flows, 'command_injection')).toBe(true);
  });

  it('#69 case 2 — local-var copy of `req.query.host` then `exec` should fire command_injection', async () => {
    const code = `const express = require('express');
const { exec } = require('child_process');
const app = express();
app.get('/x', (req, res) => {
  const h = req.query.host;
  exec('ping ' + h);
});
`;
    const r = await analyze(code, 'd2.js', 'javascript');
    expect(hasFlow(r.taint.flows, 'command_injection')).toBe(true);
  });

  it('#69 case 3 — inline `exec(req.body.cmd)` should fire command_injection', async () => {
    const code = `const express = require('express');
const { exec } = require('child_process');
const app = express();
app.post('/x', (req, res) => {
  exec(req.body.cmd);
});
`;
    const r = await analyze(code, 'd3.js', 'javascript');
    expect(hasFlow(r.taint.flows, 'command_injection')).toBe(true);
  });

  it('#69 negative control — `exec("ls")` should NOT fire command_injection', async () => {
    const code = `const { exec } = require('child_process');
exec('ls');
`;
    const r = await analyze(code, 'd_neg.js', 'javascript');
    expect(hasFlow(r.taint.flows, 'command_injection')).toBe(false);
  });

  // ---------------------------------------------------------------------------
  // Phase B — #80 HTML `<script>` taint flows propagated through merge
  // ---------------------------------------------------------------------------

  it('#80 — HTML embedded `<script>` with `document.write` should produce xss taint flow', async () => {
    const code = `<!doctype html>
<html>
<body>
<script>
  const q = new URLSearchParams(location.search).get('q');
  document.write('<p>' + q + '</p>');
</script>
</body>
</html>
`;
    const r = await analyze(code, 'page.html', 'html');
    expect(hasFlow(r.taint.flows, 'xss')).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // Phase C — #88.2 TSX/JSX grammar swap
  //
  // `tree-sitter-typescript` does NOT parse JSX. Prior to the per-extension
  // grammar selector, JSX-heavy `.tsx` files were partially parsed: any code
  // path located after the first JSX fragment was silently dropped because
  // the parser inserted an ERROR node and stopped collecting calls.
  // After the fix, `.tsx`/`.jsx` files route to `tree-sitter-tsx.wasm` which
  // is a JSX-aware superset.
  // ---------------------------------------------------------------------------

  it('#88.2 — `.tsx` with `eval(h)` BEFORE JSX should fire code_injection', async () => {
    const code = `import React from 'react';
export function App(props: { user: string }) {
  const h: string = location.hash.slice(1);
  eval(h);
  return (
    <div className="x">
      <span>{props.user}</span>
    </div>
  );
}
`;
    const r = await analyze(code, 'App.tsx', 'typescript');
    expect(hasFlow(r.taint.flows, 'code_injection')).toBe(true);
  });

  it('#88.2 — `.jsx` with arrow fn `eval(props.x)` inside JSX should fire code_injection', async () => {
    const code = `import React from 'react';
export function App(props) {
  const h = location.hash.slice(1);
  return <button onClick={() => eval(h)}>x</button>;
}
`;
    const r = await analyze(code, 'App2.jsx', 'javascript');
    expect(hasFlow(r.taint.flows, 'code_injection')).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // Phase D.1 — #68.1 `dangerouslySetInnerHTML` JSX sink
  // ---------------------------------------------------------------------------

  it('#68.1 — `<div dangerouslySetInnerHTML={{__html: tainted}}/>` should fire xss', async () => {
    const code = `import React from 'react';
export function App(props) {
  const h = props.location.hash.slice(1);
  return <div dangerouslySetInnerHTML={{ __html: h }} />;
}
`;
    const r = await analyze(code, 'Danger.jsx', 'javascript');
    expect(hasFlow(r.taint.flows, 'xss')).toBe(true);
  });

  it('#68.1 — `dangerouslySetInnerHTML` with literal HTML should NOT fire xss', async () => {
    const code = `import React from 'react';
export function App() {
  return <div dangerouslySetInnerHTML={{ __html: '<p>hello</p>' }} />;
}
`;
    const r = await analyze(code, 'Safe.jsx', 'javascript');
    expect(hasFlow(r.taint.flows, 'xss')).toBe(false);
  });

  // ---------------------------------------------------------------------------
  // Phase D.2 — #68.3 `node-serialize.unserialize` deserialization RCE
  // ---------------------------------------------------------------------------

  it('#68.3 — `serialize.unserialize(req.body.data)` should fire deserialization', async () => {
    const code = `const express = require('express');
const serialize = require('node-serialize');
const app = express();
app.post('/x', (req, res) => {
  const obj = serialize.unserialize(req.body.data);
  res.send(obj);
});
`;
    const r = await analyze(code, 'unser1.js', 'javascript');
    expect(hasFlow(r.taint.flows, 'deserialization')).toBe(true);
  });

  it('#68.3 — destructured `unserialize(req.body.data)` should fire deserialization', async () => {
    const code = `const express = require('express');
const { unserialize } = require('node-serialize');
const app = express();
app.post('/x', (req, res) => {
  unserialize(req.body.data);
});
`;
    const r = await analyze(code, 'unser2.js', 'javascript');
    expect(hasFlow(r.taint.flows, 'deserialization')).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // Phase D.3 — #68.4 DOM-XSS via `innerHTML`/`outerHTML` property assignment
  // ---------------------------------------------------------------------------

  it('#68.4 — `el.innerHTML = location.hash.slice(1)` should fire xss', async () => {
    const code = `function render() {
  const el = document.getElementById('out');
  el.innerHTML = location.hash.slice(1);
}
`;
    const r = await analyze(code, 'dom1.js', 'javascript');
    expect(hasFlow(r.taint.flows, 'xss')).toBe(true);
  });

  it('#68.4 — `el.outerHTML = req.query.x` (Express handler) should fire xss', async () => {
    const code = `const express = require('express');
const app = express();
app.get('/x', (req, res) => {
  const el = global.someElement;
  el.outerHTML = req.query.x;
  res.end();
});
`;
    const r = await analyze(code, 'dom2.js', 'javascript');
    expect(hasFlow(r.taint.flows, 'xss')).toBe(true);
  });

  it('#68.4 — `el.innerHTML = "<p>static</p>"` should NOT fire xss', async () => {
    const code = `function render() {
  const el = document.getElementById('out');
  el.innerHTML = '<p>static</p>';
}
`;
    const r = await analyze(code, 'dom_neg.js', 'javascript');
    expect(hasFlow(r.taint.flows, 'xss')).toBe(false);
  });

  // ---------------------------------------------------------------------------
  // Phase D.4 — #68.2 Prototype-pollution CWE re-tag (CWE-1321)
  // ---------------------------------------------------------------------------

  it('#68.2 — `_.merge({}, req.body)` should fire mass_assignment with CWE-1321', async () => {
    const code = `const express = require('express');
const _ = require('lodash');
const app = express();
app.post('/x', (req, res) => {
  const target = {};
  _.merge(target, req.body);
  res.json(target);
});
`;
    const r = await analyze(code, 'pp1.js', 'javascript');
    expect(hasFlow(r.taint.flows, 'mass_assignment')).toBe(true);
    const flow = (r.taint.flows ?? []).find(f => f.sink_type === 'mass_assignment');
    expect(flow).toBeDefined();
    // CWE is stamped on the corresponding sink, not on the flow itself —
    // verify the matching sink carries CWE-1321.
    const sink = (r.taint.sinks ?? []).find(s => s.type === 'mass_assignment');
    expect(sink?.cwe).toBe('CWE-1321');
  });

  it('#68.2 — `Object.assign({}, req.body)` should fire mass_assignment with CWE-1321', async () => {
    const code = `const express = require('express');
const app = express();
app.post('/x', (req, res) => {
  const target = {};
  Object.assign(target, req.body);
  res.json(target);
});
`;
    const r = await analyze(code, 'pp2.js', 'javascript');
    expect(hasFlow(r.taint.flows, 'mass_assignment')).toBe(true);
    const sink = (r.taint.sinks ?? []).find(s => s.type === 'mass_assignment');
    expect(sink?.cwe).toBe('CWE-1321');
  });

  it('#80 — HTML embedded `<script>` with `eval(location.hash)` should produce code_injection taint flow with HTML-space line', async () => {
    const code = `<!doctype html>
<html>
<body>
<script>
  eval(decodeURIComponent(location.hash.slice(1)));
</script>
</body>
</html>
`;
    const r = await analyze(code, 'page2.html', 'html');
    expect(hasFlow(r.taint.flows, 'code_injection')).toBe(true);
    // The eval is on HTML line 5 (1-indexed). Confirm the merge applied
    // the script block's lineOffset correctly.
    const codeInjFlow = (r.taint.flows ?? []).find(f => f.sink_type === 'code_injection');
    expect(codeInjFlow?.sink_line).toBe(5);
  });
});
