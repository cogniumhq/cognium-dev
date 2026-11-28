/**
 * JS/TS cross-file taint through module helpers: a tainted value passed to a
 * function another module exports (CommonJS `exports.fn`, `module.exports`
 * objects and functions, ES named and default exports) reaches the sink in
 * that function, and a value the helper hands to a callback reaches the
 * sinks inside the callback. The call is resolved through the caller's
 * import of that module, so a same-named function in a different module is
 * not credited.
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

type File = [path: string, code: string];

const lang = (p: string) => (p.endsWith('.ts') ? 'typescript' : 'javascript') as 'typescript' | 'javascript';

async function project(files: File[]) {
  return analyzeProject(files.map(([filePath, code]) => ({ filePath, code, language: lang(filePath) })));
}

/** `source file:line -> sink file:line` of every command_injection cross-file path. */
async function cmdPaths(files: File[]): Promise<string[]> {
  const r = await project(files);
  return (r.taint_paths ?? [])
    .filter(p => p.sink.type === 'command_injection')
    .map(p => `${p.source.file}:${p.source.line}->${p.sink.file}:${p.sink.line}`);
}

/** `file:source->sink` of every per-file flow of `type`. */
async function flows(files: File[], type: string): Promise<string[]> {
  const r = await project(files);
  return r.files.flatMap(f => f.analysis.taint.flows
    .filter(x => x.sink_type === type)
    .map(x => `${f.file}:${x.source_line}->${x.sink_line}`));
}

const cjsRoute = (imports: string, call: string): string => `${imports}
const express = require('express');
const app = express();
app.get('/ping', (req, res) => {
  const host = req.query.host;
  ${call}
  res.send('ok');
});
`;

const esRoute = (imports: string, call: string): string => `${imports}
import express from 'express';
const app = express();
app.get('/ping', (req, res) => {
  const host = req.query.host;
  ${call}
  res.send('ok');
});
`;

const execHelper = (exportLine: string, close = '};'): string =>
  `const { exec } = require('child_process');\n${exportLine}\n  exec('ping -c 1 ' + a);\n${close}\n`;

describe('JS/TS cross-file taint through module helpers', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  describe('CommonJS exports', () => {
    it('`exports.fn = (…) => …` called through a destructured require', async () => {
      expect(await cmdPaths([
        ['src/app.js', cjsRoute("const { ping } = require('./ping');", 'ping(host);')],
        ['src/ping.js', execHelper('exports.ping = (a) => {')],
      ])).toEqual(['src/app.js:5->src/ping.js:3']);
    });

    it('`module.exports.fn = function …` called on the required module', async () => {
      expect(await cmdPaths([
        ['src/app.js', cjsRoute("const net = require('./net');", 'net.ping(host);')],
        ['src/net.js', execHelper('module.exports.ping = function (a) {')],
      ])).toEqual(['src/app.js:5->src/net.js:3']);
    });

    it('`module.exports = { fn }` and `module.exports = { fn: () => … }`', async () => {
      expect(await cmdPaths([
        ['src/app.js', cjsRoute("const { ping } = require('./net');", 'ping(host);')],
        ['src/net.js', "const { exec } = require('child_process');\nfunction ping(a) {\n  exec('ping -c 1 ' + a);\n}\nmodule.exports = { ping };\n"],
      ])).toEqual(['src/app.js:5->src/net.js:3']);
      expect(await cmdPaths([
        ['src/app.js', cjsRoute("const net = require('./net');", 'net.ping(host);')],
        ['src/net.js', "const { exec } = require('child_process');\nmodule.exports = {\n  ping: (a) => {\n    exec('ping -c 1 ' + a);\n  },\n};\n"],
      ])).toEqual(['src/app.js:5->src/net.js:4']);
    });

    it('`module.exports = function …` called as the required module', async () => {
      expect(await cmdPaths([
        ['src/app.js', cjsRoute("const ping = require('./ping');", 'ping(host);')],
        ['src/ping.js', execHelper('module.exports = function (a) {')],
      ])).toEqual(['src/app.js:5->src/ping.js:3']);
      expect(await cmdPaths([
        ['src/app.js', cjsRoute("const ping = require('./ping');", 'ping(host);')],
        ['src/ping.js', execHelper('module.exports = function doPing(a) {')],
      ])).toEqual(['src/app.js:5->src/ping.js:3']);
    });

    it('a renamed destructured binding (`const { fn: go } = require(…)`)', async () => {
      expect(await cmdPaths([
        ['src/app.js', cjsRoute("const { ping: go } = require('./ping');", 'go(host);')],
        ['src/ping.js', execHelper('exports.ping = (a) => {')],
      ])).toEqual(['src/app.js:5->src/ping.js:3']);
    });
  });

  describe('ES modules', () => {
    const tsHelper = (exportLine: string, close = '}'): string =>
      `import { exec } from 'child_process';\n${exportLine}\n  exec('ping -c 1 ' + a);\n${close}\n`;

    it('`export function fn` and `export const fn = () =>` through named imports', async () => {
      expect(await cmdPaths([
        ['src/app.ts', esRoute("import { ping } from './ping';", 'ping(host);')],
        ['src/ping.ts', tsHelper('export function ping(a: string) {')],
      ])).toEqual(['src/app.ts:5->src/ping.ts:3']);
      expect(await cmdPaths([
        ['src/app.ts', esRoute("import { ping as go } from './ping';", 'go(host);')],
        ['src/ping.ts', tsHelper('export const ping = (a: string) => {', '};')],
      ])).toEqual(['src/app.ts:5->src/ping.ts:3']);
    });

    it('`import * as ns` then `ns.fn(…)`', async () => {
      expect(await cmdPaths([
        ['src/app.ts', esRoute("import * as net from './net';", 'net.ping(host);')],
        ['src/net.ts', tsHelper('export const ping = (a: string) => {', '};')],
      ])).toEqual(['src/app.ts:5->src/net.ts:3']);
    });

    it('`export default function` through a default import, with or without a name', async () => {
      expect(await cmdPaths([
        ['src/app.ts', esRoute("import ping from './ping';", 'ping(host);')],
        ['src/ping.ts', tsHelper('export default function (a: string) {')],
      ])).toEqual(['src/app.ts:5->src/ping.ts:3']);
      expect(await cmdPaths([
        ['src/app.ts', esRoute("import run from './ping.js';", 'run(host);')],
        ['src/ping.ts', tsHelper('export default function doPing(a: string) {')],
      ])).toEqual(['src/app.ts:5->src/ping.ts:3']);
    });

    it('a re-export through an index module', async () => {
      expect(await cmdPaths([
        ['src/app.ts', esRoute("import { ping } from './net';", 'ping(host);')],
        ['src/net/index.ts', "export * from './ping';\n"],
        ['src/net/ping.ts', tsHelper('export function ping(a: string) {')],
      ])).toEqual(['src/app.ts:5->src/net/ping.ts:3']);
    });
  });

  describe('callbacks passed to the helper', () => {
    const app = (call: string, extra = ''): File => ['src/app.js', cjsRoute(
      `const { withHost } = require('./host');\nconst { exec } = require('child_process');${extra}`, call)];

    it('an inline callback receives the value the helper derives from the tainted argument', async () => {
      const files: File[] = [
        app("withHost(host, (err, h) => {\n    exec(`ping -c 1 ${h}`);\n  });"),
        ['src/host.js', 'exports.withHost = (value, cb) => {\n  const v = value.trim();\n  cb(null, v);\n};\n'],
      ];
      expect(await cmdPaths(files)).toEqual(['src/app.js:6->src/app.js:8']);
      // Reported on the caller like any other flow.
      expect(await flows(files, 'command_injection')).toContain('src/app.js:6->8');
    });

    it('a named function of the caller passed as the callback', async () => {
      expect(await cmdPaths([
        app('withHost(host, onHost);', '\nfunction onHost(h) {\n  exec(`ping -c 1 ${h}`);\n}'),
        ['src/host.js', 'exports.withHost = (value, cb) => {\n  cb(value);\n};\n'],
      ])).toEqual(['src/app.js:9->src/app.js:4']);
    });

    it('a callback the helper calls later (ES module, async callback)', async () => {
      expect(await cmdPaths([
        ['src/app.ts', esRoute("import { withHost } from './host';\nimport { exec } from 'child_process';",
          "withHost(host, async function (h: string) {\n    exec('ping -c 1 ' + h);\n  });")],
        ['src/host.ts', 'export function withHost(value: string, cb: (v: string) => void) {\n  setTimeout(() => cb(value), 1);\n}\n'],
      ])).toEqual(['src/app.ts:6->src/app.ts:8']);
    });

    it('NEGATIVE: a helper that calls back with a constant, a literal choice or a constant-table value', async () => {
      const call = "withHost(host, (h) => {\n    exec(`ping -c 1 ${h}`);\n  });";
      for (const helper of [
        "exports.withHost = (value, cb) => {\n  cb('localhost');\n};\n",
        "exports.withHost = (value, cb) => {\n  cb(value.length > 3 ? 'a.example' : 'b.example');\n};\n",
        "const HOSTS = { a: 'a.example', b: 'b.example' };\nexports.withHost = (key, cb) => {\n  cb(HOSTS[key]);\n};\n",
      ]) {
        expect(await cmdPaths([app(call), ['src/host.js', helper]])).toEqual([]);
      }
    });

    it('NEGATIVE: the value goes to another callback parameter than the one the sink reads', async () => {
      expect(await cmdPaths([
        app("withHost(host, (err, h) => {\n    exec(`ping -c 1 ${h}`);\n  });"),
        ['src/host.js', "exports.withHost = (value, cb) => {\n  cb(value, 'localhost');\n};\n"],
      ])).toEqual([]);
    });

    it('NEGATIVE: a callback whose sink does not read its parameter', async () => {
      expect(await cmdPaths([
        app("withHost(host, (h) => {\n    const dir = '/tmp';\n    exec(`ls ${dir}`);\n  });"),
        ['src/host.js', 'exports.withHost = (value, cb) => {\n  cb(value);\n};\n'],
      ])).toEqual([]);
    });
  });

  describe('negatives', () => {
    it('a helper that ignores its argument', async () => {
      expect(await cmdPaths([
        ['src/app.js', cjsRoute("const { ping } = require('./ping');", 'ping(host);')],
        ['src/ping.js', "const { exec } = require('child_process');\nexports.ping = (a) => {\n  exec('ping -c 1 localhost');\n};\n"],
      ])).toEqual([]);
    });

    it('a helper that checks its argument against an allow-list before the sink', async () => {
      const files: File[] = [
        ['src/app.js', cjsRoute("const { ping } = require('./ping');", 'ping(host);')],
        ['src/ping.js', "const { exec } = require('child_process');\nconst ALLOWED = ['a.example', 'b.example'];\nexports.ping = (a) => {\n  if (!ALLOWED.includes(a)) return;\n  exec('ping -c 1 ' + a);\n};\n"],
      ];
      expect(await cmdPaths(files)).toEqual([]);
      expect(await flows(files, 'command_injection')).toEqual([]);
    });

    it('an exported function called only with a constant, or not called at all', async () => {
      const helper = execHelper('exports.ping = (a) => {') + 'exports.size = (b) => b.length;\n';
      expect(await cmdPaths([
        ['src/app.js', cjsRoute("const { ping } = require('./ping');", "ping('localhost');")],
        ['src/ping.js', helper],
      ])).toEqual([]);
      const files: File[] = [
        ['src/app.js', cjsRoute("const { size } = require('./ping');", 'size(host);')],
        ['src/ping.js', helper],
      ];
      expect(await cmdPaths(files)).toEqual([]);
      expect(await flows(files, 'command_injection')).toEqual([]);
    });

    it('a same-named function in a module the caller does not import', async () => {
      for (const order of [0, 1]) {
        const files: File[] = [
          ['src/app.js', cjsRoute("const { ping } = require('./safe');", 'ping(host);')],
          ['src/safe.js', 'exports.ping = (a) => a.length;\n'],
          ['src/ping.js', execHelper('exports.ping = (a) => {')],
        ];
        if (order === 1) files.reverse();
        expect(await cmdPaths(files)).toEqual([]);
      }
    });

    it('a same-named function in a module the caller does not import, from a function caller', async () => {
      const ctrl = "const { run } = require('./safe');\n\nfunction handle(req) {\n  const c = req.body.c;\n  run(c);\n}\n\nmodule.exports = { handle };\n";
      for (const safe of ['exports.run = (a) => a.length;\n', 'function run(a) { return a.length; }\nmodule.exports = { run };\n']) {
        expect(await cmdPaths([
          ['src/ctrl.js', ctrl],
          ['src/safe.js', safe],
          ['src/h.js', "const { exec } = require('child_process');\nfunction run(a) {\n  exec(a);\n}\nmodule.exports = { run };\n"],
        ])).toEqual([]);
      }
    });
  });

  describe('reporting', () => {
    it('a resolved helper call is not also an external taint escape', async () => {
      const files: File[] = [
        ['src/app.js', cjsRoute("const { ping } = require('./ping');", 'ping(host);')],
        ['src/ping.js', execHelper('exports.ping = (a) => {')],
      ];
      expect(await flows(files, 'external_taint_escape')).toEqual([]);
      expect(await flows(files, 'command_injection')).toEqual(['src/ping.js:5->3']);
    });

    it('the helper-side finding is kept when the project has other classified handlers', async () => {
      const app = `const express = require('express');
const { runPing } = require('./ping');
const app = express();
app.get('/ping', (req, res) => {
  const host = req.query.host;
  runPing(host, (out) => res.send(out));
});
function health(req, res) {
  res.send('ok');
}
app.get('/health', health);
module.exports = app;
`;
      const ping = "const { exec } = require('child_process');\nexports.runPing = (host, cb) => {\n  exec(`ping -c 1 ${host}`, (err, stdout) => cb(stdout));\n};\n";
      expect(await flows([['src/app.js', app], ['src/ping.js', ping]], 'command_injection')).toEqual(['src/ping.js:5->3']);
    });
  });
});
