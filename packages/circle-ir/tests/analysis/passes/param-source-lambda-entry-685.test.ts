/**
 * cognium-dev #685 (first slice) — a narrow allow-list of framework entry-point
 * signatures keeps their parameter-sourced flows past the #292 gate:
 *
 *   - JS/TS AWS Lambda `handler(event, context[, callback])`, when the module
 *     exports it (`export`, `exports.handler = handler`,
 *     `module.exports = { handler }`, ...);
 *   - Python AWS Lambda `lambda_handler(event, context)` at module level.
 *
 * Matching is on the signature shape (name, exact parameter names, module
 * level, exported), never on file or fixture names. Everything else stays
 * gated: one-argument `handler(event)` / `handle(req)`, arbitrary parameters,
 * an allow-listed name that is not exported, class methods.
 *
 * The registered-callback shape (`client.on('message', (topic, payload) => …)`)
 * is already seeded by the network source patterns; it is pinned here so the
 * slice does not regress it, with its negatives.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';
import type { SupportedLanguage } from '../../../src/types/index.js';

async function paramFlows(code: string, file: string, lang: SupportedLanguage, sink = 'command_injection') {
  const ir = await analyze(code, file, lang);
  return (ir.taint.flows ?? []).filter(f => f.sink_type === sink);
}
const fires = async (code: string, file: string, lang: SupportedLanguage) =>
  (await paramFlows(code, file, lang)).length > 0;

beforeAll(async () => { await initAnalyzer(); });

const body = `  const target = event.cmd;
  exec("ls " + target);
`;
const js = (head: string, tail = '') => `const { exec } = require('child_process');
${head} {
${body}}
${tail}
`;

describe('#685 JS/TS Lambda handler(event, context) is an entry point', () => {
  it('export async function handler', async () => {
    expect(await fires(js('export async function handler(event, context)'), 'index.js', 'javascript')).toBe(true);
  });

  it('function handler + exports.handler = handler', async () => {
    expect(await fires(js('async function handler(event, context)', 'exports.handler = handler;'), 'fn.js', 'javascript')).toBe(true);
    expect(await fires(js('async function handler(event, context)', 'module.exports.handler = handler;'), 'fn.js', 'javascript')).toBe(true);
  });

  it('an export assignment at the end of the file with no trailing newline', async () => {
    const code = js('async function handler(event, context)').trimEnd() + '\nexports.handler = handler';
    expect(await fires(code, 'fn.js', 'javascript')).toBe(true);
  });

  it('module.exports = { handler } with a callback third parameter', async () => {
    expect(await fires(js('function handler(event, context, callback)', 'module.exports = { handler };'), 'fn.js', 'javascript')).toBe(true);
  });

  it('const arrow handler exported through exports.handler', async () => {
    const code = `const { exec } = require('child_process');
const handler = async (event, context) => {
${body}};
exports.handler = handler;
`;
    expect(await fires(code, 'svc.js', 'javascript')).toBe(true);
  });

  it('TypeScript: export const handler / export { handler }', async () => {
    const a = `import { exec } from 'child_process';
export const handler = async (event, context) => {
${body}};
`;
    const b = `import { exec } from 'child_process';
async function handler(event, context) {
${body}}
export { handler };
`;
    expect(await fires(a, 'main.ts', 'typescript')).toBe(true);
    expect(await fires(b, 'main.ts', 'typescript')).toBe(true);
  });

  it('safe twin: a constant command through the same handler stays clean', async () => {
    const code = `const { exec } = require('child_process');
exports.handler = async function handler(event, context) {
  exec('ls -l');
};
function handler2(event, context) { exec('ls -l'); }
module.exports.other = handler2;
`;
    expect(await fires(code, 'safe.js', 'javascript')).toBe(false);
  });

  it('a one-argument handler(event) / handle(req) stays gated', async () => {
    expect(await fires(js('function handler(event)', 'module.exports = { handler };'), 'a.js', 'javascript')).toBe(false);
    expect(await fires(js('function handle(event)', 'module.exports = { handle };'), 'a.js', 'javascript')).toBe(false);
    const req = `const { exec } = require('child_process');
function handle(req) { exec("ls " + req.cmd); }
module.exports = { handle };
`;
    expect(await fires(req, 'a.js', 'javascript')).toBe(false);
  });

  it('exported functions with arbitrary parameters stay gated', async () => {
    expect(await fires(js('function runJob(a, b)', 'module.exports = { runJob };'), 'a.js', 'javascript')).toBe(false);
    expect(await fires(js('function handler(a, b)', 'module.exports = { handler };'), 'a.js', 'javascript')).toBe(false);
    expect(await fires(js('function process(event, context)', 'module.exports = { process };'), 'a.js', 'javascript')).toBe(false);
  });

  it('an allow-listed name that is not exported stays gated', async () => {
    expect(await fires(js('function handler(event, context)'), 'a.js', 'javascript')).toBe(false);
    expect(await fires(js('function handler(event, context)', 'module.exports = { other: 1 };'), 'a.js', 'javascript')).toBe(false);
    expect(await fires(js('async function handler(event, context)', 'exports.main = main;'), 'a.js', 'javascript')).toBe(false);
  });

  it('a class method named handler is not the module entry point', async () => {
    const code = `const { exec } = require('child_process');
class Worker {
  handler(event, context) {
${body}  }
}
module.exports = { Worker, handler: 1 };
`;
    expect(await fires(code, 'a.js', 'javascript')).toBe(false);
  });
});

describe('#685 Python lambda_handler(event, context) is an entry point', () => {
  const py = (head: string) => `import os
import subprocess

${head}
    os.system(event)
    return {"statusCode": 200}
`;

  it('module-level lambda_handler keeps the flow', async () => {
    expect(await fires(py('def lambda_handler(event, context):'), 'app.py', 'python')).toBe(true);
    expect(await fires(py('async def lambda_handler(event, context):'), 'app.py', 'python')).toBe(true);
  });

  it('a renamed sink and file still fires', async () => {
    const code = `import subprocess

def lambda_handler(event, context):
    subprocess.call(event, shell=True)
`;
    expect(await fires(code, 'worker_fn.py', 'python')).toBe(true);
  });

  it('other signatures stay gated', async () => {
    expect(await fires(py('def lambda_handler(event):'), 'app.py', 'python')).toBe(false);
    expect(await fires(py('def process(event, context):'), 'app.py', 'python')).toBe(false);
    expect(await fires(py('def helper(a, b):').replace('os.system(event)', 'os.system(a)'), 'app.py', 'python')).toBe(false);
    expect(await fires(py('def lambda_handler(a, b):').replace('os.system(event)', 'os.system(a)'), 'app.py', 'python')).toBe(false);
  });

  it('a class method named lambda_handler stays gated', async () => {
    const code = `import os

class Svc:
    def lambda_handler(self, event, context):
        os.system(event)
`;
    expect(await fires(code, 'app.py', 'python')).toBe(false);
  });

  it('safe twin: a constant command stays clean', async () => {
    const code = `import os

def lambda_handler(event, context):
    os.system("ls -l")
`;
    expect(await fires(code, 'app.py', 'python')).toBe(false);
  });
});

describe('#685 registered message callback (already seeded; pinned)', () => {
  const mq = (event: string) => `const mqtt = require('mqtt');
const { exec } = require('child_process');
const client = mqtt.connect('mqtt://broker');
client.on('${event}', (topic, payload) => {
  exec(payload.toString());
});
`;
  it("client.on('message', cb) keeps the payload flow", async () => {
    expect(await fires(mq('message'), 'sub.js', 'javascript')).toBe(true);
  });
  it("client.on('connect', cb) is not a message source", async () => {
    expect(await fires(mq('connect'), 'sub.js', 'javascript')).toBe(false);
  });
  it('an unregistered (topic, payload) function stays gated', async () => {
    const code = `const { exec } = require('child_process');
function onMsg(topic, payload) { exec(payload.toString()); }
`;
    expect(await fires(code, 'sub.js', 'javascript')).toBe(false);
  });
});
