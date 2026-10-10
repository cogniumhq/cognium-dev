/**
 * #593 — one over-long line must not zero the rest of the file.
 * A single-line bundle still returns an empty analysis (#460).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const LONG = 'A'.repeat(12_000);

function py(blob: string): string {
  return `import os
from flask import Flask
app = Flask(__name__)

@app.route('/before/<cmd>')
def before(cmd):
    os.system(cmd)
    return "ok"

${blob}

@app.route('/after/<cmd>')
def after(cmd):
    os.system(cmd)
    return "ok"
`;
}

async function commandFlows(code: string) {
  const ir = await analyze(code, 'app.py', 'python');
  const flows = (ir.taint.flows ?? []).filter(f => f.sink_type === 'command_injection');
  return { ir, flows };
}

describe('#593 — over-long line does not zero the file', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('keeps sinks on both sides of a long str literal', async () => {
    const { ir, flows } = await commandFlows(py(`blob = "${LONG}"`));
    expect(ir.calls.length).toBeGreaterThan(0);
    expect(flows.length).toBeGreaterThanOrEqual(2);
  });

  it('keeps sinks on both sides of a long bytes literal', async () => {
    const { ir, flows } = await commandFlows(py(`blob = b"${LONG}"`));
    expect(ir.calls.length).toBeGreaterThan(0);
    expect(flows.length).toBeGreaterThanOrEqual(2);
  });

  it('a multi-line literal of the same size still analyses', async () => {
    const body = Array.from({ length: 200 }, () => 'A'.repeat(60)).join('\n');
    const { ir, flows } = await commandFlows(py(`blob = """\n${body}\n"""`));
    expect(body.length).toBeGreaterThan(10_000);
    expect(ir.calls.length).toBeGreaterThan(0);
    expect(flows.length).toBeGreaterThanOrEqual(2);
  });
});
