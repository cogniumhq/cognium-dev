/**
 * cognium-dev #1347 — interop IL-77 safe py→node mirror (numeric fullmatch guard).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const countCmdi = (flows: Array<{ sink_type?: string; sanitized?: boolean }> | undefined) =>
  (flows ?? []).filter((f) => f.sink_type === 'command_injection' && !f.sanitized).length;

const SAFE_IL77 = `"""TN — expr numeric-allowlisted before crossing to node."""
import re
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/e")
def e():
    expr = request.args.get("expr", "")
    if not re.fullmatch(r"[0-9+\\-*/ ]+", expr):
        return "bad", 400
    subprocess.run(["node", "-e", "console.log(" + expr + ")"])
    return "ok"
`;

const TP_IL77 = `import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/e")
def e():
    expr = request.args.get("expr", "")
    subprocess.run(["node", "-e", "console.log(" + expr + ")"])
    return "ok"
`;

describe('#1347 interop IL-77 py→node', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TN — numeric re.fullmatch reject-guard before subprocess.run', async () => {
    const r = await analyze(SAFE_IL77, 'safe_interop_py_to_node.py', 'python');
    expect(countCmdi(r.taint?.flows)).toBe(0);
  });

  it('recall — unguarded expr still reaches command_injection', async () => {
    const r = await analyze(TP_IL77, 'interop_py_to_node.py', 'python');
    expect(countCmdi(r.taint?.flows)).toBeGreaterThanOrEqual(1);
  });
});