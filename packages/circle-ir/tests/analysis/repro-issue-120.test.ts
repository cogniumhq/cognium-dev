/**
 * Repro for cognium-dev#120 — Python sanitizer state dropped across
 * an intraprocedural pure-alias hop.
 *
 * Before the fix, the engine emitted a `path_traversal` flow for:
 *
 *   leaf_r = os.path.basename(request.args.get("f", ""))
 *   leaf   = leaf_r
 *   os.open(os.path.join(BASE, leaf), ...)
 *
 * The inline form (no alias hop) was correctly suppressed by the
 * #65 pt2 alias-sanitizer-coverage map, but the one-hop indirection
 * `leaf = leaf_r` re-emitted `leaf` as an unsanitized synthetic source
 * (no sanitizer call on line 9), so the suppression check at
 * sink-emission time missed and the FP escaped.
 *
 * Fix (taint-propagation-pass.ts, detectExpressionScanFlows): after
 * the existing #65 pt2 alias-sanitizer-coverage pass, run a fixpoint
 * that propagates `aliasSanitizedFor[upstream] -> aliasSanitizedFor[lhs]`
 * across pure `lhs = upstreamIdentifier` copies. Chains of arbitrary
 * length are handled.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#120 — sanitizer state dropped across alias hop', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const unsanitizedFlowsOfType = (
    flows: Array<{ sink_type?: string; sanitized?: boolean }> | undefined,
    sinkType: string,
  ) => (flows ?? []).filter((f) => f.sink_type === sinkType && !f.sanitized);

  it('inline form (baseline): basename + os.open in one expression — must NOT flag', async () => {
    const code = `import os
from flask import Flask, request
app = Flask(__name__)
BASE = "/var/app/data/"

@app.route("/w")
def w():
    leaf = os.path.basename(request.args.get("f", ""))
    fd = os.open(os.path.join(BASE, leaf), os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    return "ok"
`;
    const r = await analyze(code, 'inline.py', 'python');
    expect(unsanitizedFlowsOfType(r.taint.flows, 'path_traversal')).toEqual([]);
  });

  it('one-hop alias copy: leaf_r = basename(...); leaf = leaf_r; os.open(..., leaf) — must NOT flag', async () => {
    const code = `import os
from flask import Flask, request
app = Flask(__name__)
BASE = "/var/app/data/"

@app.route("/w")
def w():
    leaf_r = os.path.basename(request.args.get("f", ""))
    leaf = leaf_r
    fd = os.open(os.path.join(BASE, leaf), os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    return "ok"
`;
    const r = await analyze(code, 'alias.py', 'python');
    expect(unsanitizedFlowsOfType(r.taint.flows, 'path_traversal')).toEqual([]);
  });

  it('two-hop alias chain: a -> b -> c reaches sink — sanitization must still propagate', async () => {
    const code = `import os
from flask import Flask, request
app = Flask(__name__)
BASE = "/var/app/data/"

@app.route("/w")
def w():
    a = os.path.basename(request.args.get("f", ""))
    b = a
    c = b
    fd = os.open(os.path.join(BASE, c), os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    return "ok"
`;
    const r = await analyze(code, 'twohop.py', 'python');
    expect(unsanitizedFlowsOfType(r.taint.flows, 'path_traversal')).toEqual([]);
  });

  it('alias copy of shlex.quote chain: cmd = "ping " + shlex.quote(host); alias = cmd; subprocess.run(alias, shell=True) — must NOT flag', async () => {
    // Verifies the #65 pt2 mechanism inherits across alias hop for the
    // command_injection sink type, not just path_traversal.
    const code = `import shlex
import subprocess
from flask import request
def handler():
    host = request.args.get("host", "")
    cmd = "ping -c 3 " + shlex.quote(host)
    alias = cmd
    subprocess.run(alias, shell=True, capture_output=True, timeout=10)
`;
    const r = await analyze(code, 'alias_cmdi.py', 'python');
    expect(unsanitizedFlowsOfType(r.taint.flows, 'command_injection')).toEqual([]);
  });

  it('RECALL LOCK: unsanitized alias hop must STILL flag (no false suppression)', async () => {
    // Negative control: no sanitizer at all. The alias hop must NOT swallow
    // the genuine path_traversal flow.
    const code = `import os
from flask import Flask, request
app = Flask(__name__)
BASE = "/var/app/data/"

@app.route("/w")
def w():
    leaf_r = request.args.get("f", "")
    leaf = leaf_r
    fd = os.open(os.path.join(BASE, leaf), os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    return "ok"
`;
    const r = await analyze(code, 'recall.py', 'python');
    expect(unsanitizedFlowsOfType(r.taint.flows, 'path_traversal').length).toBeGreaterThan(0);
  });

  it('RECALL LOCK: re-tainting after sanitized alias must STILL flag', async () => {
    // After sanitization, a later assignment that re-injects raw taint
    // (`leaf = request.args.get(...)`) must restore unsafe state.
    const code = `import os
from flask import Flask, request
app = Flask(__name__)
BASE = "/var/app/data/"

@app.route("/w")
def w():
    leaf_r = os.path.basename(request.args.get("f", ""))
    leaf = leaf_r
    leaf = request.args.get("g", "")
    fd = os.open(os.path.join(BASE, leaf), os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    return "ok"
`;
    const r = await analyze(code, 'retaint.py', 'python');
    expect(unsanitizedFlowsOfType(r.taint.flows, 'path_traversal').length).toBeGreaterThan(0);
  });
});
