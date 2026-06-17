/**
 * Repro for cognium-dev Python batch (Sprint 12).
 *
 * Issues in scope:
 *   - #66 — Python FN sweep (zipfile/tarfile extractall, Flask
 *     send_from_directory, request.get_data, urllib.request.urlopen
 *     bare-import alias).
 *   - #59 — Boundary FN sweep (non-ASCII identifiers, single-line
 *     compound statements).
 *
 * Phase A — Stale-close regression guards (already work in 3.61.0):
 *   - #66.1b — `tarfile.open(tainted).extractall('/x')` → path_traversal flow
 *     fires on the `tarfile.open` sink (the new Phase B lowercase
 *     `extractall` sink will add a second flow but does not remove this).
 *   - #66.3b — `pickle.loads(request.data)` → deserialization flow.
 *   - #66.4b — `import urllib.request; urllib.request.urlopen(tainted)` → ssrf.
 *   - #59.2 — Single-line compound `def d(): q=...;os.system('echo '+q)` →
 *     command_injection.
 *
 * Phase B — Python `extractall` (lowercase) sink:
 *   - #66.1a — `zipfile.ZipFile(tainted).extractall('/x')` → path_traversal.
 *
 * Phase C — Flask `send_from_directory` sink:
 *   - #66.2 — `send_from_directory('/dir', tainted)` → path_traversal.
 *
 * Phase D — Flask method/property sources:
 *   - #66.3a — `pickle.loads(request.get_data())` → deserialization.
 *
 * Phase E — Bare imported function matches class-qualified pattern:
 *   - #66.4a — `from urllib.request import urlopen; urlopen(tainted)` → ssrf.
 *   - Negative — local function `def urlopen(...)` (no import) → no ssrf.
 *
 * Phase F — Non-ASCII identifier propagation:
 *   - #59.1 — `café = request.args.get(...); os.system('echo '+café)` →
 *     command_injection (matches ASCII baseline).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev Python batch — Sprint 12', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const hasFlow = (
    flows: Array<{ sink_type?: string; sink_line?: number; source_line?: number }> | undefined,
    sinkType: string,
    sinkLine?: number,
  ) =>
    (flows ?? []).some(
      (f) => f.sink_type === sinkType && (sinkLine === undefined || f.sink_line === sinkLine),
    );

  // ---------------------------------------------------------------------------
  // Phase A — Stale-close regression guards
  // ---------------------------------------------------------------------------

  it('#66.1b — `tarfile.open(tainted).extractall(...)` should fire path_traversal', async () => {
    const code = `from flask import request
import tarfile
def untar():
    path = request.args.get('p','')
    with tarfile.open(path) as tf:
        tf.extractall('/var/app/data')
`;
    const r = await analyze(code, 't66_1b.py', 'python');
    expect(hasFlow(r.taint.flows, 'path_traversal')).toBe(true);
  });

  it('#66.3b — `pickle.loads(request.data)` should fire deserialization', async () => {
    const code = `from flask import request
import pickle
def restore():
    return str(pickle.loads(request.data))
`;
    const r = await analyze(code, 't66_3b.py', 'python');
    expect(hasFlow(r.taint.flows, 'deserialization')).toBe(true);
  });

  it('#66.4b — `import urllib.request; urllib.request.urlopen(tainted)` should fire ssrf', async () => {
    const code = `from flask import request
import urllib.request
def proxy():
    return urllib.request.urlopen(request.args.get('url','')).read()
`;
    const r = await analyze(code, 't66_4b.py', 'python');
    expect(hasFlow(r.taint.flows, 'ssrf')).toBe(true);
  });

  it('#59.2 — single-line compound `def d(): q=...;os.system(...)` should fire command_injection', async () => {
    const code = `from flask import request
import os
def d(): q=request.args.get('q','');os.system('echo '+q)
`;
    const r = await analyze(code, 't59_2.py', 'python');
    expect(hasFlow(r.taint.flows, 'command_injection')).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // Phase B — Python lowercase `extractall` sink
  // ---------------------------------------------------------------------------

  it('#66.1a — `zipfile.ZipFile(tainted).extractall(...)` should fire path_traversal', async () => {
    const code = `from flask import request
import zipfile
def unzip():
    path = request.args.get('p','')
    with zipfile.ZipFile(path) as zf:
        zf.extractall('/var/app/data')
`;
    const r = await analyze(code, 't66_1a.py', 'python');
    expect(hasFlow(r.taint.flows, 'path_traversal')).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // Phase C — send_from_directory sink
  // ---------------------------------------------------------------------------

  it('#66.2 — `send_from_directory(\'/dir\', tainted)` should fire path_traversal', async () => {
    const code = `from flask import send_from_directory, request
def download():
    return send_from_directory('/var/app/files', request.args.get('f',''))
`;
    const r = await analyze(code, 't66_2.py', 'python');
    expect(hasFlow(r.taint.flows, 'path_traversal')).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // Phase D — Flask method/property sources
  // ---------------------------------------------------------------------------

  it('#66.3a — `pickle.loads(request.get_data())` should fire deserialization', async () => {
    const code = `from flask import request
import pickle
def restore():
    return str(pickle.loads(request.get_data()))
`;
    const r = await analyze(code, 't66_3a.py', 'python');
    expect(hasFlow(r.taint.flows, 'deserialization')).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // Phase E — bare imported function matches class-qualified pattern
  // ---------------------------------------------------------------------------

  it('#66.4a — `from urllib.request import urlopen; urlopen(tainted)` should fire ssrf', async () => {
    const code = `from flask import request
from urllib.request import urlopen
def proxy():
    return urlopen(request.args.get('url','')).read()
`;
    const r = await analyze(code, 't66_4a.py', 'python');
    expect(hasFlow(r.taint.flows, 'ssrf')).toBe(true);
  });

  it('#66.4a-neg — local function named `urlopen` (no import) should NOT fire ssrf', async () => {
    const code = `from flask import request
def urlopen(u):
    return u
def proxy():
    return urlopen(request.args.get('url',''))
`;
    const r = await analyze(code, 't66_4a_neg.py', 'python');
    expect(hasFlow(r.taint.flows, 'ssrf')).toBe(false);
  });

  // ---------------------------------------------------------------------------
  // Phase F — non-ASCII identifier propagation
  // ---------------------------------------------------------------------------

  it('#59.1-baseline — ASCII identifier `cafe` should fire command_injection', async () => {
    const code = `from flask import request
import os
def f():
    cafe = request.args.get('q','')
    os.system('echo ' + cafe)
`;
    const r = await analyze(code, 't59_1_baseline.py', 'python');
    expect(hasFlow(r.taint.flows, 'command_injection')).toBe(true);
  });

  it('#59.1 — non-ASCII identifier `café` should fire command_injection', async () => {
    const code = `from flask import request
import os
def f():
    café = request.args.get('q','')
    os.system('echo ' + café)
`;
    const r = await analyze(code, 't59_1.py', 'python');
    expect(hasFlow(r.taint.flows, 'command_injection')).toBe(true);
  });
});
