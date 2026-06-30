/**
 * Sprint 74 — #216 Pattern B (Python wrappers): 3 FPs
 *
 * Closes 3 of 12 remaining scorecard FPs from #216:
 *   - safe_sanitizer_wrapped_ldap.py: regex-allowlist wrapper function
 *   - safe_sanitizer_wrapped_ssti.py: set-membership allowlist guard (Jinja)
 *   - safe_sanitizer_wrapped_xxe.py: defusedxml import-alias recognition
 *
 * 9 Pattern-X (other-language) FPs remain on #216 after Sprint 74.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('#216 Sprint 74 — Python wrapper / allowlist / defusedxml sanitizers', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TN-1 — safe_sanitizer_wrapped_ldap.py: regex-fullmatch wrapper sanitizes ldap_injection + ETE', async () => {
    const code = [
      '"""c08 SAFE — custom wrapper x LDAP (CWE-90). Expect clean."""',
      'import re',
      'import ldap',
      'from flask import Flask, request, abort',
      '',
      'app = Flask(__name__)',
      '',
      '',
      'def checked_uid(uid):',
      '    if not re.fullmatch(r"[a-zA-Z0-9_-]+", uid):',
      '        abort(400)',
      '    return uid',
      '',
      '',
      '@app.route("/wrapped")',
      'def wrapped():',
      '    uid = checked_uid(request.args.get("uid", ""))',
      '    ldap.initialize("ldap://localhost").search_s("dc=ex", ldap.SCOPE_SUBTREE, "(uid=" + uid + ")")',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'safe_sanitizer_wrapped_ldap.py', 'python');
    const ldapi = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'ldap_injection',
    );
    const ete = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'external_taint_escape',
    );
    expect(ldapi.length).toBe(0);
    expect(ete.length).toBe(0);
  });

  it('TN-2 — safe_sanitizer_wrapped_ssti.py: set-membership allowlist guard sanitizes xss + ETE', async () => {
    const code = [
      '"""c08 SAFE — custom wrapper x SSTI (CWE-1336). Expect clean."""',
      'from flask import Flask, request, abort',
      'from jinja2 import Environment, BaseLoader',
      '',
      'app = Flask(__name__)',
      'env = Environment(loader=BaseLoader())',
      'ALLOWED = {"hello", "status"}',
      '',
      '',
      '@app.route("/wrapped")',
      'def wrapped():',
      '    t = request.args.get("t", "")',
      '    if t not in ALLOWED:',
      '        abort(403)',
      '    env.from_string("{{ " + t + " }}").render()',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'safe_sanitizer_wrapped_ssti.py', 'python');
    const xss = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'xss');
    const ete = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'external_taint_escape',
    );
    expect(xss.length).toBe(0);
    expect(ete.length).toBe(0);
  });

  it('TN-3 — safe_sanitizer_wrapped_xxe.py: defusedxml.ElementTree alias sanitizes xxe + ETE', async () => {
    const code = [
      '"""c08 SAFE — custom wrapper x XXE (CWE-611). Expect clean."""',
      'import defusedxml.ElementTree as ET',
      'from flask import Flask, request',
      '',
      'app = Flask(__name__)',
      '',
      '',
      '@app.route("/wrapped")',
      'def wrapped():',
      '    ET.fromstring(request.get_data())',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'safe_sanitizer_wrapped_xxe.py', 'python');
    const xxe = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'xxe');
    const ete = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'external_taint_escape',
    );
    expect(xxe.length).toBe(0);
    expect(ete.length).toBe(0);
  });

  it('TP-1 — regex-allowlist wrapper does NOT sanitize raw request var routed past wrapper', async () => {
    // Wrapper exists in file but the sink uses raw request.args.get directly,
    // bypassing the wrapper. ldap_injection must STILL fire.
    const code = [
      'import re',
      'import ldap',
      'from flask import Flask, request, abort',
      '',
      'app = Flask(__name__)',
      '',
      'def checked_uid(uid):',
      '    if not re.fullmatch(r"[a-zA-Z0-9_-]+", uid):',
      '        abort(400)',
      '    return uid',
      '',
      '@app.route("/unsafe")',
      'def unsafe():',
      '    raw = request.args.get("uid", "")',
      '    ldap.initialize("ldap://localhost").search_s("dc=ex", ldap.SCOPE_SUBTREE, "(uid=" + raw + ")")',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'tp_ldap.py', 'python');
    const ldapi = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'ldap_injection',
    );
    expect(ldapi.length).toBeGreaterThan(0);
  });

  it('TP-2 — netloc allowlist guard on var A does NOT sanitize unguarded var B at xss sink', async () => {
    // Allowlist guard fires on `t`, but the value flowing into Jinja is
    // an entirely different `q` that was never guarded. xss must STILL fire.
    const code = [
      'from flask import Flask, request, abort',
      'from jinja2 import Environment, BaseLoader',
      '',
      'app = Flask(__name__)',
      'env = Environment(loader=BaseLoader())',
      'ALLOWED = {"hello", "status"}',
      '',
      '@app.route("/ssti")',
      'def ssti():',
      '    t = request.args.get("t", "")',
      '    if t not in ALLOWED:',
      '        abort(403)',
      '    q = request.args.get("q", "")',
      '    env.from_string("{{ " + q + " }}").render()',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'tp_ssti.py', 'python');
    const xss = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'xss');
    expect(xss.length).toBeGreaterThan(0);
  });

  it('TP-3 — plain xml.etree.ElementTree alias does NOT sanitize xxe', async () => {
    // NOT defusedxml — must still fire xxe.
    const code = [
      'import xml.etree.ElementTree as ET',
      'from flask import Flask, request',
      '',
      'app = Flask(__name__)',
      '',
      '@app.route("/unsafe_xxe")',
      'def unsafe_xxe():',
      '    ET.fromstring(request.get_data())',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'tp_xxe.py', 'python');
    const xxe = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'xxe');
    expect(xxe.length).toBeGreaterThan(0);
  });
});
