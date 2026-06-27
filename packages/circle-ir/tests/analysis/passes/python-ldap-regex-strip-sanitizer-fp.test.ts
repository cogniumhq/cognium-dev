/**
 * Tests for cognium-dev #216 sanitizer-wrapped FP cluster — Python
 * `ldap_injection` (CWE-90) FP suppression on wrapper functions that strip
 * LDAP filter metacharacters via `re.sub(r"[<class>]", "", param)`
 * (Stage 17 in `sink-filter-pass.ts`, Sprint 52).
 *
 * Recall locks:
 *   - `re.sub` with a wildcard pattern (no LDAP metachars) keeps firing
 *   - direct concat without any wrapper keeps firing
 *   - wrapper applied to a different variable than the sink keeps firing
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countLdapSinks = (sinks: Array<{ type?: string }> | undefined) =>
  (sinks ?? []).filter(s => s.type === 'ldap_injection').length;
const countLdapFlows = (flows: Array<{ sink_type?: string }> | undefined) =>
  (flows ?? []).filter(f => f.sink_type === 'ldap_injection').length;

describe('cognium-dev #216 — Python ldap_injection regex-strip wrapper FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ---------------------------------------------------------------------------
  // FP suppression — recognised wrapper shapes
  // ---------------------------------------------------------------------------

  it('FP — ldap_safe wrapper with all five LDAP metachars in re.sub class', async () => {
    const code = `import ldap
import re
from flask import Flask, request

app = Flask(__name__)
conn = ldap.initialize("ldap://dir.internal")
BASE_DN = "ou=people,dc=example,dc=com"


def ldap_safe(s):
    return re.sub(r"[()=*\\\\]", "", s)


@app.route("/wrapped")
def wrapped():
    user = ldap_safe(request.args.get("user", ""))
    conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, "(uid=" + user + ")")
`;
    const r = await analyze(code, 'sanitizer_combos_ldap.py', 'python');
    expect(countLdapSinks(r.taint?.sinks)).toBe(0);
    expect(countLdapFlows(r.taint?.flows)).toBe(0);
  });

  it('FP — built-in escape_filter_chars on sink line is recognised', async () => {
    const code = `import ldap
from ldap import escape_filter_chars
from flask import Flask, request

app = Flask(__name__)
conn = ldap.initialize("ldap://dir.internal")


@app.route("/safe")
def safe():
    user = request.args.get("user", "")
    conn.search_s("ou=people", ldap.SCOPE_SUBTREE, "(uid=" + escape_filter_chars(user) + ")")
`;
    const r = await analyze(code, 'builtin_escape.py', 'python');
    expect(countLdapSinks(r.taint?.sinks)).toBe(0);
    expect(countLdapFlows(r.taint?.flows)).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // Recall locks — patterns that must keep firing
  // ---------------------------------------------------------------------------

  it('recall — wildcard re.sub (no LDAP metachars) is NOT recognised as sanitizer', async () => {
    const code = `import ldap
import re
from flask import Flask, request

app = Flask(__name__)
conn = ldap.initialize("ldap://dir.internal")


def looks_safe(s):
    return re.sub(r"[.]", "", s)


@app.route("/sus")
def sus():
    user = looks_safe(request.args.get("user", ""))
    conn.search_s("ou=people", ldap.SCOPE_SUBTREE, "(uid=" + user + ")")
`;
    const r = await analyze(code, 'wildcard_re_sub.py', 'python');
    expect(countLdapFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('recall — direct concat without any wrapper still fires', async () => {
    const code = `import ldap
from flask import Flask, request

app = Flask(__name__)
conn = ldap.initialize("ldap://dir.internal")


@app.route("/raw")
def raw():
    user = request.args.get("user", "")
    conn.search_s("ou=people", ldap.SCOPE_SUBTREE, "(uid=" + user + ")")
`;
    const r = await analyze(code, 'raw_concat.py', 'python');
    expect(countLdapFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('recall — wrapper-internal re.sub on a different param does not suppress', async () => {
    const code = `import ldap
import re
from flask import Flask, request

app = Flask(__name__)
conn = ldap.initialize("ldap://dir.internal")


def ldap_safe(s):
    return re.sub(r"[()=*\\\\]", "", s)


@app.route("/bypass")
def bypass():
    user = request.args.get("user", "")
    _ = ldap_safe("ignored")
    conn.search_s("ou=people", ldap.SCOPE_SUBTREE, "(uid=" + user + ")")
`;
    const r = await analyze(code, 'wrong_var.py', 'python');
    expect(countLdapFlows(r.taint?.flows)).toBeGreaterThan(0);
  });
});
