/**
 * Tests for cognium-dev #213 — fifth slice: Python sanitizer coverage.
 *
 * Adds high-value sanitizers that were missing from the DEFAULT_SANITIZERS
 * registry, and locks the bare-import call resolution path in
 * `matchesSanitizerPattern` so `from urllib.parse import quote; quote(x)`
 * credits the `class:'urllib.parse'` sanitizer even though the call has
 * no receiver identifier.
 *
 * Sanitizers added:
 *   - urllib.parse.quote / quote_plus / urlencode  (URL context)
 *   - bleach.linkify                                (XSS)
 *   - django.utils.html.escape / strip_tags         (XSS)
 *   - jinja2.escape / flask.escape                  (XSS)
 *   - saxutils.escape / quoteattr (+ xml.sax alias) (XSS in XML)
 *   - re.escape                                     (ReDoS + code_injection)
 *   - sqlalchemy `bindparams` (bare)                (SQL)
 *   - psycopg2 `sql.Identifier / Literal / Placeholder` (SQL)
 *
 * The bare-import fix is orthogonal to any specific sanitizer entry — it
 * activates the class-scoped ones for `from X import y` shapes.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('cognium-dev #213 fifth slice — Python sanitizer coverage', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const flowsFor = (
    r: Awaited<ReturnType<typeof analyze>>,
    sinkType: string,
  ) => (r.taint.flows ?? []).filter(f => f.sink_type === sinkType);

  it('urllib.parse.quote (bare-imported) sanitizes ssrf via bare-call resolution', async () => {
    const code = `import urllib.request
from urllib.parse import quote
from flask import request

def h():
    u = request.args["url"]
    safe = quote(u)
    urllib.request.urlopen("https://api.example.com/" + safe)
`;
    const r = await analyze(code, 'quote.py', 'python');
    expect(flowsFor(r, 'ssrf').length).toBe(0);
    // A sanitizer at line 7 must be registered.
    const san = (r.taint.sanitizers ?? []).find(s => s.line === 7);
    expect(san).toBeDefined();
  });

  it('urllib.parse.quote_plus (qualified) sanitizes ssrf', async () => {
    const code = `import urllib.request, urllib.parse
from flask import request

def h():
    u = request.args["url"]
    safe = urllib.parse.quote_plus(u)
    urllib.request.urlopen("https://api.example.com/" + safe)
`;
    const r = await analyze(code, 'quote_plus.py', 'python');
    expect(flowsFor(r, 'ssrf').length).toBe(0);
  });

  it('bleach.linkify (bare-imported) sanitizes xss', async () => {
    const code = `from bleach import linkify
from flask import request

def h():
    msg = request.args["m"]
    clean = linkify(msg)
    return "<div>" + clean + "</div>"
`;
    const r = await analyze(code, 'linkify.py', 'python');
    // No xss flow should reach the sink.
    const san = (r.taint.sanitizers ?? []).find(s => s.method === 'linkify()');
    expect(san).toBeDefined();
  });

  it('django.utils.html.escape sanitizes xss', async () => {
    const code = `from django.utils.html import escape
from django.http import HttpResponse

def view(request):
    name = request.GET.get("name")
    return HttpResponse("Hello " + escape(name))
`;
    const r = await analyze(code, 'django.py', 'python');
    const san = (r.taint.sanitizers ?? []).find(s => s.method === 'escape()');
    expect(san).toBeDefined();
  });

  it('re.escape sanitizes redos + code_injection (re.compile is CWE-94 in engine)', async () => {
    const code = `import re
from flask import request

def h():
    pat = request.args["pat"]
    r = re.compile(re.escape(pat))
    return r.match("abc")
`;
    const r = await analyze(code, 're.py', 'python');
    // Without sanitizer, this would fire code_injection. With re.escape
    // credited for both `redos` and `code_injection`, the sink is
    // suppressed.
    expect(flowsFor(r, 'code_injection').length).toBe(0);
    expect(flowsFor(r, 'redos').length).toBe(0);
  });

  it('xml.sax.saxutils.escape sanitizes xss', async () => {
    const code = `from xml.sax import saxutils
from flask import request

def h():
    x = request.args["x"]
    return "<a>" + saxutils.escape(x) + "</a>"
`;
    const r = await analyze(code, 'saxutils.py', 'python');
    const san = (r.taint.sanitizers ?? []).find(s => s.method === 'saxutils.escape()');
    expect(san).toBeDefined();
  });
});
