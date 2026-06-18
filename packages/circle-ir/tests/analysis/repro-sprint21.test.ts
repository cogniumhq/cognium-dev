/**
 * Repro for cognium-dev Sprint 21 — OOP safe-mirror sanitizer FP + SSRF FN
 * inversion (#105).
 *
 * Scope locked to the two FPs that the current engine still emits on the
 * safe OOP mirror corpus (FP-31 and FP-32) plus the corresponding negative
 * regression locks. The other safe-mirror FPs called out in #105
 * (FP-33 hardened-XML-parser, FP-34 EJS auto-escape) and the SSRF FN
 * inversion (FN-INV) were already suppressed/detected by the Sprint 16/18
 * machinery once the probe ran against `3.70.0` (see
 * `/tmp/sprint21_baseline.txt`); those fixtures are kept here as locks
 * against future regression but require no new code.
 *
 * Fixture map:
 *   FP-31 — allowlist-checked getter (`_checked()` with `raise`) → 0 ssrf
 *   GETTER.1-vuln — plain getter (no allowlist) → ≥1 ssrf (lock for B.1)
 *   GUARD.1-noisy — `if x in CACHE: return self.url` (no raise) → ≥1 ssrf (lock for B.1)
 *   FN-INV — direct `self.url` read → ≥1 ssrf (already passes; lock)
 *   FP-32 — `findOne({user: name})` value-bound dict → 0 nosql_injection
 *   NOSQL.2-vuln — `findOne(filter)` raw arg → ≥1 nosql_injection (lock for B.2)
 *   FP-33 — hardened lxml parser → 0 xxe (already passes; lock)
 *   FP-34 — EJS `<%= n %>` auto-escape → 0 xss/template_injection (already passes; lock)
 *
 * Target release: circle-ir 3.71.0 / cognium-dev 3.71.0.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev OOP safe-mirror precision — Sprint 21 (#105)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const flowsByType = (
    flows: Array<{ sink_type?: string; sanitized?: boolean }> | undefined,
    sinkType: string,
  ) => (flows ?? []).filter((f) => f.sink_type === sinkType && !f.sanitized);

  // ---------------------------------------------------------------------------
  // FP-31 — allowlist-checked getter must not be treated as a taint source.
  // ---------------------------------------------------------------------------

  it('#105 FP-31 — allowlist-checked _checked() getter should NOT fire ssrf', async () => {
    const code = `import requests

class HttpClient:
    ALLOWED = {'api.internal.example.com', 'cdn.example.com'}
    def __init__(self, url):
        self.url = url
    def _checked(self):
        if self.url not in self.ALLOWED:
            raise ValueError("host not allowed")
        return self.url
    def fetch(self):
        return requests.get(self._checked())
`;
    const r = await analyze(code, 'safe_oop_ssrf.py', 'python');
    expect(flowsByType(r.taint.flows, 'ssrf')).toEqual([]);
  });

  it('#105 GETTER.1-vuln — plain getter (no allowlist) should still fire ssrf', async () => {
    const code = `import requests

class HttpClient:
    def __init__(self, url):
        self.url = url
    def get_url(self):
        return self.url
    def fetch(self):
        return requests.get(self.get_url())
`;
    const r = await analyze(code, 'oop_ssrf_getter.py', 'python');
    expect(flowsByType(r.taint.flows, 'ssrf').length).toBeGreaterThanOrEqual(1);
  });

  it('#105 GUARD.1-noisy — `if x in CACHE: return self.url` (no raise) should still fire ssrf', async () => {
    // Cache-lookup shape, NOT an allowlist. The `in CACHE` check is a
    // membership test followed by a passthrough, not a rejection. B.1's
    // allowlist-guard recognition must require `raise`/`abort`/`return None`
    // within the guarded branch — this fixture lacks both, so the getter
    // remains a source.
    const code = `import requests

class HttpClient:
    CACHE = set()
    def __init__(self, url):
        self.url = url
    def _maybe_cached(self):
        if self.url in self.CACHE:
            return self.url
    def fetch(self):
        return requests.get(self._maybe_cached())
`;
    const r = await analyze(code, 'guard_noisy.py', 'python');
    expect(flowsByType(r.taint.flows, 'ssrf').length).toBeGreaterThanOrEqual(1);
  });

  // ---------------------------------------------------------------------------
  // FN-INV — direct `self.url` read on a constructor-injected field. The
  // existing Sprint 16 (#78) machinery already emits the field source and a
  // flow; this fixture locks that behavior so we don't regress when adding
  // B.1's allowlist-guard skip to the getter detector.
  // ---------------------------------------------------------------------------

  it('#105 FN-INV — direct `self.url` read must fire ssrf', async () => {
    const code = `import requests

class HttpClient:
    def __init__(self, url):
        self.url = url
    def fetch(self):
        return requests.get(self.url)
`;
    const r = await analyze(code, 'oop_ssrf.py', 'python');
    expect(flowsByType(r.taint.flows, 'ssrf').length).toBeGreaterThanOrEqual(1);
  });

  // ---------------------------------------------------------------------------
  // FP-32 — MongoDB value-bound filter must not be treated as nosql_injection.
  // ---------------------------------------------------------------------------

  it('#105 FP-32 — value-bound `{user: name}` filter should NOT fire nosql_injection', async () => {
    const code = `class UserRepo {
  constructor(db) { this.db = db; }
  async findByName(name) {
    return this.db.collection('users').findOne({ user: name });
  }
}
`;
    const r = await analyze(code, 'safe_oop_nosql.js', 'javascript');
    expect(flowsByType(r.taint.flows, 'nosql_injection')).toEqual([]);
  });

  it('#105 NOSQL.2-vuln — operator-injection-capable raw filter should still fire nosql_injection', async () => {
    const code = `class UserRepo {
  constructor(db) { this.db = db; }
  async findRaw(filter) {
    return this.db.collection('users').findOne(filter);
  }
}
`;
    const r = await analyze(code, 'oop_nosql.js', 'javascript');
    expect(flowsByType(r.taint.flows, 'nosql_injection').length).toBeGreaterThanOrEqual(1);
  });

  // ---------------------------------------------------------------------------
  // FP-33 / FP-34 — already-clean safe-mirror locks. Hardened lxml parser
  // and EJS `<%= %>` template currently produce 0 flows in the engine; this
  // suite locks that state.
  // ---------------------------------------------------------------------------

  it('#105 FP-33 — hardened lxml parser (resolve_entities=False) should NOT fire xxe', async () => {
    const code = `from lxml import etree

class XmlParser:
    def __init__(self):
        self.parser = etree.XMLParser(
            resolve_entities=False, no_network=True, load_dtd=False
        )
    def parse(self, src):
        return etree.parse(src, parser=self.parser)
`;
    const r = await analyze(code, 'safe_oop_xxe.py', 'python');
    expect(flowsByType(r.taint.flows, 'xxe')).toEqual([]);
  });

  it('#105 FP-34 — EJS `<%= n %>` auto-escape template should NOT fire xss', async () => {
    const code = `const ejs = require('ejs');
const TEMPLATE = '<p>Hello <%= n %></p>';
class Renderer {
  render(name) {
    return ejs.render(TEMPLATE, { n: name });
  }
}
`;
    const r = await analyze(code, 'safe_oop_ssti.js', 'javascript');
    expect(flowsByType(r.taint.flows, 'xss')).toEqual([]);
    expect(flowsByType(r.taint.flows, 'template_injection')).toEqual([]);
  });
});
