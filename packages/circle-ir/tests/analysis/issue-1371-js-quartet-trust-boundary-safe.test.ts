/**
 * cognium-dev #1371 — flow-quartet `trust_boundary` / `privilege_escalation` js safe
 * mirrors (`javascript-vuln-demo` tier 1 and tier 3 shapes). Neither safe mirror
 * may report trust_boundary or privilege_escalation. The tier-1 mirror passes a
 * hardcoded session secret, so its one security finding is CWE-798 on that line:
 * a real hardcoded credential, not a trust-boundary false positive. With a
 * placeholder secret the same shapes are clean.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type R = Awaited<ReturnType<typeof analyze>>;

/** Security findings without the missing-header noise every Express handler gets. */
const security = (ir: R) =>
  (ir.findings ?? []).filter((f) => f.category === 'security' && !f.rule_id.startsWith('missing-'));

const boundaryFlows = (ir: R) =>
  (ir.taint.flows ?? []).filter(
    (f) => (f.sink_type === 'trust_boundary' || f.sink_type === 'privilege_escalation') && !f.sanitized,
  );

const tier1Safe = (secret: string) => `'use strict';
const express = require('express');
const session = require('express-session');
const app = express();
const ALLOWED = new Set(['user', 'viewer', 'admin']);
app.use(session({ secret: '${secret}' }));
app.get('/role', (req, res) => {
  const role = req.query.role;
  if (!ALLOWED.has(role)) return res.status(400).end('bad role');
  req.session.role = role;
  res.end('ok');
});
module.exports = app;
`;

const tier3TrustSafe = `'use strict';
const express = require('express');
const session = require('express-session');
const app = express();
const ALLOWED = new Set(['user', 'viewer']);
app.use(session({ secret: 'changeme' }));
app.get('/role', (req, res) => {
  const role = ALLOWED.has(req.query.role) ? req.query.role : 'user';
  req.session.role = role;
  res.end('ok');
});
module.exports = app;
`;

const tier3PrivSafe = `'use strict';
const express = require('express');
const session = require('express-session');
const app = express();
app.use(session({ secret: 'changeme' }));
app.get('/elevate', (req, res) => {
  if (!req.session.isStaff) {
    return res.status(403).end('forbidden');
  }
  req.session.role = 'admin';
  res.end('ok');
});
module.exports = app;
`;

describe('#1371 flow-quartet js trust_boundary / privilege_escalation safe mirrors', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('tier 1: allowlist guard, hardcoded secret — only CWE-798 on the secret line', async () => {
    const ir = await analyze(tier1Safe('dev'), 'v01_baseline_safe.js', 'javascript');
    expect(boundaryFlows(ir)).toEqual([]);
    const f = security(ir);
    expect(f.map((x) => [x.rule_id, x.cwe, x.line])).toEqual([['hardcoded-credential', 'CWE-798', 6]]);
  });

  it('tier 1: allowlist guard, placeholder secret — clean', async () => {
    const ir = await analyze(tier1Safe('changeme'), 'v01_baseline_safe.js', 'javascript');
    expect(boundaryFlows(ir)).toEqual([]);
    expect(security(ir)).toEqual([]);
  });

  it('tier 3: ternary allowlist before the session write — clean', async () => {
    const ir = await analyze(tier3TrustSafe, 'trust_boundary_safe.js', 'javascript');
    expect(boundaryFlows(ir)).toEqual([]);
    expect(security(ir)).toEqual([]);
  });

  it('tier 3: staff check before a constant role write — clean', async () => {
    const ir = await analyze(tier3PrivSafe, 'privilege_escalation_safe.js', 'javascript');
    expect(boundaryFlows(ir)).toEqual([]);
    expect(security(ir)).toEqual([]);
  });
});
