/**
 * cognium-dev #899 — JS LDAP filter passed as positional arg to client.search.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const ldapFindings = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'ldap_injection');

describe('cognium-dev #899 — JS LDAP positional filter', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TP: client.search(base, filterVar, cb) when filterVar is tainted concat', async () => {
    const code = [
      "const express = require('express');",
      "const ldap = require('ldapjs');",
      'const app = express();',
      "const client = ldap.createClient({ url: 'ldap://x' });",
      "app.get('/find', (req, res) => {",
      '  const email = req.query.email;',
      "  const filter = '(mail=' + email + ')';",
      "  client.search('ou=people,dc=example,dc=com', filter, () => {});",
      "  res.send('ok');",
      '});',
    ].join('\n');
    const r = await analyze(code, 'omniauth_ldap_mail_tp_var.js', 'javascript');
    expect(ldapFindings(r).length).toBeGreaterThan(0);
  });

  it('TP: client.search(base, "(mail=" + email + ")", cb) fires ldap_injection', async () => {
    const code = [
      "const express = require('express');",
      "const ldap = require('ldapjs');",
      'const app = express();',
      "const client = ldap.createClient({ url: 'ldap://x' });",
      "app.get('/find', (req, res) => {",
      '  const email = req.query.email;',
      "  client.search('ou=people,dc=example,dc=com', '(mail=' + email + ')', () => {});",
      "  res.send('ok');",
      '});',
    ].join('\n');
    const r = await analyze(code, 'omniauth_ldap_mail_tp.js', 'javascript');
    expect(ldapFindings(r).length).toBeGreaterThan(0);
  });

  it('safe: fixed filter string stays clean', async () => {
    const code = [
      "const ldap = require('ldapjs');",
      "const client = ldap.createClient({ url: 'ldap://x' });",
      "client.search('ou=people,dc=example,dc=com', '(mail=user@example.com)', () => {});",
    ].join('\n');
    const r = await analyze(code, 'omniauth_ldap_mail_safe.js', 'javascript');
    expect(ldapFindings(r)).toHaveLength(0);
  });
});
