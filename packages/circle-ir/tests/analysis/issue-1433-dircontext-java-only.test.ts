/**
 * cognium-dev #1433 — JNDI DirContext.search rows must not match JS String.search.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const ldapFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint?.flows ?? []).filter((f) => f.sink_type === 'ldap_injection');

describe('cognium-dev #1433 — JNDI LDAP sinks are Java-only', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('safe: String.prototype.search on a variable named text is not ldap_injection', async () => {
    const code = [
      'export function f(code: string) {',
      '  const text = code;',
      '  return text.search(/\\S/);',
      '}',
    ].join('\n');
    const r = await analyze(code, 'fixtures/ldap/string-search-regex.ts', 'typescript');
    expect(ldapFlows(r)).toHaveLength(0);
  });

  it('TP: Java DirContext.search with tainted filter still fires', async () => {
    const code = [
      'import javax.naming.directory.SearchControls;',
      'import javax.servlet.http.HttpServletRequest;',
      'import javax.naming.directory.DirContext;',
      'class LdapQuery {',
      '  void q(DirContext ctx, HttpServletRequest req) throws Exception {',
      '    SearchControls sc = new SearchControls();',
      '    String base = "dc=example,dc=com";',
      '    ctx.search(base, "(uid=" + req.getParameter("u") + ")", sc);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'LdapQuery.java', 'java');
    expect(ldapFlows(r).length).toBeGreaterThan(0);
  });
});