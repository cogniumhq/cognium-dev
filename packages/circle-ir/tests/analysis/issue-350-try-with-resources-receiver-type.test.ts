/**
 * cognium-dev #350 — a JDBC `Statement` declared in a try-with-resources head
 * had no entry in `localVarTypes`, so the receiver of `s.executeQuery(query)`
 * could not be resolved to `Statement`:
 *
 *   try (Connection c = ...; Statement s = c.createStatement()) {
 *     s.executeQuery(query);      // <- typed external_taint_escape, not sql_injection
 *   }
 *
 * The call extractor collected `local_variable_declaration` nodes but not
 * `resource` nodes, which is the grammar node try-with-resources uses for its
 * declarations. The same statement written as a plain local resolved fine,
 * which is what made this look like a taint bug rather than a type-resolution
 * one.
 *
 * Note the finding was MIS-TYPED, not missing: `external_taint_escape` is a
 * far weaker, differently-triaged result than CWE-89, and a consumer filtering
 * on sql_injection saw nothing. Try-with-resources is the idiomatic way to
 * write JDBC, so this shape is the common case, not an edge case.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const sqli = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection' && !f.sanitized);

const run = (body: string[]) =>
  analyze(
    [
      'import java.sql.*; import java.util.Map;',
      'import org.springframework.web.bind.annotation.*;',
      '@RestController public class S {',
      '  @PostMapping("/x") public String x(@RequestBody Map<String, String> body) throws Exception {',
      ...body.map(l => '    ' + l),
      '    return "";',
      '  }',
      '}',
    ].join('\n'),
    'S.java',
    'java'
  );

const TAINTED_QUERY =
  'String query = "SELECT * FROM users WHERE u = \'" + body.getOrDefault("username", "") + "\'";';

describe('#350 try-with-resources receiver type resolution', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('types a two-resource try-with-resources executeQuery as sql_injection', async () => {
    const r = await run([
      TAINTED_QUERY,
      'try (Connection c = DriverManager.getConnection("jdbc:h2:mem:t"); Statement s = c.createStatement()) {',
      '  ResultSet rs = s.executeQuery(query);',
      '}',
    ]);
    expect(sqli(r).length).toBeGreaterThan(0);
  });

  it('types a single-resource try-with-resources executeQuery as sql_injection', async () => {
    const r = await run([
      TAINTED_QUERY,
      'try (Statement s = DriverManager.getConnection("jdbc:h2:mem:t").createStatement()) {',
      '  s.executeQuery(query);',
      '}',
    ]);
    expect(sqli(r).length).toBeGreaterThan(0);
  });

  it('keeps typing the equivalent plain-local form as sql_injection', async () => {
    const r = await run([
      TAINTED_QUERY,
      'Connection c = DriverManager.getConnection("jdbc:h2:mem:t"); Statement s = c.createStatement();',
      'ResultSet rs = s.executeQuery(query);',
    ]);
    expect(sqli(r).length).toBeGreaterThan(0);
  });

  it('does not fire for a parameterized PreparedStatement in a try-with-resources', async () => {
    const r = await run([
      'try (Connection c = DriverManager.getConnection("jdbc:h2:mem:t");',
      '     PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE u = ?")) {',
      '  ps.setString(1, body.getOrDefault("username", ""));',
      '  ps.executeQuery();',
      '}',
    ]);
    expect(sqli(r)).toHaveLength(0);
  });

  it('does not fire for a constant query in a try-with-resources', async () => {
    const r = await run([
      'try (Connection c = DriverManager.getConnection("jdbc:h2:mem:t"); Statement s = c.createStatement()) {',
      '  s.executeQuery("SELECT 1");',
      '}',
    ]);
    expect(sqli(r)).toHaveLength(0);
  });
});
