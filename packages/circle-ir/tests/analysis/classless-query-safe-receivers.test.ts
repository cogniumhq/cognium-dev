/**
 * The JS plugin's classless `query` CWE-89 sink fires on any `.query(tainted)`.
 * Logger receivers are a false positive — winston exposes a real `.query()`
 * for querying log records, so `logger.query(userInput)` is a log lookup, not
 * SQL. These lock the safe-receiver suppression WITHOUT weakening recall on
 * genuine database handles.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

describe('classless query() sink — logger receivers suppressed, DB handles fire', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const sqlFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows ?? []).filter((f) => f.sink_type === 'sql_injection');

  for (const recv of ['logger', 'logging', 'winston', 'pino', 'console']) {
    it(`${recv}.query(userInput) does NOT fire SQL injection`, async () => {
      const code = [
        'app.get("/u", (req, res) => {',
        '  const id = req.params.id;',
        `  ${recv}.query("lookup " + id);`,
        '});',
      ].join('\n');
      const r = await analyze(code, 'server.js', 'javascript');
      expect(sqlFlows(r).length).toBe(0);
    });
  }

  for (const recv of ['db', 'pool', 'client', 'connection', 'conn']) {
    it(`${recv}.query(userInput) STILL fires SQL injection (recall preserved)`, async () => {
      const code = [
        'app.get("/u", (req, res) => {',
        '  const id = req.params.id;',
        `  ${recv}.query("SELECT * FROM users WHERE id = " + id);`,
        '});',
      ].join('\n');
      const r = await analyze(code, 'server.js', 'javascript');
      expect(sqlFlows(r).length).toBeGreaterThan(0);
    });
  }
});
