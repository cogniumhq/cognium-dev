/**
 * cognium-dev#683 — a `sql_injection` sink pattern supplied without
 * `arg_positions` must not make analyze() throw. A taint config can come
 * from JSON or YAML, where the required field is not type-checked.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { getDefaultConfig } from '../../src/analysis/config-loader.js';
import type { SinkPattern } from '../../src/types/config.js';

describe('#683 sql_injection sink without arg_positions', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const code = [
    'using System.Data.SqlClient;',
    'public class Repo {',
    '  public void Run(SqlConnection conn, string name) {',
    '    var cmd = new SqlCommand("SELECT * FROM t WHERE n = \'" + name + "\'", conn);',
    '    cmd.ExecuteNonQuery();',
    '  }',
    '}',
  ].join('\n');

  it('analyze() does not throw when a user sink omits arg_positions', async () => {
    const cfg = getDefaultConfig();
    // Shape of a sink loaded from an untyped rules file.
    const untyped = { method: 'ExecuteNonQuery', class: 'SqlCommand', type: 'sql_injection', cwe: 'CWE-89', severity: 'high' };
    cfg.sinks.push(untyped as unknown as SinkPattern);
    await expect(analyze(code, 'Repo.cs', 'csharp', { taintConfig: cfg })).resolves.toBeDefined();
  });
});
