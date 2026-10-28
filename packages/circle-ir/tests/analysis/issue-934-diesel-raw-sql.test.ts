/**
 * cognium-dev #934 — rust-synthetic `sqli_diesel_raw_sql`: parameter-built SQL
 * must reach diesel `sql_query` / `raw_sql` without `speculativeParamSources`.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

beforeAll(async () => {
  await initAnalyzer();
});

function sqliFlows(code: string, file = 'diesel_sqli.rs') {
  return analyze(code, file, 'rust').then((r) =>
    (r.taint.flows ?? []).filter((f) => f.sink_type === 'sql_injection' && !f.sanitized),
  );
}

describe('issue #934 diesel raw SQL parameter flow', () => {
  it('format! into sql_query reports sql_injection by default', async () => {
    const code = `
pub fn run_bad(user_input: String) {
    let sql = format!("SELECT * FROM users WHERE id = {}", user_input);
    diesel::sql_query(&sql);
}
`;
    const flows = await sqliFlows(code);
    expect(flows.some((f) => f.source_type === 'interprocedural_param')).toBe(true);
    expect(flows.length).toBeGreaterThan(0);
  });

  it('constant sql_query argument stays clean', async () => {
    const code = `
pub fn run_safe() {
    diesel::sql_query("SELECT 1");
}
`;
    expect(await sqliFlows(code)).toHaveLength(0);
  });
});
