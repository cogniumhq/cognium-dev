/**
 * cognium-dev#327 — C# field written from a method parameter carries taint to
 * readers in other methods; literal-only field assignments stay clean.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const ledgerReader = `
using System.Data.SqlClient;

public class LedgerReader {
    static SqlConnection conn;
    string _ref;

    public void Remember(string input) { _ref = input; }

    public void Load() {
        var cmd = new SqlCommand("SELECT * FROM ledger WHERE ref=" + _ref, conn);
        cmd.ExecuteReader();
    }
}
`;

const ledgerDefaults = `
using System.Data.SqlClient;

public class LedgerDefaults {
    static SqlConnection conn;
    string _ref;

    public LedgerDefaults() { _ref = "ledger-1"; }

    public void Load(string input) {
        var cmd = new SqlCommand("SELECT * FROM ledger WHERE ref=" + _ref, conn);
        cmd.ExecuteReader();
    }
}
`;

describe('issue #327 C# parameter-written field crosses methods', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('LedgerReader reports sql_injection from parameter to sink', async () => {
    const ir = await analyze(ledgerReader, 'LedgerReader.cs', 'csharp');
    const flows = ir.taint.flows?.filter(f => f.sink_type === 'sql_injection') ?? [];
    expect(flows.length).toBeGreaterThanOrEqual(1);
    const inputLine = ledgerReader.split('\n').findIndex(l => l.includes('Remember(string input)')) + 1;
    expect(flows.some(f => f.source_line === inputLine && f.sink_type === 'sql_injection')).toBe(true);
  });

  it('LedgerDefaults stays clean when the field is literal-only', async () => {
    const ir = await analyze(ledgerDefaults, 'LedgerDefaults.cs', 'csharp');
    const flows = ir.taint.flows?.filter(f => f.sink_type === 'sql_injection') ?? [];
    expect(flows).toHaveLength(0);
  });
});
