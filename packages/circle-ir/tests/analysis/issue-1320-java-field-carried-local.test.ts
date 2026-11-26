/**
 * cognium-dev#1320 — Java: a private field written from a source in one method
 * and copied into a local in another method keeps its taint (Juliet flow
 * variant 45, "data passed as a private class member variable").
 *
 * A sink that used the field directly already fired. Copying the field into a
 * local first (`String data = dataBad;`) lost the flow: constant propagation
 * scoped the field's taint to the writing method, and the alias for the local
 * was keyed by name across the whole file.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const sqlSinkLines = async (code: string) => {
  const ir = await analyze(code, 'T.java', 'java');
  return [...new Set((ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection').map(f => f.sink_line))];
};

const lineOf = (code: string, needle: string) => code.split('\n').findIndex(l => l.includes(needle)) + 1;

const SINK_FIRST = `import java.sql.*;

public class OrderLookup {
    private String nameBad;
    private String nameGood;

    private void badSink() throws Throwable {
        String name = nameBad;
        Connection conn = Db.open();
        Statement st = conn.createStatement();
        st.executeQuery("select * from orders where owner='" + name + "'");
    }

    public void bad() throws Throwable {
        String name;
        name = System.getenv("OWNER");
        nameBad = name;
        badSink();
    }

    private void goodSink() throws Throwable {
        String name = nameGood;
        Connection conn = Db.open();
        Statement st = conn.createStatement();
        st.executeQuery("select * from orders where owner='" + name + "'");
    }

    public void good() throws Throwable {
        String name;
        name = "alice";
        nameGood = name;
        goodSink();
    }
}
`;

describe('#1320 Java field copied into a local in another method keeps taint', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('the sink method declared before the writer fires; the literal-only field stays clean', async () => {
    const lines = await sqlSinkLines(SINK_FIRST);
    const badSinkLine = lineOf(SINK_FIRST, 'executeQuery');
    const goodSinkLine = SINK_FIRST.split('\n').findLastIndex(l => l.includes('executeQuery')) + 1;
    expect(lines).toContain(badSinkLine);
    expect(lines).not.toContain(goodSinkLine);
  });

  it('the sink method declared after the writer fires', async () => {
    const code = `import java.sql.*;

public class OrderLookup {
    private String ownerField;

    public void bad() throws Throwable {
        ownerField = System.getenv("OWNER");
        badSink();
    }

    private void badSink() throws Throwable {
        String owner = ownerField;
        Connection conn = Db.open();
        Statement st = conn.createStatement();
        st.executeQuery("select * from orders where owner='" + owner + "'");
    }
}
`;
    expect(await sqlSinkLines(code)).toContain(lineOf(code, 'executeQuery'));
  });
});
