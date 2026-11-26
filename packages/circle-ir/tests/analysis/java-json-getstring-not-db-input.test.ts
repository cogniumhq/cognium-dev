/**
 * A Java report parser reads fields off a `JSONObject` named `result`. The
 * receiver name prefix-matched the `ResultSet.getString` db_input row, so
 * reading JSON metadata was reported as a database read. The parser also keeps
 * a sample report, with a SQL statement in it, inside a block comment; that
 * text is not a sink.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const reportParser = `package demo.score;

import org.json.JSONObject;

public class ScanReportReader {
    private int parseFinding(JSONObject result) {
        /*
         * Sample entry:
         * {
         *   "check_id": "java.sqli.string-concat",
         *   "path": "src/main/java/demo/Case00042.java",
         *   "lines": "java.sql.Statement st = conn.createStatement(); st.execute(sql);"
         * }
         */
        String path = result.getString("path");
        String name = path.substring(path.lastIndexOf('/') + 1).split("\\\\.")[0];
        String rule = result.getString("check_id");
        return name.length() + rule.length();
    }
}
`;

const realDbRead = `package demo.score;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class Lookup {
    void run(Connection conn) throws Exception {
        Statement st = conn.createStatement();
        ResultSet result = st.executeQuery("SELECT name FROM users");
        String name = result.getString("name");
        st.execute("DELETE FROM audit WHERE who = '" + name + "'");
    }
}
`;

describe('Java: JSON field reads are not db_input; a commented sample is not a sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('JSONObject result.getString is not a db_input source', async () => {
    const ir = await analyze(reportParser, 'ScanReportReader.java', 'java');
    expect(ir.taint.sources.filter(s => s.type === 'db_input')).toEqual([]);
    expect(ir.taint.flows).toEqual([]);
  });

  it('the SQL text in the block comment is not a sink', async () => {
    const ir = await analyze(reportParser, 'ScanReportReader.java', 'java');
    const commentLines = new Set([7, 8, 9, 10, 11, 12, 13, 14]);
    expect(ir.taint.sinks.filter(s => commentLines.has(s.line))).toEqual([]);
    expect(ir.taint.sinks.filter(s => s.type === 'sql_injection')).toEqual([]);
  });

  it('ResultSet result.getString is still a db_input source that reaches a SQL sink', async () => {
    const ir = await analyze(realDbRead, 'Lookup.java', 'java');
    expect(ir.taint.sources.some(s => s.type === 'db_input' && s.line === 11)).toBe(true);
    expect(ir.taint.flows.some(f => f.source_type === 'db_input' && f.sink_type === 'sql_injection')).toBe(true);
  });
});
