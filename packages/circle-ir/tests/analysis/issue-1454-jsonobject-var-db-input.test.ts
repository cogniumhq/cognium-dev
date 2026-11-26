/**
 * cognium-dev #1454 (follow-up #1447): a `var` local whose initializer is
 * `new JSONObject(...)` must not match `ResultSet.getString` db_input by name.
 * Explicit `ResultSet` and untyped `var` JDBC reads stay db_input.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const jsonVarLocal = `package demo.score;

import org.json.JSONObject;

public class VarJsonReader {
    void run(String body) {
        var result = new JSONObject(body);
        String path = result.getString("path");
        return;
    }
}
`;

const jsonTypedParam = `package demo.score;

import org.json.JSONObject;

public class TypedJsonReader {
    void run(JSONObject result) {
        String path = result.getString("path");
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

const varResultSet = `package demo.score;

import java.sql.Connection;
import java.sql.Statement;

public class VarLookup {
    void run(Connection conn) throws Exception {
        Statement st = conn.createStatement();
        var rs = st.executeQuery("SELECT name FROM users");
        String name = rs.getString("n");
        st.execute("DELETE FROM audit WHERE who = '" + name + "'");
    }
}
`;

describe('#1454 var JSONObject initializer is not db_input on getString', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('var result = new JSONObject(body) — no db_input on getString', async () => {
    const ir = await analyze(jsonVarLocal, 'VarJsonReader.java', 'java');
    expect(ir.taint.sources.filter((s) => s.type === 'db_input')).toEqual([]);
    expect(ir.taint.flows).toEqual([]);
  });

  it('JSONObject parameter — no db_input on getString', async () => {
    const ir = await analyze(jsonTypedParam, 'TypedJsonReader.java', 'java');
    expect(ir.taint.sources.filter((s) => s.type === 'db_input')).toEqual([]);
  });

  it('ResultSet result.getString remains db_input to SQL sink', async () => {
    const ir = await analyze(realDbRead, 'Lookup.java', 'java');
    expect(ir.taint.sources.some((s) => s.type === 'db_input' && s.line === 11)).toBe(true);
    expect(ir.taint.flows.some((f) => f.source_type === 'db_input' && f.sink_type === 'sql_injection')).toBe(
      true,
    );
  });

  it('var rs = executeQuery — still db_input when name matches ResultSet', async () => {
    const ir = await analyze(varResultSet, 'VarLookup.java', 'java');
    expect(ir.taint.sources.some((s) => s.type === 'db_input' && s.line === 10)).toBe(true);
    expect(ir.taint.flows.some((f) => f.source_type === 'db_input' && f.sink_type === 'sql_injection')).toBe(
      true,
    );
  });
});