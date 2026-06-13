/**
 * Tests for JSqlParser AST visitor exclusion (#24b).
 *
 * JSqlParser (`net.sf.jsqlparser.*`) is an in-memory SQL AST library.
 * Its `Statement` type has `execute(StatementVisitor)` and `accept(...)`
 * methods that are visitor-pattern dispatch over an in-memory parse tree —
 * not database execution. circle-ir's simple-name `Statement.execute`
 * sink pattern previously matched these calls and reported them as
 * critical `sql_injection` findings.
 *
 * 3.44.0 leverages the `receiver_type_fqn` field added in 3.43.0
 * (`CallInfo.receiver_type_fqn`) to drop matches whose receiver FQN
 * starts with `net.sf.jsqlparser.`, while preserving every other
 * `Statement.execute(sql)` finding on real JDBC types.
 *
 * Closes cognium-dev#24 (JSqlParser half).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import { analyzeTaint } from '../../src/analysis/taint-matcher.js';
import { getDefaultConfig } from '../../src/analysis/config-loader.js';

async function sinksFor(code: string) {
  const tree = await parse(code, 'java');
  const calls = extractCalls(tree);
  const types = extractTypes(tree);
  const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'java');
  return taint.sinks;
}

describe('JSqlParser AST visitor exclusion (#24b)', () => {
  beforeAll(async () => {
    await initParser();
  });

  describe('exclusion fires when receiver FQN is JSqlParser', () => {
    it('Statement.execute(visitor) where Statement is net.sf.jsqlparser does NOT emit sql_injection', async () => {
      const code = `
package com.example;
import net.sf.jsqlparser.statement.Statement;
import net.sf.jsqlparser.statement.StatementVisitor;
public class Test {
  public void parse(Statement stmt, StatementVisitor visitor) {
    stmt.execute(visitor);
  }
}
`;
      const sinks = await sinksFor(code);
      const sqlSinks = sinks.filter(s => s.type === 'sql_injection');
      expect(sqlSinks).toHaveLength(0);
    });

    it('Select.execute on net.sf.jsqlparser Select does NOT emit sql_injection', async () => {
      // Even though the pattern set doesn't ship a `Select.execute` entry,
      // verify the broader namespace exclusion holds for parametrized
      // execute method names on JSqlParser AST nodes (defensive regression).
      const code = `
package com.example;
import net.sf.jsqlparser.statement.select.Select;
public class Test {
  public void run(Select select, Object visitor) {
    select.execute(visitor);
  }
}
`;
      const sinks = await sinksFor(code);
      const sqlSinks = sinks.filter(s => s.type === 'sql_injection');
      expect(sqlSinks).toHaveLength(0);
    });

    it('field-typed JSqlParser Statement still excluded', async () => {
      const code = `
package com.example;
import net.sf.jsqlparser.statement.Statement;
public class Test {
  private Statement stmt;
  public void run(Object visitor) {
    stmt.execute(visitor);
  }
}
`;
      const sinks = await sinksFor(code);
      const sqlSinks = sinks.filter(s => s.type === 'sql_injection');
      expect(sqlSinks).toHaveLength(0);
    });

    it('local-var-typed JSqlParser Statement still excluded', async () => {
      const code = `
package com.example;
import net.sf.jsqlparser.statement.Statement;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;
public class Test {
  public void run(String sql, Object visitor) throws Exception {
    Statement stmt = CCJSqlParserUtil.parse(sql);
    stmt.execute(visitor);
  }
}
`;
      const sinks = await sinksFor(code);
      const sqlSinks = sinks.filter(s => s.type === 'sql_injection');
      expect(sqlSinks).toHaveLength(0);
    });
  });

  describe('exclusion does NOT fire for real JDBC types', () => {
    it('java.sql.Statement.execute(sql) still emits sql_injection', async () => {
      const code = `
package com.example;
import java.sql.Statement;
import java.sql.Connection;
public class Test {
  public void run(Connection conn, String userInput) throws Exception {
    Statement stmt = conn.createStatement();
    stmt.execute(userInput);
  }
}
`;
      const sinks = await sinksFor(code);
      const sqlSinks = sinks.filter(s => s.type === 'sql_injection' && s.method === 'execute');
      expect(sqlSinks.length).toBeGreaterThanOrEqual(1);
    });

    it('java.sql.Statement.executeQuery(sql) still emits sql_injection', async () => {
      const code = `
package com.example;
import java.sql.Statement;
import java.sql.Connection;
public class Test {
  public void run(Connection conn, String userInput) throws Exception {
    Statement stmt = conn.createStatement();
    stmt.executeQuery(userInput);
  }
}
`;
      const sinks = await sinksFor(code);
      const sqlSinks = sinks.filter(s => s.type === 'sql_injection' && s.method === 'executeQuery');
      expect(sqlSinks.length).toBeGreaterThanOrEqual(1);
    });

    it('java.sql.Statement.executeUpdate(sql) still emits sql_injection', async () => {
      const code = `
package com.example;
import java.sql.Statement;
import java.sql.Connection;
public class Test {
  public void run(Connection conn, String userInput) throws Exception {
    Statement stmt = conn.createStatement();
    stmt.executeUpdate(userInput);
  }
}
`;
      const sinks = await sinksFor(code);
      const sqlSinks = sinks.filter(s => s.type === 'sql_injection' && s.method === 'executeUpdate');
      expect(sqlSinks.length).toBeGreaterThanOrEqual(1);
    });

    it('JdbcTemplate.execute(sql) still emits sql_injection', async () => {
      const code = `
package com.example;
import org.springframework.jdbc.core.JdbcTemplate;
public class Test {
  public void run(JdbcTemplate jdbcTemplate, String userInput) {
    jdbcTemplate.execute(userInput);
  }
}
`;
      const sinks = await sinksFor(code);
      const sqlSinks = sinks.filter(s => s.type === 'sql_injection' && s.method === 'execute');
      expect(sqlSinks.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('conservative behavior when FQN unresolvable', () => {
    it('unresolved receiver still matches simple-name pattern (no FQN to exclude on)', async () => {
      // No `import` at all → receiver_type_fqn is null → exclusion does
      // not fire → simple-name heuristic still flags as sql_injection.
      // This preserves today's recall in the absence of resolved types.
      const code = `
public class Test {
  public void run(Statement stmt, String userInput) throws Exception {
    stmt.execute(userInput);
  }
}
`;
      const sinks = await sinksFor(code);
      const sqlSinks = sinks.filter(s => s.type === 'sql_injection' && s.method === 'execute');
      expect(sqlSinks.length).toBeGreaterThanOrEqual(1);
    });

    it('wildcard JSqlParser import leaves FQN null and falls back to heuristic match', async () => {
      // Wildcard imports do not populate `receiver_type_fqn` in 3.43.0
      // (intentional conservatism). The exclusion therefore does not
      // fire and the simple-name `Statement.execute` pattern matches.
      // This is the documented limitation — explicit imports are
      // required to get the precision improvement.
      const code = `
package com.example;
import net.sf.jsqlparser.statement.*;
public class Test {
  public void run(Statement stmt, Object visitor) throws Exception {
    stmt.execute(visitor);
  }
}
`;
      const sinks = await sinksFor(code);
      const sqlSinks = sinks.filter(s => s.type === 'sql_injection' && s.method === 'execute');
      // We expect this to still flag (false positive preserved). When a
      // future release adds wildcard-import FQN resolution, this test
      // should be updated to expect zero sinks.
      expect(sqlSinks.length).toBeGreaterThanOrEqual(1);
    });
  });
});
