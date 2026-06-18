/**
 * Repro for Sprint 16 (cognium-dev v3.66.0) — Java CVE sinks (B) + OOP
 * field-sensitivity round 2 (D) + Java cross-file taint (E).
 *
 *   B — #52 FreeMarker SSTI filename variant:
 *       `Configuration.getTemplate(req.getParameter("name"))` must FIRE
 *       `code_injection`. Today there is no sink entry for `getTemplate(name)`.
 *
 *   D — #78 round 2: static field stores (intra-class), non-bean
 *       setter/getter pairs, and cross-instance aliasing via constructor-stored
 *       receivers. Round 1 (v3.39.0+) shipped `this.field = source` via the
 *       constructor body only; these three patterns are net-new.
 *
 *   E — #74 follow-up: cross-file Java taint. Direct instance call, static
 *       import, Spring @Autowired, and interface dispatch. Today's resolver
 *       does not consult `call.receiver_type_fqn` (the Java extractor does
 *       populate it), so cross-file lookups miss for Java even though the
 *       SymbolTable is keyed by FQN.
 *
 * NOTE: SAST regression fixtures — every example is either deliberately
 * vulnerable (must fire) or deliberately safe (must NOT fire). Do not "fix"
 * the fixtures.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze, analyzeProject } from '../../src/analyzer.js';

describe('Sprint 16 — cognium-dev v3.66.0 Java CVE sinks + OOP r2 + Java cross-file', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ===========================================================================
  // B — #52 FreeMarker SSTI filename variant
  // ===========================================================================

  it('B.1: FreeMarker Configuration.getTemplate(taintedFilename) FIRES code_injection', async () => {
    const code = `import javax.servlet.http.*;
import freemarker.template.*;
public class FmGetTemplate {
  public void render(HttpServletRequest req, java.io.Writer out, Configuration cfg) throws Exception {
    String name = req.getParameter("tpl");
    Template tpl = cfg.getTemplate(name);
    tpl.process(new java.util.HashMap(), out);
  }
}
`;
    const r = await analyze(code, 'FmGetTemplate.java', 'java');
    const ci = (r.taint.flows ?? []).filter((f) => f.sink_type === 'code_injection');
    expect(ci.length, 'expected at least one code_injection flow').toBeGreaterThanOrEqual(1);
  });

  // ===========================================================================
  // D — #78 round 2
  // ===========================================================================

  it('D.1: static field intra-class — Config.dbHost set in init(), read in query() FIRES', async () => {
    const code = `import javax.servlet.http.HttpServletRequest;
public class Config {
  private static String dbHost;
  public static void init(HttpServletRequest req) {
    dbHost = req.getParameter("h");
  }
  public static Process query() throws Exception {
    return Runtime.getRuntime().exec(dbHost);
  }
}
`;
    const r = await analyze(code, 'Config.java', 'java');
    // Runtime.exec is a command_injection sink; the assertion is that
    // *some* flow attributes its source to the static dbHost write.
    const flows = (r.taint.flows ?? []).filter(f =>
      f.sink_type === 'command_injection' || f.sink_type === 'ssrf' || f.sink_type === 'path_traversal',
    );
    expect(flows.length, 'expected at least one flow from static dbHost to Runtime.exec sink').toBeGreaterThanOrEqual(1);
  });

  it('D.2: non-bean setter/getter — u.setCred(taint) then stmt.execute(... + u.getCred()) FIRES sql_injection', async () => {
    const code = `import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;
public class UserOps {
  static class User {
    private String cred;
    public void setCred(String c) { this.cred = c; }
    public String getCred() { return this.cred; }
  }
  public void handle(HttpServletRequest req, Statement stmt) throws Exception {
    User u = new User();
    u.setCred(req.getParameter("c"));
    stmt.executeQuery("SELECT * FROM creds WHERE c = '" + u.getCred() + "'");
  }
}
`;
    const r = await analyze(code, 'UserOps.java', 'java');
    const sqli = (r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sqli.length, 'expected at least one sql_injection flow from setCred to getCred-in-sink').toBeGreaterThanOrEqual(1);
  });

  it('D.3: cross-instance aliasing — Service stores Repo, writes Repo.sql, Repo.run() executes it', async () => {
    const service = `package com.example;
import javax.servlet.http.HttpServletRequest;
public class Service {
  private Repo repo;
  public Service(Repo r) { this.repo = r; }
  public void handle(HttpServletRequest req) {
    this.repo.sql = req.getParameter("c");
  }
}
`;
    const repo = `package com.example;
import java.sql.Statement;
public class Repo {
  public String sql;
  public Statement stmt;
  public void run() throws Exception {
    stmt.executeQuery(sql);
  }
}
`;
    const result = await analyzeProject([
      { code: service, filePath: 'com/example/Service.java', language: 'java' },
      { code: repo,    filePath: 'com/example/Repo.java',    language: 'java' },
    ]);
    const sqlPaths = result.taint_paths.filter(p => p.sink.type === 'sql_injection');
    expect(sqlPaths.length, 'expected at least one cross-instance sql_injection path').toBeGreaterThanOrEqual(1);
  });

  // ===========================================================================
  // E — Java cross-file taint
  // ===========================================================================

  it('E.1: direct instance — Controller constructs DbHelper, helper.runUserQuery(taint) reaches SQL sink in DbHelper', async () => {
    const controller = `package com.example.web;
import javax.servlet.http.HttpServletRequest;
import com.example.db.DbHelper;
public class Controller {
  public void handle(HttpServletRequest req) throws Exception {
    String id = req.getParameter("id");
    DbHelper helper = new DbHelper();
    helper.runUserQuery(id);
  }
}
`;
    const helper = `package com.example.db;
import java.sql.*;
public class DbHelper {
  public Connection conn;
  public void runUserQuery(String userId) throws Exception {
    Statement stmt = conn.createStatement();
    stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
  }
}
`;
    const result = await analyzeProject([
      { code: controller, filePath: 'com/example/web/Controller.java', language: 'java' },
      { code: helper,     filePath: 'com/example/db/DbHelper.java',    language: 'java' },
    ]);
    const sqlPaths = result.taint_paths.filter(p => p.sink.type === 'sql_injection');
    expect(sqlPaths.length, 'expected at least one cross-file sql_injection path').toBeGreaterThanOrEqual(1);
    const xfile = sqlPaths.find(p =>
      p.source.file.endsWith('Controller.java') && p.sink.file.endsWith('DbHelper.java'),
    );
    expect(xfile, 'expected source=Controller.java / sink=DbHelper.java').toBeTruthy();
  });

  it('E.2: static import — `import static …DbHelper.runUserQuery` then runUserQuery(taint) crosses files', async () => {
    const controller = `package com.example.web;
import javax.servlet.http.HttpServletRequest;
import static com.example.db.DbHelper.runUserQuery;
public class Controller {
  public void handle(HttpServletRequest req) throws Exception {
    String id = req.getParameter("id");
    runUserQuery(id);
  }
}
`;
    const helper = `package com.example.db;
import java.sql.*;
public class DbHelper {
  public static Connection conn;
  public static void runUserQuery(String userId) throws Exception {
    Statement stmt = conn.createStatement();
    stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
  }
}
`;
    const result = await analyzeProject([
      { code: controller, filePath: 'com/example/web/Controller.java', language: 'java' },
      { code: helper,     filePath: 'com/example/db/DbHelper.java',    language: 'java' },
    ]);
    const sqlPaths = result.taint_paths.filter(p => p.sink.type === 'sql_injection');
    expect(sqlPaths.length, 'expected at least one cross-file sql_injection path via static import').toBeGreaterThanOrEqual(1);
  });

  it('E.3: Spring @Autowired — Controller has @Autowired DbHelper, calls helper.runUserQuery(taint)', async () => {
    const controller = `package com.example.web;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import com.example.db.DbHelper;
public class Controller {
  @Autowired
  private DbHelper helper;
  public void handle(HttpServletRequest req) throws Exception {
    String id = req.getParameter("id");
    helper.runUserQuery(id);
  }
}
`;
    const helper = `package com.example.db;
import java.sql.*;
public class DbHelper {
  public Connection conn;
  public void runUserQuery(String userId) throws Exception {
    Statement stmt = conn.createStatement();
    stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
  }
}
`;
    const result = await analyzeProject([
      { code: controller, filePath: 'com/example/web/Controller.java', language: 'java' },
      { code: helper,     filePath: 'com/example/db/DbHelper.java',    language: 'java' },
    ]);
    const sqlPaths = result.taint_paths.filter(p => p.sink.type === 'sql_injection');
    expect(sqlPaths.length, 'expected at least one cross-file sql_injection path via @Autowired').toBeGreaterThanOrEqual(1);
  });

  it('E.4: interface dispatch — userRepo: UserRepo (interface), unique impl UserRepoJdbc, call resolves through implementor', async () => {
    const iface = `package com.example.db;
public interface UserRepo {
  void load(String id) throws Exception;
}
`;
    const impl = `package com.example.db;
import java.sql.*;
public class UserRepoJdbc implements UserRepo {
  public Statement stmt;
  public void load(String id) throws Exception {
    stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
  }
}
`;
    const controller = `package com.example.web;
import javax.servlet.http.HttpServletRequest;
import com.example.db.UserRepo;
public class Controller {
  private UserRepo userRepo;
  public Controller(UserRepo r) { this.userRepo = r; }
  public void handle(HttpServletRequest req) throws Exception {
    String id = req.getParameter("id");
    userRepo.load(id);
  }
}
`;
    const result = await analyzeProject([
      { code: iface,      filePath: 'com/example/db/UserRepo.java',      language: 'java' },
      { code: impl,       filePath: 'com/example/db/UserRepoJdbc.java',  language: 'java' },
      { code: controller, filePath: 'com/example/web/Controller.java',   language: 'java' },
    ]);
    const sqlPaths = result.taint_paths.filter(p => p.sink.type === 'sql_injection');
    expect(sqlPaths.length, 'expected at least one cross-file sql_injection path via interface dispatch').toBeGreaterThanOrEqual(1);
  });

  // ===========================================================================
  // Same-file negative controls — verify single-file behaviour does not regress
  // ===========================================================================

  it('N.1: same-file equivalent of E.1 still fires (lock single-file path)', async () => {
    const code = `import javax.servlet.http.HttpServletRequest;
import java.sql.*;
public class AllInOne {
  public Connection conn;
  public void runUserQuery(String userId) throws Exception {
    Statement stmt = conn.createStatement();
    stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
  }
  public void handle(HttpServletRequest req) throws Exception {
    String id = req.getParameter("id");
    runUserQuery(id);
  }
}
`;
    const r = await analyze(code, 'AllInOne.java', 'java');
    const sqli = (r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sqli.length, 'expected at least one same-file sql_injection flow').toBeGreaterThanOrEqual(1);
  });
});
