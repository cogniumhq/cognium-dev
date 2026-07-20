/**
 * Regression locks for cognium-dev #179 Sinks 2-4.
 *
 * Sprint 44 recon confirmed that #179 Sinks 2 (typed Jackson),
 * 3 (parameterized JdbcTemplate), and 4 (TransformerFactory
 * output-only) are already addressed by existing gates:
 *
 *   - Sink 2: `safe_if_class_literal_at: 1` SinkPattern field on the
 *             ObjectMapper.readValue entry in `config-loader.ts`.
 *             Shipped under cognium-dev#22.
 *   - Sink 3: Placeholder-aware SQL filter (?, $1, :name, %s) inside
 *             the SQL injection sink pipeline. See
 *             `tests/analysis/placeholder-sql-filter.test.ts`.
 *   - Sink 4: Output-direction gate in `xml-entity-expansion-pass.ts`.
 *             Shipped Sprint 43 as cognium-dev#173.
 *
 * This file replicates the exact #179 ticket-body shapes verbatim and
 * locks them against future drift. No source change is required to
 * pass these tests — they exist purely to detect regressions.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countByType = (
  arr: Array<{ type?: string }> | undefined,
  t: string,
) => (arr ?? []).filter((s) => s.type === t).length;

const countByRule = (
  arr: Array<{ rule_id?: string }> | undefined,
  r: string,
) => (arr ?? []).filter((f) => f.rule_id === r).length;

describe('cognium-dev #179 Sinks 2-4 — regression locks (existing gates)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // Sink 2 — typed Jackson ObjectMapper.readValue (safe_if_class_literal_at)
  // -------------------------------------------------------------------------

  it('Sink 2 — mapper.readValue(json, User.class) (simple class literal): no deserialization sink', async () => {
    const code = `import com.fasterxml.jackson.databind.ObjectMapper;

public class Svc {
  public Object run(ObjectMapper mapper, String json) throws Exception {
    return mapper.readValue(json, User.class);
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    expect(countByType(r.taint?.sinks, 'deserialization')).toBe(0);
  });

  it('Sink 2 — mapper.readValue(json, com.example.User.class) (FQN class literal): no deserialization sink', async () => {
    const code = `import com.fasterxml.jackson.databind.ObjectMapper;

public class Svc {
  public Object run(ObjectMapper mapper, String json) throws Exception {
    return mapper.readValue(json, com.example.User.class);
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    expect(countByType(r.taint?.sinks, 'deserialization')).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Sink 3 — parameterized JdbcTemplate (placeholder-aware SQL filter)
  // -------------------------------------------------------------------------

  it('Sink 3 — jdbcTemplate.update("UPDATE users SET name=? WHERE id=?", name, id): no sql_injection sink', async () => {
    const code = `import org.springframework.jdbc.core.JdbcTemplate;

public class Repo {
  private final JdbcTemplate jdbcTemplate;
  public Repo(JdbcTemplate j) { this.jdbcTemplate = j; }
  public int rename(String name, long id) {
    return jdbcTemplate.update("UPDATE users SET name=? WHERE id=?", name, id);
  }
}
`;
    const r = await analyze(code, 'Repo.java', 'java');
    expect(countByType(r.taint?.sinks, 'sql_injection')).toBe(0);
  });

  it('Sink 3 — jdbcTemplate.queryForObject("...?", mapper, id): no sql_injection sink', async () => {
    const code = `import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

public class Repo {
  private final JdbcTemplate jdbcTemplate;
  public Repo(JdbcTemplate j) { this.jdbcTemplate = j; }
  public Object findById(RowMapper<?> mapper, long id) {
    return jdbcTemplate.queryForObject("SELECT * FROM users WHERE id=?", mapper, id);
  }
}
`;
    const r = await analyze(code, 'Repo.java', 'java');
    expect(countByType(r.taint?.sinks, 'sql_injection')).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Sink 4 — TransformerFactory output-only (Sprint 43, #173)
  // -------------------------------------------------------------------------

  it('Sink 4 — TransformerFactory.transform(DOMSource → StreamResult), no parse-input shape: no xml-entity-expansion finding', async () => {
    const code = `import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import java.io.File;

public class Serializer {
  public void write(Document doc, File out) throws Exception {
    Transformer t = TransformerFactory.newInstance().newTransformer();
    t.transform(new DOMSource(doc), new StreamResult(out));
  }
}
`;
    const r = await analyze(code, 'Serializer.java', 'java');
    expect(countByRule(r.findings, 'xml-entity-expansion')).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// cognium-dev #256 (3.176.0) — Sink-shape gate indirection resolution.
//
// Both #22 (`safe_if_class_literal_at`) and #179 (`PROCESS_BUILDER_ARGV_FORM_RE`)
// only match the DIRECT/LITERAL arg form. #256 extends both gates with a
// same-file type resolver so a bare identifier (param/field) or a same-file
// method call whose return type resolves to `Class<...>` (Gate 1) or
// `List<String>` / `String[]` (Gate 2) is also suppressed.
//
// Recall locks below verify that indirection targets which are NOT in the
// same-file `ir.types` (e.g. `Class.forName(x)`, `getClass()`) OR whose
// resolved type is not container-shaped (bare `String` for ProcessBuilder)
// continue to fire as sinks.
// ---------------------------------------------------------------------------

describe('cognium-dev #256 — indirection resolution for #22/#179 gates', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // Gate 1 — CWE-502 typed deserialization via variable Class<T> / return type.

  it('Gate 1 — readValue(json, templateClass) where templateClass: Class<T extends X> param (jib repro): no deserialization sink', async () => {
    const code = `import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;

public class JsonTemplateMapper {
  private static final ObjectMapper mapper = new ObjectMapper();
  public static <T extends JsonTemplate> T readJsonFromFile(InputStream fileIn, Class<T> templateClass) throws Exception {
    return mapper.readValue(fileIn, templateClass);
  }
}
`;
    const r = await analyze(code, 'JsonTemplateMapper.java', 'java');
    expect(countByType(r.taint?.sinks, 'deserialization')).toBe(0);
  });

  it('Gate 1 — readValue(json, fieldClass) where fieldClass: Class<Foo> field: no deserialization sink', async () => {
    const code = `import com.fasterxml.jackson.databind.ObjectMapper;

public class Svc {
  private static final Class<Object> fieldClass = Object.class;
  private final ObjectMapper mapper = new ObjectMapper();
  public Object run(String json) throws Exception {
    return mapper.readValue(json, fieldClass);
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    expect(countByType(r.taint?.sinks, 'deserialization')).toBe(0);
  });

  it('Gate 1 — readValue(json, getTargetClass()) where getTargetClass returns Class<Foo>: no deserialization sink', async () => {
    const code = `import com.fasterxml.jackson.databind.ObjectMapper;

public class Svc {
  private final ObjectMapper mapper = new ObjectMapper();
  private static Class<Object> getTargetClass() { return Object.class; }
  public Object run(String json) throws Exception {
    return mapper.readValue(json, getTargetClass());
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    expect(countByType(r.taint?.sinks, 'deserialization')).toBe(0);
  });

  it('Gate 1 recall lock — readValue(json, Class.forName(userType)): deserialization sink still fires', async () => {
    const code = `import com.fasterxml.jackson.databind.ObjectMapper;

public class Svc {
  private final ObjectMapper mapper = new ObjectMapper();
  public Object run(String json, String userType) throws Exception {
    return mapper.readValue(json, Class.forName(userType));
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    expect(countByType(r.taint?.sinks, 'deserialization')).toBeGreaterThanOrEqual(1);
  });

  it('Gate 1 recall lock — readValue(json, other.getClass()): deserialization sink still fires', async () => {
    const code = `import com.fasterxml.jackson.databind.ObjectMapper;

public class Svc {
  private final ObjectMapper mapper = new ObjectMapper();
  public Object run(String json, Object other) throws Exception {
    return mapper.readValue(json, other.getClass());
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    expect(countByType(r.taint?.sinks, 'deserialization')).toBeGreaterThanOrEqual(1);
  });

  // Gate 2 — CWE-78 ProcessBuilder argv form via method-call return type / variable.

  it('Gate 2 — new ProcessBuilder(buildCommand(bin)) where buildCommand returns List<String> (flyingsaucer repro): no command_injection sink', async () => {
    const code = `import java.util.List;
import java.util.Arrays;

public class DevToolsSession {
  private static List<String> buildCommand(String binary) {
    return Arrays.asList(binary, "--remote-debugging-port=0");
  }
  public Process launch(String binary) throws Exception {
    return new ProcessBuilder(buildCommand(binary)).redirectErrorStream(false).start();
  }
}
`;
    const r = await analyze(code, 'DevToolsSession.java', 'java');
    expect(countByType(r.taint?.sinks, 'command_injection')).toBe(0);
  });

  it('Gate 2 — new ProcessBuilder(args) where args is List<String> param: no command_injection sink', async () => {
    const code = `import java.util.List;

public class Launcher {
  public Process launch(List<String> args) throws Exception {
    return new ProcessBuilder(args).start();
  }
}
`;
    const r = await analyze(code, 'Launcher.java', 'java');
    expect(countByType(r.taint?.sinks, 'command_injection')).toBe(0);
  });

  it('Gate 2 recall lock — new ProcessBuilder(userCmd) where userCmd is String: command_injection sink still fires', async () => {
    const code = `public class Launcher {
  public Process launch(String userCmd) throws Exception {
    return new ProcessBuilder(userCmd).start();
  }
}
`;
    const r = await analyze(code, 'Launcher.java', 'java');
    expect(countByType(r.taint?.sinks, 'command_injection')).toBeGreaterThanOrEqual(1);
  });
});
