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
