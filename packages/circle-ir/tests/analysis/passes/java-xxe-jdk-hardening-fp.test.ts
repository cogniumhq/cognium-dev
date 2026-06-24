/**
 * Tests for cognium-dev #166 — Java `xml-entity-expansion` (CWE-776)
 * FP suppression on JDK 8u121+ entity-limit hardening and the
 * load-external-dtd / secure-processing feature patterns.
 *
 * Sprint 44 extends `JAVA_SAFE_EVIDENCE_RE` in
 * `xml-entity-expansion-pass.ts` with additional alternations:
 *   - `load-external-dtd` (Apache feature URL)
 *   - `jdk.xml.totalEntitySizeLimit` / `entityExpansionLimit` /
 *     `maxGeneralEntitySizeLimit` / `maxParameterEntitySizeLimit` /
 *     `elementAttributeLimit` (JDK 8u121+ properties; any one set
 *     fully disables the corresponding limit class).
 *   - `feature/secure-processing` URL or `FEATURE_SECURE_PROCESSING`
 *     constant identifier.
 *
 * Confirmed FP repros (per #166 body):
 *   - languagetool PatternRuleLoader.java:70
 *   - FalseFriendRuleLoader.java:78
 *   - DisambiguationRuleLoader.java:45
 *   - BitextPatternRuleLoader.java:41
 *
 * Recall lock: SAX parsers / DocumentBuilders without any hardening
 * pattern continue to fire `xml-entity-expansion`.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countXxe = (
  findings: Array<{ rule_id?: string }> | undefined,
) => (findings ?? []).filter((f) => f.rule_id === 'xml-entity-expansion').length;

describe('cognium-dev #166 — Java XXE JDK hardening FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // FP #166 — hardening patterns that must suppress the warning
  // -------------------------------------------------------------------------

  it('FP #166 — load-external-dtd feature disabled: no xml-entity-expansion finding', async () => {
    const code = `import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

public class Loader {
  public void load() throws Exception {
    SAXParser sp = SAXParserFactory.newInstance().newSAXParser();
    sp.getXMLReader().setFeature(
      "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    sp.parse("rules.xml", null);
  }
}
`;
    const r = await analyze(code, 'Loader.java', 'java');
    expect(countXxe(r.findings)).toBe(0);
  });

  it('FP #166 — jdk.xml.totalEntitySizeLimit=0: no xml-entity-expansion finding', async () => {
    const code = `import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

public class Loader {
  public void load() throws Exception {
    SAXParser sp = SAXParserFactory.newInstance().newSAXParser();
    sp.setProperty("jdk.xml.totalEntitySizeLimit", 0);
    sp.parse("rules.xml", null);
  }
}
`;
    const r = await analyze(code, 'Loader.java', 'java');
    expect(countXxe(r.findings)).toBe(0);
  });

  it('FP #166 — jdk.xml.entityExpansionLimit=0: no xml-entity-expansion finding', async () => {
    const code = `import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

public class Loader {
  public void load() throws Exception {
    SAXParser sp = SAXParserFactory.newInstance().newSAXParser();
    sp.setProperty("jdk.xml.entityExpansionLimit", 0);
    sp.parse("rules.xml", null);
  }
}
`;
    const r = await analyze(code, 'Loader.java', 'java');
    expect(countXxe(r.findings)).toBe(0);
  });

  it('FP #166 — XMLConstants.FEATURE_SECURE_PROCESSING constant: no xml-entity-expansion finding', async () => {
    const code = `import javax.xml.XMLConstants;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

public class Loader {
  public void load() throws Exception {
    SAXParserFactory f = SAXParserFactory.newInstance();
    f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    SAXParser sp = f.newSAXParser();
    sp.parse("rules.xml", null);
  }
}
`;
    const r = await analyze(code, 'Loader.java', 'java');
    expect(countXxe(r.findings)).toBe(0);
  });

  it('FP #166 — feature/secure-processing URL string: no xml-entity-expansion finding', async () => {
    const code = `import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

public class Loader {
  public void load() throws Exception {
    SAXParserFactory f = SAXParserFactory.newInstance();
    f.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);
    SAXParser sp = f.newSAXParser();
    sp.parse("rules.xml", null);
  }
}
`;
    const r = await analyze(code, 'Loader.java', 'java');
    expect(countXxe(r.findings)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Recall locks — no hardening pattern means the warning must fire
  // -------------------------------------------------------------------------

  it('Recall — SAXParserFactory.newInstance().newSAXParser() with NO safe features: xml-entity-expansion finding fires', async () => {
    const code = `import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

public class Loader {
  public void load() throws Exception {
    SAXParser sp = SAXParserFactory.newInstance().newSAXParser();
    sp.parse("rules.xml", null);
  }
}
`;
    const r = await analyze(code, 'Loader.java', 'java');
    expect(countXxe(r.findings)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — setFeature(...) on an unrelated feature (no hardening keyword): xml-entity-expansion finding fires', async () => {
    const code = `import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

public class Loader {
  public void load() throws Exception {
    SAXParserFactory f = SAXParserFactory.newInstance();
    f.setFeature("http://xml.org/sax/features/namespaces", true);
    SAXParser sp = f.newSAXParser();
    sp.parse("rules.xml", null);
  }
}
`;
    const r = await analyze(code, 'Loader.java', 'java');
    expect(countXxe(r.findings)).toBeGreaterThanOrEqual(1);
  });
});
