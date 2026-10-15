/**
 * cognium-dev#591 (first slice) — optional `AnalyzerOptions.resources`: project
 * resource files (`*.properties`) reach the weak-hash pass, which resolves
 * `Properties.load(...getResourceAsStream("<name>"))` to the matching resource
 * and looks up `getProperty(key)`.
 *
 * No file-name or key-name allowlist: the resolver follows the `load(...)`
 * argument. A missing key (or no resources) keeps today's behaviour, the
 * default literal.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, analyzeProject, initAnalyzer } from '../../src/analyzer.js';
import type { AnalyzerOptions } from '../../src/index.js';

const weakHash = (r: { findings?: Array<{ rule_id: string; evidence?: Record<string, unknown> }> }) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'weak-hash');

const service = (opts: { resource?: string; key?: string; dflt?: string } = {}) => `
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Properties;

public class DigestService {
  public byte[] fingerprint(byte[] data) throws Exception {
    Properties cfg = new Properties();
    try (InputStream in = DigestService.class.getClassLoader().getResourceAsStream("${opts.resource ?? 'app.properties'}")) {
      cfg.load(in);
    }
    String alg = cfg.getProperty("${opts.key ?? 'digest.alg'}", "${opts.dflt ?? 'SHA-512'}");
    MessageDigest md = MessageDigest.getInstance(alg);
    return md.digest(data);
  }
}
`;

const res = (path: string, text: string): AnalyzerOptions => ({ resources: new Map([[path, text]]) });

describe('#591: properties resources resolve a getProperty algorithm', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('a weak value in the loaded resource fires CWE-328 although the default is strong', async () => {
    const r = await analyze(service(), 'DigestService.java', 'java', res('src/main/resources/app.properties', 'digest.alg=MD5\n'));
    const f = weakHash(r);
    expect(f).toHaveLength(1);
    expect((f[0] as { cwe?: string }).cwe).toBe('CWE-328');
    expect(f[0].evidence?.algorithm).toBe('md5');
  });

  it('twin: the same code with a strong value in the resource stays clean', async () => {
    const r = await analyze(service(), 'DigestService.java', 'java', res('src/main/resources/app.properties', 'digest.alg=SHA-256\n'));
    expect(weakHash(r)).toHaveLength(0);
  });

  it('is not keyed on names: another resource name and key still fire (and SHA1 with ":" separator)', async () => {
    const code = service({ resource: 'crypto/settings.properties', key: 'hash.algorithm', dflt: 'SHA-384' });
    const r = await analyze(code, 'Other.java', 'java', res('/work/proj/crypto/settings.properties', '# digest\nhash.algorithm : SHA1\n'));
    expect(weakHash(r)).toHaveLength(1);
  });

  it('the resolver follows the load() argument: a different resource name does not apply', async () => {
    const r = await analyze(service({ resource: 'app.properties' }), 'DigestService.java', 'java', res('other.properties', 'digest.alg=MD5\n'));
    expect(weakHash(r)).toHaveLength(0);
  });

  it('an ambiguous resource name (two different files match) is not resolved', async () => {
    const options: AnalyzerOptions = {
      resources: new Map([
        ['a/app.properties', 'digest.alg=MD5\n'],
        ['b/app.properties', 'digest.alg=SHA-256\n'],
      ]),
    };
    const r = await analyze(service(), 'DigestService.java', 'java', options);
    expect(weakHash(r)).toHaveLength(0);
  });

  it('an unresolvable key falls back to the default literal: a strong default stays clean', async () => {
    const r = await analyze(service(), 'DigestService.java', 'java', res('app.properties', 'other.key=MD5\n'));
    expect(weakHash(r)).toHaveLength(0);
  });

  it('an unresolvable key falls back to the default literal: a weak default still fires', async () => {
    const r = await analyze(service({ dflt: 'MD5' }), 'DigestService.java', 'java', res('app.properties', 'other.key=SHA-256\n'));
    expect(weakHash(r)).toHaveLength(1);
  });

  it('without resources a strong default stays clean (unchanged behaviour)', async () => {
    const r = await analyze(service(), 'DigestService.java', 'java');
    expect(weakHash(r)).toHaveLength(0);
  });

  it('a literal getInstance("SHA-512") stays clean even when a resource holds a weak value', async () => {
    const code = `
import java.security.MessageDigest;
public class Fixed {
  public byte[] h(byte[] d) throws Exception {
    return MessageDigest.getInstance("SHA-512").digest(d);
  }
}
`;
    const r = await analyze(code, 'Fixed.java', 'java', res('app.properties', 'digest.alg=MD5\n'));
    expect(weakHash(r)).toHaveLength(0);
  });

  it('a literal getInstance("MD5") still fires with resources present', async () => {
    const code = `
import java.security.MessageDigest;
public class Fixed {
  public byte[] h(byte[] d) throws Exception {
    return MessageDigest.getInstance("MD5").digest(d);
  }
}
`;
    const r = await analyze(code, 'Fixed.java', 'java', res('app.properties', 'digest.alg=SHA-256\n'));
    expect(weakHash(r)).toHaveLength(1);
  });

  it('load(getResourceAsStream("/name")) inline, and getProperty passed straight to getInstance', async () => {
    const code = `
import java.security.MessageDigest;
import java.util.Properties;

public class Inline {
  public byte[] h(byte[] d) throws Exception {
    Properties p = new Properties();
    p.load(Inline.class.getResourceAsStream("/hash.properties"));
    MessageDigest md = MessageDigest.getInstance(p.getProperty("algo", "SHA-256"));
    return md.digest(d);
  }
}
`;
    const weak = await analyze(code, 'Inline.java', 'java', res('hash.properties', 'algo=SHA-1'));
    expect(weakHash(weak)).toHaveLength(1);
    const strong = await analyze(code, 'Inline.java', 'java', res('hash.properties', 'algo=SHA-512'));
    expect(weakHash(strong)).toHaveLength(0);
  });

  it('a property that is not loaded from a resource (no load call) is not resolved', async () => {
    const code = `
import java.security.MessageDigest;
import java.util.Properties;

public class NoLoad {
  public byte[] h(Properties p, byte[] d) throws Exception {
    String alg = p.getProperty("digest.alg", "SHA-512");
    return MessageDigest.getInstance(alg).digest(d);
  }
}
`;
    const r = await analyze(code, 'NoLoad.java', 'java', res('app.properties', 'digest.alg=MD5'));
    expect(weakHash(r)).toHaveLength(0);
  });

  it('analyzeProject threads resources to the per-file pass', async () => {
    const project = await analyzeProject(
      [{ code: service(), filePath: 'src/main/java/DigestService.java', language: 'java' }],
      res('src/main/resources/app.properties', 'digest.alg=MD5'),
    );
    const flat = project.files.flatMap((f) => weakHash(f.analysis));
    expect(flat).toHaveLength(1);
  });
});

describe('#591 review: getProperty resolution scoped to method, skip reassignment', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // Review claim (1): FP — later reassignment to strong literal ignored when resource is weak
  it('reassigned to a strong literal after getProperty (resource weak) stays clean', async () => {
    const code = `
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Properties;

public class ReassignStrong {
  public byte[] fingerprint(byte[] data) throws Exception {
    Properties p = new Properties();
    try (InputStream in = ReassignStrong.class.getClassLoader().getResourceAsStream("app.properties")) {
      p.load(in);
    }
    String alg = p.getProperty("a", "SHA-512");
    alg = "SHA-256";
    MessageDigest md = MessageDigest.getInstance(alg);
    return md.digest(data);
  }
}
`;
    const r = await analyze(code, 'ReassignStrong.java', 'java', res('app.properties', 'a=MD5\n'));
    expect(weakHash(r)).toHaveLength(0);
  });

  // Strong-value twin of (1): resource strong, reassigned to weak — still fires via literal/const-prop
  it('reassigned to "MD5" after a strong resource value still fires', async () => {
    const code = `
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Properties;

public class ReassignWeak {
  public byte[] fingerprint(byte[] data) throws Exception {
    Properties p = new Properties();
    try (InputStream in = ReassignWeak.class.getClassLoader().getResourceAsStream("app.properties")) {
      p.load(in);
    }
    String alg = p.getProperty("a", "SHA-512");
    alg = "MD5";
    MessageDigest md = MessageDigest.getInstance(alg);
    return md.digest(data);
  }
}
`;
    const r = await analyze(code, 'ReassignWeak.java', 'java', res('app.properties', 'a=SHA-256\n'));
    const f = weakHash(r);
    expect(f).toHaveLength(1);
    expect(f[0].evidence?.algorithm).toBe('md5');
  });

  // Review claim (2): lost TP — resource strong, reassigned to weak; without fix resource wins and reports nothing
  // (covered by the test above; without resources the same shape still fires)
  it('without resources, reassigned to "MD5" after getProperty still fires', async () => {
    const code = `
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Properties;

public class ReassignWeakNoRes {
  public byte[] fingerprint(byte[] data) throws Exception {
    Properties p = new Properties();
    try (InputStream in = ReassignWeakNoRes.class.getClassLoader().getResourceAsStream("app.properties")) {
      p.load(in);
    }
    String alg = p.getProperty("a", "SHA-512");
    alg = "MD5";
    MessageDigest md = MessageDigest.getInstance(alg);
    return md.digest(data);
  }
}
`;
    const r = await analyze(code, 'ReassignWeakNoRes.java', 'java');
    expect(weakHash(r)).toHaveLength(1);
  });

  // Review claim (3): same-named var in another method must not poison this method
  it('a same-named var in an earlier method does not poison a later method with a strong literal', async () => {
    const code = `
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Properties;

public class CrossMethod {
  public byte[] fromResource(byte[] data) throws Exception {
    Properties p = new Properties();
    try (InputStream in = CrossMethod.class.getClassLoader().getResourceAsStream("app.properties")) {
      p.load(in);
    }
    String alg = p.getProperty("a", "SHA-512");
    return MessageDigest.getInstance(alg).digest(data);
  }

  public byte[] fromLiteral(byte[] data) throws Exception {
    String alg = "SHA-256";
    return MessageDigest.getInstance(alg).digest(data);
  }
}
`;
    const r = await analyze(code, 'CrossMethod.java', 'java', res('app.properties', 'a=MD5\n'));
    const f = weakHash(r);
    // Only fromResource should fire; fromLiteral must stay clean
    expect(f).toHaveLength(1);
    expect(f[0].evidence?.algorithm).toBe('md5');
  });
});

describe('#591: properties unicode escapes', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('decodes \\uXXXX in a property value so a weak algorithm still fires', async () => {
    // Properties text contains a literal backslash-u escape: \u004d → 'M', so value is MD5.
    const r = await analyze(
      service(),
      'DigestService.java',
      'java',
      res('app.properties', 'digest.alg=\\u004dD5\n'),
    );
    const f = weakHash(r);
    expect(f).toHaveLength(1);
    expect(f[0].evidence?.algorithm).toBe('md5');
  });
});

describe('#591 review: the load(...) chain is read from the enclosing method only', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // `p.load(...)` in another method must not tell this method which file a
  // same-named `p` came from.
  const crossMethodLoad = `
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Properties;

public class CrossMethodLoad {
  private void warmUp() throws Exception {
    Properties p = new Properties();
    try (InputStream in = CrossMethodLoad.class.getClassLoader().getResourceAsStream("app.properties")) {
      p.load(in);
    }
  }

  public byte[] fingerprint(byte[] data, Properties p) throws Exception {
    String alg = p.getProperty("a", "SHA-256");
    return MessageDigest.getInstance(alg).digest(data);
  }
}
`;

  it('a load of a same-named Properties in another method is not used (weak resource, strong default stays clean)', async () => {
    const r = await analyze(crossMethodLoad, 'CrossMethodLoad.java', 'java', res('app.properties', 'a=MD5\n'));
    expect(weakHash(r)).toHaveLength(0);
  });

  it('twin: with the load in the same method the weak resource value fires', async () => {
    const code = `
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Properties;

public class SameMethodLoad {
  public byte[] fingerprint(byte[] data) throws Exception {
    Properties p = new Properties();
    try (InputStream in = SameMethodLoad.class.getClassLoader().getResourceAsStream("app.properties")) {
      p.load(in);
    }
    String alg = p.getProperty("a", "SHA-256");
    return MessageDigest.getInstance(alg).digest(data);
  }
}
`;
    const r = await analyze(code, 'SameMethodLoad.java', 'java', res('app.properties', 'a=MD5\n'));
    const f = weakHash(r);
    expect(f).toHaveLength(1);
    expect(f[0].evidence?.algorithm).toBe('md5');
  });

  // The InputStream local the load reads from is also looked up in this method only.
  it('an InputStream local of the same name bound in another method is not used', async () => {
    const code = `
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Properties;

public class CrossMethodStream {
  private InputStream in;

  private void open() throws Exception {
    in = CrossMethodStream.class.getClassLoader().getResourceAsStream("app.properties");
  }

  public byte[] fingerprint(byte[] data) throws Exception {
    Properties cfg = new Properties();
    cfg.load(in);
    String alg = cfg.getProperty("a", "SHA-256");
    return MessageDigest.getInstance(alg).digest(data);
  }
}
`;
    const r = await analyze(code, 'CrossMethodStream.java', 'java', res('app.properties', 'a=MD5\n'));
    expect(weakHash(r)).toHaveLength(0);
  });
});
