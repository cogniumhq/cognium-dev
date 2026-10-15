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
