/**
 * cognium-dev#591 (slice) — `Properties.load(...getResource("name").openStream())`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import type { AnalyzerOptions } from '../../src/index.js';

const weakHash = (r: { findings?: Array<{ rule_id: string; evidence?: Record<string, unknown> }> }) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'weak-hash');

const res = (path: string, text: string): AnalyzerOptions => ({ resources: new Map([[path, text]]) });

const loader = (load: string[], extra: string[] = []): string =>
  [
    'import java.io.*;',
    'import java.security.MessageDigest;',
    'import java.util.Properties;',
    '',
    'public class Hasher {',
    '  public byte[] run(byte[] data, String other) throws Exception {',
    '    Properties cfg = new Properties();',
    ...load.map((l) => '    ' + l),
    ...extra.map((l) => '    ' + l),
    '    String alg = cfg.getProperty("digest.alg", "SHA-512");',
    '    MessageDigest md = MessageDigest.getInstance(alg);',
    '    return md.digest(data);',
    '  }',
    '}',
    '',
  ].join('\n');

const cryptoRes = res('/work/app/conf/crypto.properties', 'digest.alg=MD5\n');
const cryptoStrong = res('/work/app/conf/crypto.properties', 'digest.alg=SHA-256\n');

describe('#591 slice: getResource(..).openStream() resolves to the supplied resource', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const styles: Array<[string, string[]]> = [
    ['Hasher.class.getResource', ['cfg.load(Hasher.class.getResource("conf/crypto.properties").openStream());']],
    [
      'context class loader getResource',
      [
        'cfg.load(Thread.currentThread().getContextClassLoader().getResource("conf/crypto.properties").openStream());',
      ],
    ],
    [
      'InputStream local from getResource in try-with-resources',
      [
        'try (InputStream in = Hasher.class.getResource("/conf/crypto.properties").openStream()) {',
        '  cfg.load(in);',
        '}',
      ],
    ],
  ];

  it.each(styles)('%s: weak value fires CWE-328, strong value stays clean', async (_label, load) => {
    const weak = await analyze(loader(load), 'Hasher.java', 'java', cryptoRes);
    const f = weakHash(weak);
    expect(f).toHaveLength(1);
    expect((f[0] as { cwe?: string }).cwe).toBe('CWE-328');
    expect(f[0].evidence?.algorithm).toBe('md5');

    const strong = await analyze(loader(load), 'Hasher.java', 'java', cryptoStrong);
    expect(weakHash(strong)).toHaveLength(0);
  });

  it('is not keyed on names: another file, key and default still fire', async () => {
    const code = loader(['cfg.load(Hasher.class.getResource("settings/hashing.properties").openStream());']).replace(
      'cfg.getProperty("digest.alg", "SHA-512")',
      'cfg.getProperty("fingerprint.mode", "SHA-384")',
    );
    const weak = await analyze(code, 'Other.java', 'java', res('settings/hashing.properties', 'fingerprint.mode = SHA1\n'));
    expect(weakHash(weak)).toHaveLength(1);
    const strong = await analyze(code, 'Other.java', 'java', res('settings/hashing.properties', 'fingerprint.mode = SHA-512\n'));
    expect(weakHash(strong)).toHaveLength(0);
  });
});

describe('#591 slice: getResource(..).openStream() shapes that must not resolve', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const weakRes = cryptoRes;
  const clean = async (code: string, options: AnalyzerOptions = weakRes) => {
    const r = await analyze(code, 'Hasher.java', 'java', options);
    expect(weakHash(r)).toHaveLength(0);
  };

  it('a different resource name does not apply', async () => {
    await clean(loader(['cfg.load(Hasher.class.getResource("conf/other.properties").openStream());']));
  });

  it('a name that is not one literal is not resolved', async () => {
    await clean(loader(['cfg.load(Hasher.class.getResource("conf/" + other).openStream());']));
    await clean(loader(['String name = "conf/crypto.properties";', 'cfg.load(Hasher.class.getResource(name).openStream());']));
  });

  it('openConnection().getInputStream() is not recognised', async () => {
    await clean(
      loader(['cfg.load(Hasher.class.getResource("conf/crypto.properties").openConnection().getInputStream());']),
    );
  });

  it('a decorated stream (BufferedInputStream) is not recognised', async () => {
    await clean(
      loader([
        'cfg.load(new BufferedInputStream(Hasher.class.getResource("conf/crypto.properties").openStream()));',
      ]),
    );
  });

  it('an unresolvable key falls back to the default literal (strong default stays clean)', async () => {
    await clean(loader(['cfg.load(Hasher.class.getResource("conf/crypto.properties").openStream());']), {
      resources: new Map([['/work/app/conf/crypto.properties', 'other.key=MD5\n']]),
    });
  });

  it('without resources a strong default stays clean (unchanged behaviour)', async () => {
    const r = await analyze(
      loader(['cfg.load(Hasher.class.getResource("conf/crypto.properties").openStream());']),
      'Hasher.java',
      'java',
    );
    expect(weakHash(r)).toHaveLength(0);
  });
});
