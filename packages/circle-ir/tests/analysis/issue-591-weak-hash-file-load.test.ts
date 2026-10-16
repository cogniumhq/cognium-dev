/**
 * cognium-dev#591 (second slice) — `Properties.load(...)` from a file path.
 *
 * The first slice resolved `load(...getResourceAsStream("<name>"))` to a supplied
 * `.properties` resource. This slice adds the file-path load styles, still driven by
 * the `load(...)` argument with no file-name or key-name allowlist:
 *   new FileInputStream("<path>") / new FileReader("<path>")  (optionally via `new File("<path>")`)
 *   Files.newInputStream(Paths.get("<path>")) / Files.newBufferedReader(Path.of("<path>"))
 *   ClassLoader.getSystemResourceAsStream("<name>")
 * A path that is not a single string literal resolves nothing.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import type { AnalyzerOptions } from '../../src/index.js';

const weakHash = (r: { findings?: Array<{ rule_id: string; evidence?: Record<string, unknown> }> }) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'weak-hash');

const res = (path: string, text: string): AnalyzerOptions => ({ resources: new Map([[path, text]]) });

/** A method that loads `Properties cfg` with the given statements, then hashes the configured algorithm. */
const loader = (load: string[], extra: string[] = []): string =>
  [
    'import java.io.*;',
    'import java.nio.file.*;',
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

const styles: Array<[string, string[]]> = [
  ['new FileInputStream(path) inline', ['cfg.load(new FileInputStream("conf/crypto.properties"));']],
  ['new FileInputStream(new File(path)) inline', ['cfg.load(new FileInputStream(new File("conf/crypto.properties")));']],
  ['new FileReader(path) inline', ['cfg.load(new FileReader("conf/crypto.properties"));']],
  ['Files.newInputStream(Paths.get(path))', ['cfg.load(Files.newInputStream(Paths.get("conf/crypto.properties")));']],
  ['Files.newBufferedReader(Path.of(path))', ['cfg.load(Files.newBufferedReader(Path.of("conf/crypto.properties")));']],
  [
    'FileInputStream local in try-with-resources',
    ['try (FileInputStream in = new FileInputStream("conf/crypto.properties")) {', '  cfg.load(in);', '}'],
  ],
  [
    'FileInputStream local assigned before the load',
    ['InputStream in = new FileInputStream("conf/crypto.properties");', 'cfg.load(in);', 'in.close();'],
  ],
  [
    'load argument wrapped over several lines',
    ['cfg.load(', '    new FileInputStream(', '        "conf/crypto.properties"));'],
  ],
  ['ClassLoader.getSystemResourceAsStream', ['cfg.load(ClassLoader.getSystemResourceAsStream("conf/crypto.properties"));']],
];

describe('#591 slice 2: a file-path load resolves to the supplied resource', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it.each(styles)('%s: weak value fires CWE-328, strong value stays clean', async (_label, load) => {
    const weak = await analyze(loader(load), 'Hasher.java', 'java', res('/work/app/conf/crypto.properties', 'digest.alg=MD5\n'));
    const f = weakHash(weak);
    expect(f).toHaveLength(1);
    expect((f[0] as { cwe?: string }).cwe).toBe('CWE-328');
    expect(f[0].evidence?.algorithm).toBe('md5');

    const strong = await analyze(loader(load), 'Hasher.java', 'java', res('/work/app/conf/crypto.properties', 'digest.alg=SHA-256\n'));
    expect(weakHash(strong)).toHaveLength(0);
  });

  it('is not keyed on names: another file, key and default still fire', async () => {
    const code = loader(['cfg.load(new FileInputStream("settings/hashing.properties"));']).replace(
      'cfg.getProperty("digest.alg", "SHA-512")',
      'cfg.getProperty("fingerprint.mode", "SHA-384")',
    );
    const weak = await analyze(code, 'Other.java', 'java', res('settings/hashing.properties', 'fingerprint.mode = SHA1\n'));
    expect(weakHash(weak)).toHaveLength(1);
    const strong = await analyze(code, 'Other.java', 'java', res('settings/hashing.properties', 'fingerprint.mode = SHA-512\n'));
    expect(weakHash(strong)).toHaveLength(0);
  });

  it('an unresolvable key falls back to the default literal (strong default stays clean)', async () => {
    const r = await analyze(
      loader(['cfg.load(new FileInputStream("conf/crypto.properties"));']),
      'Hasher.java',
      'java',
      res('conf/crypto.properties', 'other.key=MD5\n'),
    );
    expect(weakHash(r)).toHaveLength(0);
  });

  it('without resources a strong default stays clean (unchanged behaviour)', async () => {
    const r = await analyze(loader(['cfg.load(new FileInputStream("conf/crypto.properties"));']), 'Hasher.java', 'java');
    expect(weakHash(r)).toHaveLength(0);
  });
});

describe('#591 slice 2: shapes that must not resolve', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const weakRes = res('conf/crypto.properties', 'digest.alg=MD5\n');
  const clean = async (code: string, options: AnalyzerOptions = weakRes) => {
    const r = await analyze(code, 'Hasher.java', 'java', options);
    expect(weakHash(r)).toHaveLength(0);
  };

  it('a path with a different name does not apply', async () => {
    await clean(loader(['cfg.load(new FileInputStream("conf/other.properties"));']));
  });

  it('a path that only shares a suffix with the file name does not apply', async () => {
    await clean(loader(['cfg.load(new FileInputStream("crypto.properties"));']), res('conf/mycrypto.properties', 'digest.alg=MD5\n'));
  });

  it('a path built by concatenation is not a literal', async () => {
    await clean(loader(['cfg.load(new FileInputStream("conf/" + other + ".properties"));']));
  });

  it('a path held in a variable is not resolved', async () => {
    await clean(loader(['String path = "conf/crypto.properties";', 'cfg.load(new FileInputStream(path));']));
  });

  it('Paths.get with several segments is not resolved', async () => {
    await clean(loader(['cfg.load(Files.newInputStream(Paths.get("conf", "crypto.properties")));']));
  });

  it('a path that climbs out of the tree is not resolved', async () => {
    await clean(loader(['cfg.load(new FileInputStream("../conf/crypto.properties"));']));
  });

  it('a stream local reassigned to an unresolved source before the load is not resolved', async () => {
    await clean(
      loader([
        'InputStream in = new FileInputStream("conf/crypto.properties");',
        'in = openFor(other);',
        'cfg.load(in);',
      ]),
    );
  });

  it('a stream local reassigned to another resolvable file uses the last one', async () => {
    const code = loader([
      'InputStream in = new FileInputStream("conf/crypto.properties");',
      'in = new FileInputStream("conf/safe.properties");',
      'cfg.load(in);',
    ]);
    await clean(code, {
      resources: new Map([
        ['conf/crypto.properties', 'digest.alg=MD5\n'],
        ['conf/safe.properties', 'digest.alg=SHA-256\n'],
      ]),
    });
  });

  it('two different files match the path: ambiguous, not resolved', async () => {
    await clean(loader(['cfg.load(new FileInputStream("crypto.properties"));']), {
      resources: new Map([
        ['a/crypto.properties', 'digest.alg=MD5\n'],
        ['b/crypto.properties', 'digest.alg=SHA-256\n'],
      ]),
    });
  });

  it('the file is wrapped in a call that is not a plain reader (decorated source is not resolved)', async () => {
    await clean(loader(['cfg.load(decrypt(new FileInputStream("conf/crypto.properties")));']));
  });

  it('the file is loaded into a different Properties object than the one read', async () => {
    const code = [
      'import java.io.*;',
      'import java.security.MessageDigest;',
      'import java.util.Properties;',
      'public class Hasher {',
      '  public byte[] run(byte[] data) throws Exception {',
      '    Properties cfg = new Properties();',
      '    Properties scratch = new Properties();',
      '    scratch.load(new FileInputStream("conf/crypto.properties"));',
      '    String alg = cfg.getProperty("digest.alg", "SHA-512");',
      '    return MessageDigest.getInstance(alg).digest(data);',
      '  }',
      '}',
      '',
    ].join('\n');
    await clean(code);
  });

  it('twin: a literal MD5 still fires and a literal SHA-512 stays clean with resources present', async () => {
    const mk = (a: string) =>
      [
        'import java.security.MessageDigest;',
        'public class Fixed {',
        `  public byte[] h(byte[] d) throws Exception { return MessageDigest.getInstance("${a}").digest(d); }`,
        '}',
        '',
      ].join('\n');
    expect(weakHash(await analyze(mk('MD5'), 'Fixed.java', 'java', res('conf/crypto.properties', 'digest.alg=SHA-256')))).toHaveLength(1);
    expect(weakHash(await analyze(mk('SHA-512'), 'Fixed.java', 'java', weakRes))).toHaveLength(0);
  });
});
