import { describe, test, expect } from 'bun:test';
import { parseArgs, showHelp, unknownOptions, COMMAND_OPTIONS } from '../src/utils/args.js';

describe('parseArgs', () => {
  test('parses command with no options', () => {
    const result = parseArgs(['scan', 'src/']);
    expect(result.command).toBe('scan');
    expect(result.args).toEqual(['src/']);
    expect(result.options).toEqual({});
  });

  test('parses long options with values', () => {
    const result = parseArgs(['scan', 'src/', '--format', 'json', '--severity', 'high']);
    expect(result.command).toBe('scan');
    expect(result.args).toEqual(['src/']);
    expect(result.options.format).toBe('json');
    expect(result.options.severity).toBe('high');
  });

  test('parses long options with = syntax', () => {
    const result = parseArgs(['scan', 'src/', '--format=sarif', '--threads=8']);
    expect(result.options.format).toBe('sarif');
    expect(result.options.threads).toBe('8');
  });

  test('parses boolean flags', () => {
    const result = parseArgs(['scan', '.', '--exclude-tests', '--quiet', '--verbose']);
    expect(result.options['exclude-tests']).toBe(true);
    expect(result.options.quiet).toBe(true);
    expect(result.options.verbose).toBe(true);
  });

  test('parses short options with values', () => {
    const result = parseArgs(['scan', '.', '-f', 'json', '-o', 'out.json']);
    expect(result.options.f).toBe('json');
    expect(result.options.o).toBe('out.json');
  });

  test('parses short boolean flags', () => {
    const result = parseArgs(['scan', '.', '-q', '-v']);
    expect(result.options.q).toBe(true);
    expect(result.options.v).toBe(true);
  });

  test('handles no arguments', () => {
    const result = parseArgs([]);
    expect(result.command).toBeUndefined();
    expect(result.args).toEqual([]);
    expect(result.options).toEqual({});
  });

  test('handles help flag without command', () => {
    const result = parseArgs(['--help']);
    expect(result.command).toBeUndefined();
    expect(result.options.help).toBe(true);
  });

  test('handles --version flag', () => {
    const result = parseArgs(['--version']);
    expect(result.options.version).toBe(true);
  });

  test('parses command with multiple positional args', () => {
    const result = parseArgs(['list-passes', 'security']);
    expect(result.command).toBe('list-passes');
    expect(result.args).toEqual(['security']);
  });

  test('parses --disable-pass with comma-separated value', () => {
    const result = parseArgs(['scan', '.', '--disable-pass', 'naming-convention,todo-in-prod']);
    expect(result.options['disable-pass']).toBe('naming-convention,todo-in-prod');
  });

  test('parses --profile option', () => {
    const result = parseArgs(['scan', '.', '--profile', 'custom.json']);
    expect(result.options.profile).toBe('custom.json');
  });

  test('parses --exclude-cwe option', () => {
    const result = parseArgs(['scan', '.', '--exclude-cwe', 'CWE-330,CWE-327']);
    expect(result.options['exclude-cwe']).toBe('CWE-330,CWE-327');
  });

  test('treats next arg starting with - as boolean (no value)', () => {
    const result = parseArgs(['scan', '.', '--quiet', '--format', 'json']);
    expect(result.options.quiet).toBe(true);
    expect(result.options.format).toBe('json');
  });

  test('mixed short and long options', () => {
    const result = parseArgs(['scan', 'src/', '-l', 'java', '--severity', 'high', '-f', 'sarif', '-q']);
    expect(result.command).toBe('scan');
    expect(result.args).toEqual(['src/']);
    expect(result.options.l).toBe('java');
    expect(result.options.severity).toBe('high');
    expect(result.options.f).toBe('sarif');
    expect(result.options.q).toBe(true);
  });
});

describe('unknownOptions', () => {
  test('a typo or an option of another command is reported as typed', () => {
    expect(unknownOptions('scan', parseArgs(['scan', '.', '--frobnicate']).options)).toEqual(['--frobnicate']);
    expect(unknownOptions('scan', parseArgs(['scan', '.', '--severty', 'high', '-x']).options)).toEqual(['--severty', '-x']);
    expect(unknownOptions('metrics', parseArgs(['metrics', '.', '--threads', '2']).options)).toEqual(['--threads']);
    expect(unknownOptions('deadcode', parseArgs(['deadcode', '.', '--severity', 'high']).options)).toEqual(['--severity']);
    expect(unknownOptions('list-passes', parseArgs(['list-passes', '-f', 'json']).options)).toEqual(['-f']);
    expect(unknownOptions(undefined, parseArgs(['--frobnicate']).options)).toEqual(['--frobnicate']);
  });

  test('known options pass, in long and short spellings, plus the global ones', () => {
    const argv = ['scan', '.', '-l', 'java', '--format', 'sarif', '-o', 'x', '-q', '-v', '--threads', '2',
      '--file-timeout-ms', '9', '--severity', 'high', '--category', 'security', '--exclude-cwe', 'CWE-1',
      '--disable-pass', 'x', '--exclude-tests', '-p', 'c.json', '--project-profile', 'library/production',
      '--no-project-profile', '--project-profile-explain', '--cross-file-budget-ms', '0',
      '--max-project-source-chars', '0', '--log-level', 'info'];
    expect(unknownOptions('scan', parseArgs(argv).options)).toEqual([]);
    expect(unknownOptions('sbom', parseArgs(['sbom', '.', '--prod', '--prod-only', '--deterministic', '--name', 'n', '--license-map', 'm.json']).options)).toEqual([]);
    expect(unknownOptions('recheck', parseArgs(['recheck', '.', '--changed', 'a', '--baseline', 'b', '-o', 'c']).options)).toEqual([]);
    expect(unknownOptions('scan', parseArgs(['scan', '--help']).options)).toEqual([]);
    expect(unknownOptions(undefined, parseArgs(['--version']).options)).toEqual([]);
  });

  test('an unknown command is left to the unknown-command error', () => {
    expect(unknownOptions('frobnicate', parseArgs(['frobnicate', '--x']).options)).toEqual([]);
  });

  // Refusing unknown options must not refuse a documented one.
  test('every option --help documents is accepted by some command', () => {
    const lines: string[] = [];
    const log = console.log;
    console.log = (...a: unknown[]) => { lines.push(a.join(' ')); };
    try { showHelp(); } finally { console.log = log; }
    const documented = new Set([...lines.join('\n').matchAll(/(?<![\w-])--?([a-zA-Z][\w-]*)/g)].map(m => m[1]));
    // --max-old-space-size is named in the help as a Node.js option (NODE_OPTIONS), not a CLI one;
    // --name-status and -M are git diff flags the recheck --changed help quotes.
    const accepted = new Set(['help', 'h', 'version', 'V', 'log-level', 'max-old-space-size', 'name-status', 'M', ...Object.values(COMMAND_OPTIONS).flat()]);
    expect(documented.size).toBeGreaterThan(30);
    expect([...documented].filter(o => !accepted.has(o))).toEqual([]);
  });
});
