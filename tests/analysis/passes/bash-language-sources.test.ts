/**
 * Bash pattern-based findings tests
 *
 * Tests the five non-DFG pattern rules added to LanguageSourcesPass for Bash:
 *   1. hardcoded-credential (CWE-798)
 *   2. cleartext-transmission (CWE-319)
 *   3. predictable-temp-file (CWE-377)
 *   4. insecure-file-permission (CWE-732)
 *   5. unsafe-archive-extraction (CWE-22)
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

describe('Bash language-sources pattern rules', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ── Hardcoded credentials ──────────────────────────────────────────────

  describe('hardcoded-credential', () => {
    it('detects PASSWORD="literal"', async () => {
      const code = 'PASSWORD="s3cretValue"';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'hardcoded-credential');
      expect(findings.length).toBe(1);
      expect(findings[0].cwe).toBe('CWE-798');
    });

    it('detects API_KEY=literal', async () => {
      const code = 'API_KEY=abcdef123456';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'hardcoded-credential');
      expect(findings.length).toBe(1);
    });

    it('skips PASSWORD=$VAR (variable reference)', async () => {
      const code = 'PASSWORD="$DB_PASS"';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'hardcoded-credential');
      expect(findings.length).toBe(0);
    });

    it('skips comments', async () => {
      const code = '# PASSWORD="s3cretValue"';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'hardcoded-credential');
      expect(findings.length).toBe(0);
    });
  });

  // ── Cleartext HTTP ─────────────────────────────────────────────────────

  describe('cleartext-transmission', () => {
    it('detects curl http://', async () => {
      const code = 'curl http://example.com/api';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'cleartext-transmission');
      expect(findings.length).toBe(1);
      expect(findings[0].cwe).toBe('CWE-319');
    });

    it('detects wget http://', async () => {
      const code = 'wget http://example.com/file.tar.gz';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'cleartext-transmission');
      expect(findings.length).toBe(1);
    });

    it('skips curl https://', async () => {
      const code = 'curl https://example.com/api';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'cleartext-transmission');
      expect(findings.length).toBe(0);
    });
  });

  // ── Predictable /tmp file ──────────────────────────────────────────────

  describe('predictable-temp-file', () => {
    it('detects /tmp/myapp.log', async () => {
      const code = 'echo "data" > /tmp/myapp.log';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'predictable-temp-file');
      expect(findings.length).toBe(1);
      expect(findings[0].cwe).toBe('CWE-377');
    });

    it('skips mktemp usage', async () => {
      const code = 'tmpfile=$(mktemp /tmp/myapp.XXXXXX)';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'predictable-temp-file');
      expect(findings.length).toBe(0);
    });
  });

  // ── Insecure file permissions ──────────────────────────────────────────

  describe('insecure-file-permission', () => {
    it('detects chmod 777', async () => {
      const code = 'chmod 777 /var/www/html';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'insecure-file-permission');
      expect(findings.length).toBe(1);
      expect(findings[0].cwe).toBe('CWE-732');
    });

    it('detects chmod 666', async () => {
      const code = 'chmod 666 /etc/config';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'insecure-file-permission');
      expect(findings.length).toBe(1);
    });

    it('skips chmod 755 (safe)', async () => {
      const code = 'chmod 755 /usr/local/bin/myapp';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'insecure-file-permission');
      expect(findings.length).toBe(0);
    });
  });

  // ── Unsafe archive extraction ──────────────────────────────────────────

  describe('unsafe-archive-extraction', () => {
    it('detects tar -xf without --strip-components', async () => {
      const code = 'tar -xf archive.tar.gz';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'unsafe-archive-extraction');
      expect(findings.length).toBe(1);
      expect(findings[0].cwe).toBe('CWE-22');
    });

    it('skips tar -xf with --strip-components', async () => {
      const code = 'tar -xf archive.tar.gz --strip-components=1';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'unsafe-archive-extraction');
      expect(findings.length).toBe(0);
    });

    it('skips tar -cf (create, not extract)', async () => {
      const code = 'tar -cf backup.tar /home';
      const result = await analyze(code, 'deploy.sh', 'bash');
      const findings = (result.findings ?? []).filter(f => f.rule_id === 'unsafe-archive-extraction');
      expect(findings.length).toBe(0);
    });
  });

  // ── DFG integration ────────────────────────────────────────────────────

  describe('DFG integration', () => {
    it('buildBashDFG produces defs and uses for variable assignment + expansion', async () => {
      const code = 'VAR="hello"\necho "$VAR"';
      const result = await analyze(code, 'test.sh', 'bash');
      expect(result.dfg.defs.some(d => d.variable === 'VAR')).toBe(true);
      expect(result.dfg.uses.some(u => u.variable === 'VAR')).toBe(true);
    });

    it('read creates a DFG def', async () => {
      const code = 'read username';
      const result = await analyze(code, 'test.sh', 'bash');
      expect(result.dfg.defs.some(d => d.variable === 'username')).toBe(true);
    });

    it('for loop variable creates a DFG def', async () => {
      const code = 'for f in *.txt; do\n  echo "$f"\ndone';
      const result = await analyze(code, 'test.sh', 'bash');
      expect(result.dfg.defs.some(d => d.variable === 'f')).toBe(true);
      expect(result.dfg.uses.some(u => u.variable === 'f')).toBe(true);
    });

    it('def-use chain links read → $VAR usage', async () => {
      const code = 'read input\necho "$input"';
      const result = await analyze(code, 'test.sh', 'bash');
      const inputDef = result.dfg.defs.find(d => d.variable === 'input');
      expect(inputDef).toBeDefined();
      const inputUse = result.dfg.uses.find(u => u.variable === 'input');
      expect(inputUse).toBeDefined();
      expect(inputUse!.def_id).toBe(inputDef!.id);
    });
  });

  // ── CFG integration ────────────────────────────────────────────────────

  describe('CFG integration', () => {
    it('buildBashCFG produces blocks for top-level commands', async () => {
      const code = 'echo "start"\nread input\necho "$input"';
      const result = await analyze(code, 'test.sh', 'bash');
      expect(result.cfg.blocks.length).toBeGreaterThan(0);
    });

    it('if_statement creates conditional block', async () => {
      const code = 'if [ -f /etc/passwd ]; then\n  echo "exists"\nfi';
      const result = await analyze(code, 'test.sh', 'bash');
      const conditionalBlocks = result.cfg.blocks.filter(b => b.type === 'conditional');
      expect(conditionalBlocks.length).toBeGreaterThan(0);
    });
  });
});
