/**
 * Sprint 76 — #216 Pattern B (Java inline sanitizers): 2 FPs
 *
 * Closes 2 of 7 remaining scorecard FPs from #216:
 *   - BenignPathNormalize.java: `ROOT.resolve(name).normalize()` then
 *     `if (!full.startsWith(ROOT)) throw new SecurityException(...)`
 *     guard → returns the normalized path. Canonical "resolve under
 *     root + normalize + startsWith guard" safe-pattern.
 *   - BenignRedactedLog.java: inline
 *     `log.info("...{}", user.replaceAll("[\\r\\n\\t]", "_"))` — the
 *     CRLF/tab characters are stripped at the sink call site.
 *
 * 5 Pattern-X (other-language + TS interop) FPs remain on #216 after
 * Sprint 76.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('#216 Sprint 76 — Java inline sanitizer recognition', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TN-1 — BenignPathNormalize.java: resolve+normalize+startsWith guard sanitizes path_traversal + ETE', async () => {
    const code = [
      'package com.demo.benign_corpus;',
      '',
      'import java.nio.file.*;',
      '',
      '/** TN -- normalize under root. */',
      'public class BenignPathNormalize {',
      '    private static final Path ROOT = Paths.get("/data");',
      '    public Path safe(String name) throws Exception {',
      '        Path full = ROOT.resolve(name).normalize();',
      '        if (!full.startsWith(ROOT)) throw new SecurityException("escape");',
      '        return full;',
      '    }',
      '}',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'BenignPathNormalize.java', 'java');
    const pt = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'path_traversal',
    );
    const ete = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'external_taint_escape',
    );
    expect(pt.length).toBe(0);
    expect(ete.length).toBe(0);
  });

  it('TN-2 — BenignRedactedLog.java: inline replaceAll CRLF-strip sanitizes log_injection + ETE', async () => {
    const code = [
      'package com.demo.benign_corpus;',
      '',
      'import org.slf4j.Logger;',
      'import org.slf4j.LoggerFactory;',
      '',
      '/** TN -- structured log. */',
      'public class BenignRedactedLog {',
      '    private static final Logger log = LoggerFactory.getLogger(BenignRedactedLog.class);',
      '    public void logUser(String user) {',
      '        log.info("event=user_lookup value={}", user.replaceAll("[\\r\\n\\t]", "_"));',
      '    }',
      '}',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'BenignRedactedLog.java', 'java');
    const li = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'log_injection',
    );
    const ete = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'external_taint_escape',
    );
    expect(li.length).toBe(0);
    expect(ete.length).toBe(0);
  });

  it('TP-1 — resolve+normalize WITHOUT startsWith guard does NOT sanitize path_traversal', async () => {
    // .normalize() alone is not safe -- "../etc/passwd" normalizes to
    // "etc/passwd" relative to ROOT, but an absolute-path argument like
    // "/etc/passwd" replaces ROOT entirely. The startsWith() guard is
    // the load-bearing check.
    const code = [
      'package com.demo.tp;',
      '',
      'import java.nio.file.*;',
      '',
      'public class UnsafePathNoGuard {',
      '    private static final Path ROOT = Paths.get("/data");',
      '    public Path read(String name) throws Exception {',
      '        Path full = ROOT.resolve(name).normalize();',
      '        return full;',
      '    }',
      '}',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'UnsafePathNoGuard.java', 'java');
    const pt = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'path_traversal',
    );
    // path_traversal MUST still fire when the startsWith guard is absent.
    expect(pt.length).toBeGreaterThan(0);
  });

  it('TP-2 — log.info with unsanitized var does NOT get sanitized by an unrelated replaceAll', async () => {
    // A replaceAll on a DIFFERENT variable must not over-suppress the
    // tainted argument actually passed to log.info().
    const code = [
      'package com.demo.tp;',
      '',
      'import org.slf4j.Logger;',
      'import org.slf4j.LoggerFactory;',
      '',
      'public class UnsafeLog {',
      '    private static final Logger log = LoggerFactory.getLogger(UnsafeLog.class);',
      '    public void logUser(String user, String other) {',
      '        String redacted = other.replaceAll("[\\r\\n\\t]", "_");',
      '        log.info("event={} other={}", user, redacted);',
      '    }',
      '}',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'UnsafeLog.java', 'java');
    const li = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'log_injection',
    );
    // log_injection MUST still fire on the unsanitized `user` arg even
    // though `other.replaceAll(...)` sits on a previous line.
    expect(li.length).toBeGreaterThan(0);
  });
});
