/**
 * cognium-dev#280 — library-context severity is NOT recalibrated in circle-ir.
 *
 * #280 reported that library-context cross-boundary findings (command
 * injection, XXE, deserialization, SSRF, SQLi) were rated `medium` on 4.9.8
 * where 3.95 rated them high/critical, and asked whether that was intended
 * precision work or a recall regression.
 *
 * Bisecting the issue's own hutool `RuntimeUtil` example across v3.95.0,
 * v3.150.0, circle-ir-v4.9.8 and HEAD produced byte-identical output at every
 * version: `high:5`, matching the 3.150.0 baseline quoted in the issue. The
 * downgrade does not occur anywhere in this repo, so it is introduced by the
 * consumer building the report, not by the engine.
 *
 * These lock that in: the library-API shape stays `high`, and neither central
 * severity hook can reach it. `applyLibraryApiSurfaceDowngrade` and
 * `applyProjectProfileTransform` both require `LIBRARY_API_SURFACE_TAG`, which
 * is attached at one site (`sink-filter-pass.ts`) gated on Java *and*
 * `code_injection` — so `command_injection` never carries it under any profile.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';
import { LIBRARY_API_SURFACE_TAG } from '../../src/analysis/library-api-surface-downgrade.js';

// The hutool `RuntimeUtil` shape from the issue: a library API whose own
// parameters reach five exec sinks. Source is `interprocedural_param` (not an
// HTTP source), sink family is `command_injection` (a CRITICAL_SINKS member),
// so `calculateSeverity` lands on `pathExists && isCritical -> 'high'`.
const RUNTIME_UTIL = [
  'package cn.hutool.core.util;',
  'import java.io.InputStream;',
  'public class RuntimeUtil {',
  '    public static Process exec(String cmd) throws Exception {',
  '        return Runtime.getRuntime().exec(cmd);',
  '    }',
  '    public static Process exec(String[] cmds) throws Exception {',
  '        return Runtime.getRuntime().exec(cmds);',
  '    }',
  '    public static Process exec(String[] envp, String cmd) throws Exception {',
  '        return Runtime.getRuntime().exec(cmd, envp);',
  '    }',
  '    public static String execForStr(String cmd) throws Exception {',
  '        Process p = new ProcessBuilder(cmd).start();',
  '        InputStream in = p.getInputStream();',
  '        return in.toString();',
  '    }',
  '    public static void openDir(String outDir) throws Exception {',
  '        Runtime.getRuntime().exec("open " + outDir);',
  '    }',
  '}',
].join('\n');

describe('cognium-dev#280 — library-context command_injection stays high', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const findingsFor = async (projectProfile?: string) => {
    const opts = projectProfile ? { projectProfile } : {};
    const r = await analyze(RUNTIME_UTIL, 'RuntimeUtil.java', 'java', opts as never);
    return generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'RuntimeUtil.java', RUNTIME_UTIL, 'java',
      r.taint.sanitizers ?? [],
    );
  };

  it('the hutool RuntimeUtil shape yields 5 command_injection findings, all high', async () => {
    const cmdi = (await findingsFor()).filter((f) => f.type === 'command_injection');
    expect(cmdi).toHaveLength(5);
    expect(cmdi.every((f) => f.severity === 'high')).toBe(true);
    // The issue's 3.150.0 baseline was `high:5` — unchanged here.
    expect(cmdi.filter((f) => f.severity === 'medium')).toHaveLength(0);
  });

  it('severity is identical under library and application profiles', async () => {
    for (const profile of ['library', 'application']) {
      const cmdi = (await findingsFor(profile)).filter((f) => f.type === 'command_injection');
      expect(cmdi).toHaveLength(5);
      expect(cmdi.every((f) => f.severity === 'high')).toBe(true);
    }
  });

  it('command_injection sinks never carry the library-API tag (so no hook can downgrade them)', async () => {
    const r = await analyze(RUNTIME_UTIL, 'RuntimeUtil.java', 'java');
    const cmdiSinks = r.taint.sinks.filter((s) => s.type === 'command_injection');
    expect(cmdiSinks.length).toBeGreaterThan(0);
    expect(cmdiSinks.some((s) => s.tags?.includes(LIBRARY_API_SURFACE_TAG))).toBe(false);
  });
});
