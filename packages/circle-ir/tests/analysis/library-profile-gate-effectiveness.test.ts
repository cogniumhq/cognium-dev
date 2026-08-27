/**
 * cognium-dev — library-profile gates: which ones survive the post-pipeline
 * `taint` rebuild.
 *
 * `analyze()` rebuilds the returned `taint` object from PASS RESULT objects
 * after the pipeline finishes (`analyzer.ts`):
 *
 *     sources: sinkFilter.sources,                 // rebuilt from mergedSources
 *     flows:   interProc.additionalFlows,          // rebuilt from the pass result
 *
 * A pass that filters by mutating `graph.ir.taint.sources` / `.flows` in place
 * therefore has its work discarded — the rebuilt object never sees it.
 * `LibraryProfileSinkGatePass` is unaffected because the sink array it mutates
 * is the one carried into the result.
 *
 * Net effect: under `library/*`, the log_injection sink drop takes effect, but
 * the #236 speculative-source drop and the #245 CWE-22 flow drop do not.
 *
 * CHARACTERIZATION TEST — the `library/production` expectations below assert
 * today's behaviour, including the two that are defective. When the rebuild is
 * fixed, the two marked cases must flip to dropped.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const LOG_INJECTION = [
  'package com.acme.lib;',
  'import org.slf4j.Logger;',
  'public class Svc {',
  '    private static final Logger log = org.slf4j.LoggerFactory.getLogger(Svc.class);',
  '    public void handle(String user) {',
  '        log.info("login attempt: " + user);',
  '    }',
  '}',
].join('\n');

const CWE22 = [
  'package com.acme.lib;',
  'import java.io.*;',
  'public class FileUtil {',
  '    public static File touch(String path) throws Exception {',
  '        File f = new File("/var/data/" + path);',
  '        new FileInputStream(f).close();',
  '        return f;',
  '    }',
  '}',
].join('\n');

const run = async (code: string, file: string, projectProfile?: string) => {
  const opts = projectProfile ? ({ projectProfile } as never) : {};
  const r = await analyze(code, file, 'java', opts);
  return {
    sources: (r.taint?.sources ?? []).map((s) => s.type),
    sinks: (r.taint?.sinks ?? []).map((s) => s.type),
    flows: (r.taint?.flows ?? []).map((f) => `${f.source_type}->${f.sink_type}`),
  };
};

describe('library-profile gates — sink gate takes effect', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('drops log_injection under library/* and keeps it under application/*', async () => {
    expect((await run(LOG_INJECTION, 'Svc.java')).sinks).toContain('log_injection');
    expect((await run(LOG_INJECTION, 'Svc.java', 'library/production')).sinks)
      .not.toContain('log_injection');
    expect((await run(LOG_INJECTION, 'Svc.java', 'application/production')).sinks)
      .toContain('log_injection');
  });
});

describe('library-profile gates — source and CWE-22 flow drops are LOST in the rebuild', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // LibraryProfileSourceGatePass (#236) drops interprocedural_param /
  // constructor_field from graph.ir.taint.sources. The returned sources come
  // from sinkFilter.sources instead, so the drop is invisible.
  it('DEFECT: speculative sources survive under library/production', async () => {
    const lib = await run(CWE22, 'FileUtil.java', 'library/production');
    expect(lib.sources).toContain('interprocedural_param');
  });

  // LibraryProfileCwe22PathGatePass (#245 RC1) filters exactly
  // interprocedural_param -> path_traversal from graph.ir.taint.flows. The
  // returned flows come from interProc.additionalFlows, so the drop is lost.
  it('DEFECT: interprocedural_param -> path_traversal flows survive under library/production', async () => {
    const base = await run(CWE22, 'FileUtil.java');
    const lib = await run(CWE22, 'FileUtil.java', 'library/production');
    expect(base.flows).toContain('interprocedural_param->path_traversal');
    // Should be dropped by the #245 gate; currently identical to the ungated run.
    expect(lib.flows).toEqual(base.flows);
  });
});
