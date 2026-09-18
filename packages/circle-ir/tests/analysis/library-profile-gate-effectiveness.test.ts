/**
 * cognium-dev #288 — library-profile gates: wired up, and expressed as a TAG
 * rather than a deletion.
 *
 * TWO defects, and the second is why the first was not enough.
 *
 * 1. WIRING. Both gates were no-ops end-to-end. The issue diagnosed it as
 *    "in-place mutations discarded by the post-pipeline rebuild"; closer is
 *    that the arrays they mutated were never populated at all. `analyzer.ts`
 *    builds the graph with `taint: { sources: [], sinks: [], sanitizers: [] }`
 *    and nothing assigns to it, so the source gate filtered a permanently
 *    empty array and the CWE-22 gate read an `undefined` `flows`. Nothing was
 *    discarded because nothing was computed — so the fix the issue calls
 *    smallest (have the rebuild read `graph.ir.taint.*`) would have emitted
 *    EMPTY taint. The authoritative lists are the pass results:
 *    `SinkFilterResult.sources` and `InterproceduralPassResult.additionalFlows`.
 *
 *    Ordering mattered too, and the issue does not mention it: the source gate
 *    ran BEFORE `SinkFilterPass`, so the result it needed did not exist yet.
 *
 * 2. POLICY. Wired up as written, the gates DELETE sources and flows. That was
 *    measured before being rejected: on SecuriBench Micro it silently removes
 *    8 genuine `interprocedural_param->xss` true positives (Inter3, Inter7,
 *    Aliasing5, Collections11b, Datastructures3/4) whenever a repo is
 *    classified `library/*` — and a library is precisely where such a bug
 *    propagates to every consumer. Deletion is also invisible: nothing in the
 *    output distinguishes a clean file from a gated one, and the profile is
 *    often auto-detected, so a misclassification silently erases a finding
 *    class.
 *
 *    This codebase already answers the same "caller's responsibility" question
 *    the other way. `applyLibraryApiSurfaceDowngrade` and
 *    `applyProjectProfileTransform` (ADR-008) KEEP the finding, downgrade its
 *    severity and record `original_severity`, so the decision is auditable and
 *    reversible. `TaintFlowInfo.tags` has carried
 *    `library-api-surface:caller-responsibility` since 3.105.0 for exactly
 *    this, and CLI/SARIF consumers already treat it as "downgrade and badge".
 *
 *    So: sources and flows survive, and the library-shape judgement is a tag.
 *
 * Worth recording for whoever revisits the severity policy: ADR-008's
 * `DOWNGRADE_ELIGIBLE_RULE_IDS` deliberately EXCLUDES `path_traversal` — only
 * code_injection / template_injection / xpath_injection / sql_injection are
 * eligible — on the reasoning that a library with a path traversal is a bug
 * whatever its shape. Tagging a CWE-22 flow therefore does not downgrade it
 * today. Deleting those flows, which is what this pass used to do, contradicted
 * that decision outright.
 *
 * Default and `application/*` scans are unaffected by construction:
 * `isLibraryShape(undefined)` is false.
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

// A library-shape helper whose public parameters reach several sink families,
// so the scope of the drop (not just CWE-22) and the sources/flows consistency
// invariant are both observable.
const MIXED_SINKS = [
  'package com.acme.lib;',
  'import java.io.*; import java.sql.*;',
  'public class Util {',
  '    public static File touch(String path) throws Exception {',
  '        File f = new File("/var/data/" + path);',
  '        new FileInputStream(f).close();',
  '        return f;',
  '    }',
  '    public static void find(Connection c, String name) throws Exception {',
  '        Statement s = c.createStatement();',
  '        s.executeQuery("SELECT * FROM t WHERE n = \'" + name + "\'");',
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
    tags: (r.taint?.flows ?? []).flatMap((f) => f.tags ?? []),
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

describe('library-profile gates — the library-shape judgement is a tag, not a deletion (#288)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // LibraryProfileSourceGatePass (#236) now reads SinkFilterResult.sources —
  // the list that is actually assigned to `taint.sources` — instead of the
  // never-populated `graph.ir.taint.sources`.
  it('KEEPS speculative sources under library/production', async () => {
    // Option A: the source list is information the adjudication layer needs.
    const base = await run(CWE22, 'FileUtil.java');
    const lib = await run(CWE22, 'FileUtil.java', 'library/production');
    expect(base.sources).toContain('interprocedural_param');
    expect(lib.sources).toEqual(base.sources);
  });

  it('KEEPS the flow and tags it under library/production', async () => {
    const base = await run(CWE22, 'FileUtil.java');
    const lib = await run(CWE22, 'FileUtil.java', 'library/production');
    expect(base.flows).toContain('interprocedural_param->path_traversal');
    expect(lib.flows).toContain('interprocedural_param->path_traversal');
    expect(lib.tags).toContain('library-api-surface:caller-responsibility');
  });

  it('does not tag under application/* or with no profile', async () => {
    expect((await run(CWE22, 'FileUtil.java')).tags).toHaveLength(0);
    expect((await run(CWE22, 'FileUtil.java', 'application/production')).tags).toHaveLength(0);
  });

  it('does not delete the non-CWE-22 flows either', async () => {
    // Option C removed every flow from a gated source, which on SecuriBench
    // Micro cost 8 genuine interprocedural XSS true positives.
    const base = await run(MIXED_SINKS, 'Util.java');
    const lib = await run(MIXED_SINKS, 'Util.java', 'library/production');
    expect(base.flows).toContain('interprocedural_param->sql_injection');
    expect(lib.flows).toContain('interprocedural_param->sql_injection');
  });

  // The ordering assertion. Gating the source list anywhere after
  // TaintPropagationPass empties `sources[]` while leaving the flows alive, so
  // the IR would advertise flows whose `source_type` is absent from
  // `sources[]`. This is what distinguishes "before flow generation" from the
  // weaker "before InterproceduralPass".
  it('leaves no flow citing a source type absent from sources[]', async () => {
    for (const profile of [undefined, 'library/production', 'application/production']) {
      const r = await run(MIXED_SINKS, 'Util.java', profile);
      const orphans = r.flows.filter((f) => !r.sources.includes(f.split('->')[0]));
      expect(orphans, `profile=${String(profile)}`).toEqual([]);
    }
  });

  // Scope: the drop is not limited to CWE-22. A library-shape parameter
  // reaching a SQL sink is suppressed too. Deliberate (#288) and the reason
  // the recall cost is documented in this file's header.
  // The guard that keeps this from affecting ordinary scans.
  it('does not change default or application/* scans', async () => {
    const base = await run(MIXED_SINKS, 'Util.java');
    const app = await run(MIXED_SINKS, 'Util.java', 'application/production');
    expect(app.sources).toEqual(base.sources);
    expect(app.flows).toEqual(base.flows);
    expect(app.sinks).toEqual(base.sinks);
  });
});
