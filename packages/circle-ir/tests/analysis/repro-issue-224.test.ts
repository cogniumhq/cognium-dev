import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

/**
 * cognium-dev #224 — CWE-078 regression 3.90.0 → 3.144.0.
 *
 * The CWE-Bench-Java strict score dropped 104/120 → 101/120 across
 * that window, with the entire delta concentrated in CWE-078
 * (command injection). Three CVEs regressed:
 *
 *   - CVE-2020-26217  x-stream/xstream 1.4.14-java7
 *   - CVE-2021-21345  x-stream/xstream 1.4.15
 *   - CVE-2022-20617  jenkinsci/docker-commons-plugin 1.17
 *
 * # Root cause
 *
 * The #128 entry-point gate (Sprint 35, shipped ~3.95.0) classifies
 * methods without framework annotations as TIER_3_LIBRARY_API and
 * drops their `interprocedural_param` sources. Both surfaces failed
 * this test:
 *
 *   1. XStream converters — user classes implement `Converter` /
 *      extend `AbstractReflectionConverter` etc. The trust boundary
 *      is the xstream deserializer invoking `unmarshal(reader, ctx)`
 *      with attacker XML — no framework annotation carries this
 *      contract, so pre-fix the source was silently dropped.
 *
 *   2. Jenkins docker-commons — `DockerRegistryEndpoint` uses
 *      `@DataBoundConstructor` / `@DataBoundSetter` for Stapler form
 *      binding from Jenkins UI. Pre-fix these annotations were not
 *      in the Tier 1 list, so the credential-plumbing methods
 *      dropped their sources.
 *
 * # Fix
 *
 * `entry-point-detection.ts`:
 *   - `TIER_1_METHOD_ANNOTATIONS` += `DataBoundConstructor`,
 *     `DataBoundSetter`.
 *   - `TIER_1_BY_SUPERTYPE` += XStream `Converter`,
 *     `SingleValueConverter`, `ConverterMatcher`,
 *     `AbstractReflectionConverter`, `AbstractSingleValueConverter`,
 *     `AbstractCollectionConverter`.
 *
 * This test asserts the two vuln shapes re-fire against minimal
 * standalone Java fixtures (independent of the CWE-Bench-Java
 * runner) and locks the recall guarantee at the classifier level.
 */
describe('cognium-dev #224 — CWE-078 regression on Java sink surfaces', () => {
  beforeAll(async () => { await initAnalyzer(); });

  // -------------------------------------------------------------------
  // XStream Converter shape (CVE-2020-26217 / CVE-2021-21345 family)
  // -------------------------------------------------------------------

  it('xstream Converter#unmarshal — attacker-controlled reader flows to exec', async () => {
    // Minimal repro of the xstream deserialization-gadget shape:
    // user class implements Converter, unmarshal(reader, ctx) pulls
    // an attribute off the attacker-supplied reader, and passes it
    // to Runtime.exec. Pre-fix, `reader` was Tier-3-gated so the
    // interprocedural_param source vanished before propagation.
    const code = `
package com.demo.converter;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

public class GadgetConverter implements Converter {
    public boolean canConvert(Class type) { return true; }
    public void marshal(Object src, HierarchicalStreamWriter w, MarshallingContext ctx) { }
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext ctx) throws Exception {
        String cmd = reader.getValue();
        Runtime.getRuntime().exec(cmd);
        return null;
    }
}
`;
    const ir = await analyze(code, 'GadgetConverter.java', 'java');
    const cmdFlows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(cmdFlows.length).toBeGreaterThan(0);
  });

  it('xstream AbstractReflectionConverter subclass — doUnmarshal recall guard', async () => {
    // The `extends AbstractReflectionConverter` shape is common for
    // user-authored converters that reuse xstream's reflection base.
    // The `doUnmarshal` override is the attacker-facing hook.
    const code = `
package com.demo.converter;

import com.thoughtworks.xstream.converters.reflection.AbstractReflectionConverter;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;

public class MyReflectionConverter extends AbstractReflectionConverter {
    public MyReflectionConverter() { super(null, null); }
    public boolean canConvert(Class type) { return true; }
    public Object doUnmarshal(Object result, HierarchicalStreamReader reader, UnmarshallingContext ctx) throws Exception {
        String cmd = reader.getValue();
        Runtime.getRuntime().exec(cmd);
        return result;
    }
}
`;
    const ir = await analyze(code, 'MyReflectionConverter.java', 'java');
    const cmdFlows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(cmdFlows.length).toBeGreaterThan(0);
  });

  it('xstream SingleValueConverter#fromString — string-form recall guard', async () => {
    const code = `
package com.demo.converter;

import com.thoughtworks.xstream.converters.SingleValueConverter;

public class StringExecConverter implements SingleValueConverter {
    public boolean canConvert(Class type) { return true; }
    public String toString(Object obj) { return String.valueOf(obj); }
    public Object fromString(String s) throws Exception {
        Runtime.getRuntime().exec(s);
        return s;
    }
}
`;
    const ir = await analyze(code, 'StringExecConverter.java', 'java');
    const cmdFlows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(cmdFlows.length).toBeGreaterThan(0);
  });

  // -------------------------------------------------------------------
  // Jenkins Stapler shape (CVE-2022-20617 docker-commons family)
  // -------------------------------------------------------------------

  it('Jenkins @DataBoundConstructor — user-supplied param flows to exec', async () => {
    // Minimal repro of the DockerRegistryEndpoint shape: the
    // constructor is Stapler-bound to a Jenkins UI form; every
    // parameter is a user-controlled taint source.
    const code = `
package com.demo.jenkins;

import org.kohsuke.stapler.DataBoundConstructor;

public class RegistryEndpoint {
    @DataBoundConstructor
    public RegistryEndpoint(String url, String credentialsId) throws Exception {
        Runtime.getRuntime().exec(credentialsId);
    }
}
`;
    const ir = await analyze(code, 'RegistryEndpoint.java', 'java');
    const cmdFlows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(cmdFlows.length).toBeGreaterThan(0);
  });

  it('Jenkins @DataBoundSetter — user-supplied setter param flows to exec', async () => {
    const code = `
package com.demo.jenkins;

import org.kohsuke.stapler.DataBoundSetter;

public class RegistryEndpoint {
    @DataBoundSetter
    public void setRegistryUrl(String registryUrl) throws Exception {
        Runtime.getRuntime().exec(registryUrl);
    }
}
`;
    const ir = await analyze(code, 'RegistryEndpoint.java', 'java');
    const cmdFlows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(cmdFlows.length).toBeGreaterThan(0);
  });

  // -------------------------------------------------------------------
  // Precision locks — new seeds must NOT trigger on non-target shapes
  // -------------------------------------------------------------------

  // Precision at the classifier level (matches repro-issue-128 pattern).
  // The entry-point gate is applied inside InterproceduralPass; asserting
  // at classifier level is the tightest way to lock the shape rules.

  it('precision lock — Converter helper method (non-lifecycle) classifies TIER_3', async () => {
    // Only the named lifecycle methods (marshal/unmarshal/fromString/
    // toString/doMarshal/doUnmarshal) are TIER_1 for Converter-shaped
    // classes. A helper method on the same class must stay TIER_3.
    const { classifyEntryPointTier } = await import('../../src/analysis/entry-point-detection.js');
    const helperMethod = {
      name: 'formatEntry',
      return_type: 'String',
      parameters: [{ name: 'key', type: 'String', annotations: [] }],
      annotations: [],
      modifiers: ['public'],
      start_line: 10,
      end_line: 15,
    };
    const converterType = {
      name: 'HelperOnlyConverter',
      kind: 'class' as const,
      package: null,
      extends: null,
      implements: ['Converter'],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 1,
      end_line: 20,
    };
    expect(classifyEntryPointTier(helperMethod, converterType, { language: 'java' }))
      .toBe('TIER_3_LIBRARY_API');
  });

  it('precision lock — @DataBoundConstructor on a *Util facade stays TIER_3', async () => {
    // Class-shape short-circuit (library-facade override) runs BEFORE
    // annotation detection, so an accidental *Util class carrying
    // @DataBoundConstructor stays TIER_3.
    const { classifyEntryPointTier } = await import('../../src/analysis/entry-point-detection.js');
    const ctor = {
      name: 'CredentialsUtil',
      return_type: null,
      parameters: [{ name: 'cmd', type: 'String', annotations: [] }],
      annotations: ['@DataBoundConstructor'],
      modifiers: ['public'],
      start_line: 10,
      end_line: 15,
    };
    const utilType = {
      name: 'CredentialsUtil',
      kind: 'class' as const,
      package: null,
      extends: null,
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 1,
      end_line: 20,
    };
    expect(classifyEntryPointTier(ctor, utilType, { language: 'java' }))
      .toBe('TIER_3_LIBRARY_API');
  });
});
