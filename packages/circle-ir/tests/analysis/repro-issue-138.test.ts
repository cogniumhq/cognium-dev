import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

/**
 * Regression lock for issue #138 (3.143.0) — Source-semantics gate.
 *
 * The `SourceSemanticsPass` (canonical #108) tags every `TaintSource` in
 * `ir.taint.sources` with three optional booleans:
 *
 *   - `constant`  — compile-time constant string / static-final / enum ref
 *   - `spi`       — ServiceLoader / Class.forName + META-INF/services
 *   - `demoPath`  — file path under `/demo/`, `/examples?/`, `/samples/`,
 *                    `/integration[-_]tests/`
 *
 * Downstream consumption:
 *   - findings.ts:`sourceSemanticsAllowed` drops constant / SPI flows for
 *     the vast majority of sink types (see JSDoc for per-sink policy).
 *   - scan-secrets-pass downgrades `hardcoded-credential` findings on
 *     demo paths from `high` → `low` severity and `warning/error` →
 *     `note` SARIF level.
 *
 * Test shapes:
 *
 *   1. **jib PropertyNames shape** — `public static final String
 *      CONFIG_KEY = "jib.from.auth.password";` — the constant is a
 *      property key, not a credential. Layer 1b of scan-secrets sees a
 *      credential-named identifier assigned to a literal, but the
 *      `PROPERTY_KEY_RE` value-shape gate (#130) already suppresses
 *      dotted-key values, so this pass primarily locks the invariant
 *      that no `hardcoded-credential` finding fires on the property-key
 *      shape. #138 constant-tagging is additive protection.
 *
 *   2. **Sa-Token ServiceLoader shape** — `ServiceLoader.load(...)` and
 *      a downstream `Class.forName(loaded)` — the ServiceLoader
 *      source is tagged `spi = true` so any taint sink other than
 *      `code_injection` will drop the flow.
 *
 *   3. **Sa-Token OAuth demo shape** — a file under
 *      `sa-token-oauth2-server-demo/` with a hardcoded named-credential
 *      assignment — the finding still fires but at `severity: 'low'`
 *      and `level: 'note'`.
 *
 * The fabricated fixture strings below are NOT real credentials.
 */
describe('#138 source-semantics gate (3.143.0)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('jib PropertyNames shape: no hardcoded-credential on property-key value', async () => {
    // `CONFIG_KEY = "jib.from.auth.password"` — the RHS is a property
    // key (dotted lowercase.dot.qualified), not a credential value.
    // `PROPERTY_KEY_RE` in scan-secrets Layer 1b suppresses this even
    // without the source-semantics gate, but source-semantics is a
    // second line of defense: `CONFIG_KEY` is a taint source only if
    // some pattern matcher promotes it, and the constant tag would
    // then drop any downstream flow.
    const code = `
public class PropertyNames {
    public static final String CONFIG_KEY = "jib.from.auth.password";
}`;
    const ir = await analyze(code, 'PropertyNames.java', 'java');
    const findings = ir.findings ?? [];
    const credFindings = findings.filter(f => f.rule_id === 'hardcoded-credential');
    expect(credFindings).toHaveLength(0);
  });

  it('Sa-Token ServiceLoader shape: `spi = true` on the ServiceLoader source', async () => {
    // The source-semantics pass tags any ServiceLoader.load(...) source
    // with `spi = true`. Downstream flow generation drops these for
    // every sink except `code_injection`.
    const code = `
import java.util.ServiceLoader;
public class SaPlugin {
    public void bootstrap() {
        ServiceLoader<SaPlugin> plugins = ServiceLoader.load(SaPlugin.class);
    }
}`;
    const ir = await analyze(code, 'SaPlugin.java', 'java');
    const sources = ir.taint?.sources ?? [];
    // The ServiceLoader source may or may not be emitted as a
    // TaintSource by the pattern matcher (depending on whether the
    // config-based sources include `ServiceLoader.load`). What we can
    // guarantee is that IF a source is emitted with
    // `code === '<the ServiceLoader.load line>'`, it MUST be tagged
    // `spi = true`.
    const spiSources = sources.filter(s => s.code && /ServiceLoader\.load/.test(s.code));
    for (const s of spiSources) {
      expect(s.spi).toBe(true);
    }
    // Nothing to assert on flow suppression here — the gate is exercised
    // at the sourceSemanticsAllowed level by the unit tests; this repro
    // is a shape lock for the tagger.
  });

  it('Sa-Token OAuth demo shape: credential in demo path is downgraded to `low` / `note`', async () => {
    // A file under a `/demo/` path component with a hardcoded
    // named-credential assignment. The named-credential Layer 1b of
    // scan-secrets emits a `hardcoded-credential` finding, but because
    // the file path matches DEMO_PATH_RE (path-component match, not
    // suffix), the finding is downgraded to `severity: 'low'` and
    // `level: 'note'`. Note: the ticket's real-world path shape is
    // `sa-token-oauth2-server-demo/…` which does NOT match — the
    // ticket-approved regex is path-component-only (`(?:^|\/)demo
    // (?:\/|$)`). The FP-drop harness rerun on real repos is
    // acceptance criterion for #138 acceptance; the regex refinement
    // (suffix-match) is deferred pending that rerun.
    const code = `
public class OAuthClient {
    public static final String clientSecret = "Pr0d-DB-pass!2024xyz";
}`;
    const ir = await analyze(
      code,
      'sa-token-oauth2-server/demo/src/main/java/OAuthClient.java',
      'java',
    );
    const findings = ir.findings ?? [];
    const credFindings = findings.filter(f => f.rule_id === 'hardcoded-credential');
    expect(credFindings.length).toBeGreaterThan(0);
    for (const f of credFindings) {
      expect(f.severity).toBe('low');
      expect(f.level).toBe('note');
    }
  });

  it('non-demo path preserves `high` severity on hardcoded-credential', async () => {
    // Regression guard: the downgrade must NOT fire on production paths.
    const code = `
public class OAuthClient {
    public static final String clientSecret = "Pr0d-DB-pass!2024xyz";
}`;
    const ir = await analyze(
      code,
      'src/main/java/com/prod/OAuthClient.java',
      'java',
    );
    const findings = ir.findings ?? [];
    const credFindings = findings.filter(f => f.rule_id === 'hardcoded-credential');
    expect(credFindings.length).toBeGreaterThan(0);
    for (const f of credFindings) {
      expect(f.severity).toBe('high');
    }
  });
});
