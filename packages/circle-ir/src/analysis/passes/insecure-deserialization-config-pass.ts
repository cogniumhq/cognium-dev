/**
 * Pass: insecure-deserialization-config (CWE-502, category: security)
 *
 * Pattern pass — flags a security *configuration* that renders a deserializer
 * exploitable, independent of data flow. The vulnerability is the constant
 * argument, not a source→sink taint path, so (like `weak-crypto`) this is a
 * call-shape match rather than a taint sink.
 *
 * Java — XStream permissive type permission (cognium-dev#225):
 *   `xstream.addPermission(AnyTypePermission.ANY)`      // grant-all, insecure
 *   `xstream.addPermission(new AnyTypePermission())`    // same, constructed
 *
 * `AnyTypePermission` re-enables XStream's pre-1.4.10 grant-everything default,
 * so a later `fromXML(untrusted)` can instantiate arbitrary gadget types
 * (CVE-2013-7285, CVE-2020-26217, CVE-2021-21345, …). XStream's own docs call
 * this out: production code with untrusted input must allow-list types, never
 * `AnyTypePermission`. The argument is unambiguously XStream's security class,
 * so the FP surface is near-zero — the *secure* shapes (`NoTypePermission.NONE`,
 * `WildcardTypePermission(...)`, explicit `allowTypes(...)`) do not match.
 *
 * This is deterministic and complements the existing `fromXML` CWE-502 taint
 * sink: the sink fires at the deserialization call site (only with a reachable
 * source), while this fires at the misconfiguration site regardless of flow.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

export interface InsecureDeserializationConfigResult {
  findings: Array<{ line: number; api: string }>;
}

// XStream's grant-all permission. Matches `AnyTypePermission.ANY` and
// `new AnyTypePermission()`, incl. fully-qualified
// `com.thoughtworks.xstream.security.AnyTypePermission`.
const ANY_TYPE_PERMISSION_RE = /\bAnyTypePermission\b/;

export class InsecureDeserializationConfigPass
  implements AnalysisPass<InsecureDeserializationConfigResult>
{
  readonly name = 'insecure-deserialization-config';
  readonly category = 'security' as const;

  run(ctx: PassContext): InsecureDeserializationConfigResult {
    if (ctx.language === 'java') return this.runJava(ctx);
    if (ctx.language === 'csharp') return this.runCSharp(ctx);
    return { findings: [] };
  }

  private runJava(ctx: PassContext): InsecureDeserializationConfigResult {
    const { graph, language } = ctx;
    const file = graph.ir.meta.file;
    const findings: InsecureDeserializationConfigResult['findings'] = [];

    for (const call of graph.ir.calls) {
      if (!this.isPermissiveXStreamConfig(call)) continue;
      const line = call.location.line;
      const api = `addPermission(${call.arguments[0]?.expression ?? 'AnyTypePermission'})`;
      findings.push({ line, api });
      ctx.addFinding({
        id: `${this.name}-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-502',
        severity: 'high',
        level: 'error',
        message:
          'XStream configured with AnyTypePermission (grant-all): untrusted XML ' +
          'passed to fromXML/unmarshal can instantiate arbitrary types (deserialization RCE)',
        file,
        line,
        fix: 'Replace AnyTypePermission with an explicit type allow-list: xstream.addPermission(NoTypePermission.NONE) then allowTypes/allowTypesByWildcard for the classes you deserialize.',
        evidence: { api, language },
      });
    }

    return { findings };
  }

  // C# — Json.NET `TypeNameHandling` set to a value other than `None` (ca#318).
  // `TypeNameHandling.All/Auto/Objects/Arrays` makes Json.NET honour a `$type`
  // field in the payload and instantiate the named .NET type, so
  // `JsonConvert.DeserializeObject(untrusted, settings)` becomes a gadget-chain
  // RCE (the .NET analogue of XStream's grant-all). The vulnerability is the
  // constant setting, independent of flow — the secure value `None` never matches.
  private runCSharp(ctx: PassContext): InsecureDeserializationConfigResult {
    const file = ctx.graph.ir.meta.file;
    const findings: InsecureDeserializationConfigResult['findings'] = [];
    const lines = ctx.code.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const m = INSECURE_TYPE_NAME_HANDLING_RE.exec(lines[i]);
      if (!m) continue;
      const line = i + 1;
      const api = `TypeNameHandling = TypeNameHandling.${m[1]}`;
      findings.push({ line, api });
      ctx.addFinding({
        id: `${this.name}-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-502',
        severity: 'high',
        level: 'error',
        message:
          `Json.NET configured with TypeNameHandling.${m[1]}: a $type field in ` +
          'untrusted JSON can instantiate arbitrary .NET types (deserialization RCE)',
        file,
        line,
        fix: 'Use TypeNameHandling.None (the default), or bind a SerializationBinder that allow-lists the exact types you deserialize.',
        evidence: { api, language: 'csharp' },
      });
    }

    return { findings };
  }

  private isPermissiveXStreamConfig(call: CallInfo): boolean {
    if (call.method_name !== 'addPermission') return false;
    const arg0 = call.arguments[0]?.expression;
    return typeof arg0 === 'string' && ANY_TYPE_PERMISSION_RE.test(arg0);
  }
}

// Json.NET's unsafe polymorphic-type settings. `None` (safe/default) is absent
// by construction, so it never matches.
const INSECURE_TYPE_NAME_HANDLING_RE =
  /\bTypeNameHandling\s*=\s*(?:Newtonsoft\.Json\.)?TypeNameHandling\.(All|Auto|Objects|Arrays)\b/;
