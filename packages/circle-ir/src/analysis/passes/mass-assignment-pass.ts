/**
 * Pass: mass-assignment (CWE-915, category: security)
 *
 * Pattern pass — flags code paths that splat an HTTP request bag (form /
 * body / query / json) directly into a domain-object constructor or update
 * helper without an allow-list. This complements the taint-based
 * `mass_assignment` SinkType which catches `Object.assign(user, req.body)`
 * via the regular sink matcher; this pass catches the *syntactic spread /
 * kwargs* forms that aren't a discrete call argument.
 *
 * Detection per language:
 *   Python:
 *     - `Model(**request.form)`
 *     - `Model(**request.json)` / `**request.get_json()`
 *     - `Model(**request.args)` / `**request.values`
 *     - `Model.objects.create(**request.X)` (Django ORM)
 *     - `Model.objects.update(**request.X)`
 *   JavaScript / TypeScript:
 *     - `{ ...req.body }`, `{ ...req.query }`, `{ ...req.params }`
 *     - `{ ...request.body }`, `{ ...ctx.request.body }` (Koa)
 *     - `await Model.create({ ...req.body })`
 *     - `await user.update({ ...req.body })`
 *
 * Severity: high (direct privilege escalation vector).
 * Issue: #86, Sprint 6.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

// Python: `**<httpSource>` where httpSource is one of the known
// request bags. We intentionally allow trailing dots / call-syntax
// (`request.get_json()`).
const PY_KWARGS_SPLAT_RE =
  /\*\*\s*(?:request|self\.request|flask\.request|ctx|self)\s*\.\s*(?:form|args|values|json|get_json\s*\(\s*\)|files|data)/;

// JS object-spread of an HTTP source. We match `{...<source>}` where the
// source begins with `req|request|ctx|context` and continues into `body`,
// `query`, `params`, `request.body`, etc.
const JS_OBJECT_SPREAD_RE =
  /\{\s*\.\.\.\s*(?:req|request|ctx|context)(?:\.request)?\s*\.\s*(?:body|query|params|form)\b/;

// Same but as a standalone arg: `Model.create(req.body)` etc. is a real
// sink and already covered by Object.assign-style matchers, so we don't
// duplicate here — only the spread form.

interface PyDetection {
  pattern: string;
  match: string;
}

export interface MassAssignmentResult {
  findings: Array<{
    line: number;
    language: string;
    pattern: string;
    snippet: string;
  }>;
}

export class MassAssignmentPass
  implements AnalysisPass<MassAssignmentResult>
{
  readonly name = 'mass-assignment';
  readonly category = 'security' as const;

  run(ctx: PassContext): MassAssignmentResult {
    const { graph, language } = ctx;
    const file = graph.ir.meta.file;
    const findings: MassAssignmentResult['findings'] = [];
    const code = ctx.code ?? '';
    if (!code) return { findings };

    const lines = code.split('\n');

    if (language === 'python') {
      for (let i = 0; i < lines.length; i++) {
        const text = lines[i] ?? '';
        const m = PY_KWARGS_SPLAT_RE.exec(text);
        if (!m) continue;
        const line = i + 1;
        const det: PyDetection = {
          pattern: '**request.<bag>',
          match: m[0],
        };
        findings.push({
          line,
          language,
          pattern: det.pattern,
          snippet: text.trim().slice(0, 200),
        });
        ctx.addFinding({
          id: `${this.name}-${file}-${line}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-915',
          severity: 'high',
          level: 'error',
          message:
            `HTTP request bag splatted into constructor / ORM helper via ` +
            `\`${det.match}\`. Every form field becomes a settable attribute ` +
            'on the domain object, including ones the endpoint did not ' +
            'intend to expose (e.g. `is_admin`, `role`, `owner_id`).',
          file,
          line,
          fix:
            'Replace the `**` splat with an explicit allow-list: ' +
            "`Model(name=request.form['name'], email=request.form['email'])`. " +
            'For Django, use a `ModelForm` / serializer with `fields = [...]`.',
          evidence: { pattern: det.pattern, match: det.match, language },
        });
      }
      return { findings };
    }

    if (language === 'javascript' || language === 'typescript') {
      for (let i = 0; i < lines.length; i++) {
        const text = lines[i] ?? '';
        const m = JS_OBJECT_SPREAD_RE.exec(text);
        if (!m) continue;
        const line = i + 1;
        findings.push({
          line,
          language,
          pattern: '{...req.<bag>}',
          snippet: text.trim().slice(0, 200),
        });
        ctx.addFinding({
          id: `${this.name}-${file}-${line}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-915',
          severity: 'high',
          level: 'error',
          message:
            `HTTP request bag spread into object literal via \`${m[0]}\`. ` +
            'Every body field becomes a settable property on the resulting ' +
            'object, including ones the endpoint did not intend to expose ' +
            '(e.g. `isAdmin`, `role`, `ownerId`).',
          file,
          line,
          fix:
            'Replace the spread with an explicit pick: ' +
            '`const { name, email } = req.body; const user = { name, email };`. ' +
            'For ORMs, use a DTO / Zod schema with `.pick(...)` or ' +
            'allow-list serializers.',
          evidence: { pattern: '{...req.<bag>}', match: m[0], language },
        });
      }
      return { findings };
    }

    return { findings };
  }
}
