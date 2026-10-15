/**
 * Constant-caller gate (cognium-dev#636, C# slice).
 *
 * Per-file analysis seeds every `string` parameter of a method as an
 * `interprocedural_param` source, so a sink that receives the parameter is
 * reported in the callee's file whether or not any caller passes tainted data.
 * The cross-file phase already emits a path for each tainted caller, but the
 * per-file flows are final before it runs. This project-level step runs after
 * it and drops such a flow when every in-project caller is known to pass a
 * constant at that parameter.
 *
 * A flow is dropped only when ALL of these hold; otherwise nothing changes:
 *   1. C# file, flow seeded by `interprocedural_param` on parameter `P` of
 *      method `M`, and no other flow reaches the same sink from a real source.
 *   2. `M` is not virtual / abstract / override / an interface member, and no
 *      project type derives from `M`'s type; the name is not overloaded in its type.
 *   3. Every project call to a method of that name resolves exactly (the same
 *      resolution `CrossFilePass` uses) either to `M` or to some other exact
 *      target; one unresolved, inferred or polymorphic call keeps the flow.
 *   4. At least one call resolves to `M`, and at every such call the argument at
 *      `P`'s position is a plain string literal, or a local declared in the
 *      caller with exactly one assignment, a string literal.
 */

import type { CircleIR, CallInfo, MethodInfo, TypeInfo } from '../types/index.js';
import type { ProjectGraph } from '../graph/project-graph.js';

const STRING_LITERAL = /^@?"(?:[^"\\]|\\.)*"$/;

interface CallSite {
  file: string;
  call: CallInfo;
}

function typeFqn(type: TypeInfo, ir: CircleIR): string {
  const pkg = type.package || ir.meta.package || '';
  return pkg ? `${pkg}.${type.name}` : type.name;
}

function enclosingMethod(ir: CircleIR, line: number): { type: TypeInfo; method: MethodInfo } | undefined {
  let best: { type: TypeInfo; method: MethodInfo } | undefined;
  for (const type of ir.types) {
    for (const method of type.methods) {
      if (line < method.start_line || line > method.end_line) continue;
      if (!best || method.end_line - method.start_line < best.method.end_line - best.method.start_line) {
        best = { type, method };
      }
    }
  }
  return best;
}

/** True when local `name` is declared in the caller's method and assigned exactly once, a string literal. */
function isLiteralLocal(ir: CircleIR, lines: string[], call: CallInfo, name: string): boolean {
  if (!/^[A-Za-z_]\w*$/.test(name)) return false;
  const encl = enclosingMethod(ir, call.location.line);
  if (!encl) return false;
  const { method } = encl;
  if (method.parameters.some(p => p.name === name)) return false;
  const assignOp = new RegExp(`(?<![\\w.])${name}\\s*(?:[-+*/%&|^?]|<<|>>)?=(?!=)`, 'g');
  const literal = '@?"(?:[^"\\\\]|\\\\.)*"';
  const declLiteral = new RegExp(`^\\s*(?:const\\s+)?[\\w<>\\[\\],.?]+\\s+${name}\\s*=\\s*${literal}\\s*;\\s*(?://.*)?$`);
  const plainLiteral = new RegExp(`^\\s*${name}\\s*=\\s*${literal}\\s*;\\s*(?://.*)?$`);
  const bareDecl = new RegExp(`^\\s*(?:const\\s+)?[\\w<>\\[\\],.?]+\\s+${name}\\s*;`);
  const mutate = new RegExp(`\\b(?:out|ref)\\s+${name}\\b|(?:\\+\\+|--)\\s*${name}\\b|\\b${name}\\s*(?:\\+\\+|--)`);
  let assignments = 0;
  let assignLine = -1;
  let assignIsDecl = false;
  let declared = false;
  for (let l = method.start_line; l <= method.end_line; l++) {
    const text = lines[l - 1] ?? '';
    const n = text.match(assignOp)?.length ?? 0;
    assignments += n;
    if (n > 0) {
      assignLine = l;
      assignIsDecl = declLiteral.test(text);
      if (!assignIsDecl && !plainLiteral.test(text)) return false;
    }
    if (bareDecl.test(text)) declared = true;
    if (mutate.test(text)) return false;
  }
  // One assignment, a string literal, before the call; a plain `x = "lit";` needs a local `T x;` declaration.
  return assignments === 1 && assignLine > 0 && assignLine < call.location.line && (assignIsDecl || declared);
}

function isConstantArg(ir: CircleIR, lines: string[], call: CallInfo, position: number): boolean {
  const arg = call.arguments.find(a => a.position === position);
  if (!arg) return false;
  const expr = (arg.expression ?? '').trim();
  if (STRING_LITERAL.test(expr)) return true;
  return !!arg.variable && expr === arg.variable && isLiteralLocal(ir, lines, call, arg.variable);
}

export function applyConstantCallerGate(
  fileAnalyses: ReadonlyArray<{ file: string; analysis: CircleIR }>,
  projectGraph: ProjectGraph,
  sourceLinesByFile: ReadonlyMap<string, string[]>,
): void {
  const candidates = fileAnalyses.filter(fa =>
    fa.analysis.meta.language === 'csharp'
    && (fa.analysis.taint?.flows ?? []).some(f => f.source_type === 'interprocedural_param'));
  if (candidates.length === 0) return;

  const resolver = projectGraph.resolver;
  const csharp = fileAnalyses.filter(fa => fa.analysis.meta.language === 'csharp');
  const callsByName = new Map<string, CallSite[]>();
  const derivedFrom = new Set<string>();
  for (const fa of csharp) {
    for (const call of fa.analysis.calls) {
      const arr = callsByName.get(call.method_name) ?? [];
      arr.push({ file: fa.file, call });
      callsByName.set(call.method_name, arr);
    }
    for (const type of fa.analysis.types) {
      if (type.extends) derivedFrom.add(type.extends.split('.').pop() ?? type.extends);
      for (const i of type.implements) derivedFrom.add(i.split('.').pop() ?? i);
    }
  }

  for (const fa of candidates) {
    const ir = fa.analysis;
    const flows = ir.taint.flows ?? [];
    const kept = flows.filter(flow => {
      if (flow.source_type !== 'interprocedural_param') return true;
      const variable = flow.path[0]?.variable;
      if (!variable) return true;
      if (flows.some(o => o !== flow && o.sink_line === flow.sink_line && o.source_type !== 'interprocedural_param')) return true;

      const src = (ir.taint.sources ?? []).find(s =>
        s.type === 'interprocedural_param' && s.line === flow.source_line && s.variable === variable);
      if (!src?.in_method) return true;
      const encl = enclosingMethod(ir, flow.source_line);
      if (!encl || encl.method.name !== src.in_method) return true;
      const { type, method } = encl;

      if (type.kind !== 'class') return true;
      if (method.modifiers.some(m => m === 'virtual' || m === 'abstract' || m === 'override')) return true;
      if (derivedFrom.has(type.name)) return true;
      if (type.methods.filter(m => m.name === method.name).length !== 1) return true;
      const position = method.parameters.findIndex(p => p.name === variable);
      if (position < 0) return true;

      const fqn = `${typeFqn(type, ir)}.${method.name}`;
      let resolvedToMethod = 0;
      for (const site of callsByName.get(method.name) ?? []) {
        const r = resolver.resolveCall(site.call, site.file);
        if (!r || r.resolution !== 'exact') return true;
        if (r.targetMethod !== fqn) continue;
        const callerIr = fileAnalyses.find(f => f.file === site.file)?.analysis;
        const lines = sourceLinesByFile.get(site.file);
        if (!callerIr || !lines || !isConstantArg(callerIr, lines, site.call, position)) return true;
        resolvedToMethod++;
      }
      return resolvedToMethod === 0;
    });
    if (kept.length !== flows.length) ir.taint.flows = kept;
  }
}
