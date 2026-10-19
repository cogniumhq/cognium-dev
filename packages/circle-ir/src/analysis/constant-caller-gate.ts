/**
 * Constant-caller gate (cognium-dev#636 C#, cognium-dev#614 Java slice).
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
 *   1. C# or Java file, flow seeded by `interprocedural_param` on parameter `P` of
 *      method `M`, and no other flow reaches the same sink from a real source.
 *   2. `M` is not virtual / abstract / override / an interface member, and no
 *      project type derives from `M`'s type; the name is not overloaded in its type.
 *   3. Every project call to a method of that name resolves exactly (the same
 *      resolution `CrossFilePass` uses) either to `M` or to some other exact
 *      target; one unresolved, inferred or polymorphic call keeps the flow.
 *   4. At least one call resolves to `M`, and at every such call the argument at
 *      `P`'s position is a plain string literal, a literal local (`#636`), a
 *      local array whose element writes are all literals (`#638` step 1), or a
 *      parameter of the caller when every in-project caller of that method passes
 *      a constant at that parameter (transitive, depth ≤ 4, cycle-safe). Each relay
 *      method on the way must itself meet rules 2 and 3, so a relay that is
 *      virtual, overloaded or reached by a call that does not resolve exactly
 *      keeps the flow.
 */

import type { CircleIR, CallInfo, MethodInfo, TypeInfo } from '../types/index.js';
import type { ProjectGraph } from '../graph/project-graph.js';

const STRING_LITERAL = /^@?"(?:[^"\\]|\\.)*"$/;

const GATE_LANGUAGES = new Set(['csharp', 'java']);

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
  const lang = ir.meta.language;
  const typeDecl = lang === 'java'
    ? `(?:final\\s+)?[\\w<>\\[\\],.?]+`
    : `(?:const\\s+)?[\\w<>\\[\\],.?]+`;
  const declLiteral = new RegExp(`^\\s*${typeDecl}\\s+${name}\\s*=\\s*${literal}\\s*;\\s*(?://.*)?$`);
  const plainLiteral = new RegExp(`^\\s*${name}\\s*=\\s*${literal}\\s*;\\s*(?://.*)?$`);
  const bareDecl = new RegExp(`^\\s*${typeDecl}\\s+${name}\\s*;`);
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

const LITERAL_IN_BRACES = /^@?"(?:[^"\\]|\\.)*"(?:\s*,\s*@?"(?:[^"\\]|\\.)*")*\s*$/;

/** True when local array `name` is declared in the caller and only ever holds string literals (cognium-dev#638 step 1). */
export function isLiteralArrayLocal(ir: CircleIR, lines: string[], call: CallInfo, name: string): boolean {
  if (!/^[A-Za-z_]\w*$/.test(name)) return false;
  const encl = enclosingMethod(ir, call.location.line);
  if (!encl) return false;
  const { method } = encl;
  if (method.parameters.some(p => p.name === name)) return false;

  const declNew = new RegExp(
    `^\\s*(?:var\\s+)?[\\w<>\\[\\],\\s]*\\b${name}\\s*=\\s*new\\s+[\\w<>\\[\\],\\s]+\\[\\s*\\d+\\s*\\]\\s*;\\s*(?://.*)?$`,
  );
  const declInit = new RegExp(
    `^\\s*(?:var\\s+)?[\\w<>\\[\\],\\s]*\\b${name}\\s*=\\s*(?:new\\s+[\\w<>\\[\\],\\s]+\\[\\s*\\]\\s*)?\\{([^}]*)\\}\\s*;\\s*(?://.*)?$`,
  );
  const plainReassign = new RegExp(`^\\s*${name}\\s*(?![\\[])(?:[-+*/%&|^?]|<<|>>)?=(?!=)`);
  const elementWrite = new RegExp(`^\\s*${name}\\s*\\[[^\\]]+\\]\\s*=\\s*(.+?)\\s*;\\s*(?://.*)?$`);
  const alias = new RegExp(`^\\s*\\w+\\s*=\\s*${name}\\s*;`);
  const mutate = new RegExp(`\\b(?:out|ref)\\s+${name}\\b|(?:\\+\\+|--)\\s*${name}\\b|\\b${name}\\s*(?:\\+\\+|--)`);
  const copyStyle = new RegExp(`\\b(?:Array\\.Copy|CopyTo|\\.Add)\\s*\\([^)]*\\b${name}\\b`);

  let declared = false;
  let declLine = -1;

  for (let l = method.start_line; l <= method.end_line; l++) {
    const text = lines[l - 1] ?? '';
    if (mutate.test(text) || alias.test(text) || copyStyle.test(text)) return false;

    const initMatch = declInit.exec(text);
    if (initMatch) {
      declared = true;
      declLine = l;
      const inner = (initMatch[1] ?? '').trim();
      if (inner.length > 0 && !LITERAL_IN_BRACES.test(inner)) return false;
      continue;
    }
    if (declNew.test(text)) {
      declared = true;
      declLine = l;
      continue;
    }

    const ew = elementWrite.exec(text);
    if (ew) {
      const rhs = ew[1].trim();
      if (STRING_LITERAL.test(rhs)) continue;
      if (/^[A-Za-z_]\w*$/.test(rhs) && isLiteralLocal(ir, lines, call, rhs)) continue;
      return false;
    }

    if (l !== declLine && plainReassign.test(text)) return false;
  }

  if (!declared) return false;

  for (const c of ir.calls) {
    if (c.location.line < method.start_line || c.location.line > method.end_line) continue;
    if (c.location.line >= call.location.line) continue;
    if (c === call) continue;
    if (c.arguments.some(a => (a.variable ?? a.expression?.trim()) === name)) return false;
  }

  return true;
}

function isDirectConstantArg(ir: CircleIR, lines: string[], call: CallInfo, position: number): boolean {
  const arg = call.arguments.find(a => a.position === position);
  if (!arg) return false;
  const expr = (arg.expression ?? '').trim();
  if (STRING_LITERAL.test(expr)) return true;
  if (arg.variable && expr === arg.variable && isLiteralLocal(ir, lines, call, arg.variable)) return true;
  return !!arg.variable && expr === arg.variable && isLiteralArrayLocal(ir, lines, call, arg.variable);
}

/** Direct constant at a call argument (exported for #638 unit tests). */
export function isConstantArg(ir: CircleIR, lines: string[], call: CallInfo, position: number): boolean {
  return isDirectConstantArg(ir, lines, call, position);
}

interface ConstantCallerCtx {
  fileAnalyses: ReadonlyArray<{ file: string; analysis: CircleIR }>;
  callsByName: Map<string, CallSite[]>;
  resolver: ProjectGraph['resolver'];
  sourceLinesByFile: ReadonlyMap<string, string[]>;
  derivedFrom: ReadonlySet<string>;
}

/**
 * Rule 2 of the header: a method whose callers can be enumerated exactly. Applied to the
 * sink's method and to every relay method the transitive step walks through, so a virtual,
 * overridden, interface or overloaded relay keeps the flow.
 */
function hasEnumerableCallers(
  type: TypeInfo,
  method: MethodInfo,
  derivedFrom: ReadonlySet<string>,
  language: string,
): boolean {
  if (type.kind !== 'class') return false;
  if (method.modifiers.some(m => m === 'abstract')) return false;
  if (language === 'csharp' && method.modifiers.some(m => m === 'virtual' || m === 'override')) return false;
  if (derivedFrom.has(type.name)) return false;
  return type.methods.filter(m => m.name === method.name).length === 1;
}

const TRANSITIVE_MAX_DEPTH = 4;

function isConstantArgRecursive(
  ctx: ConstantCallerCtx,
  ir: CircleIR,
  lines: string[],
  call: CallInfo,
  position: number,
  depth: number,
  visiting: Set<string>,
): boolean {
  if (isDirectConstantArg(ir, lines, call, position)) return true;
  if (depth >= TRANSITIVE_MAX_DEPTH) return false;

  const arg = call.arguments.find(a => a.position === position);
  if (!arg?.variable || (arg.expression ?? '').trim() !== arg.variable) return false;

  const encl = enclosingMethod(ir, call.location.line);
  if (!encl) return false;
  if (!hasEnumerableCallers(encl.type, encl.method, ctx.derivedFrom, ir.meta.language)) return false;
  const paramIdx = encl.method.parameters.findIndex(p => p.name === arg.variable);
  if (paramIdx < 0) return false;

  const fqn = `${typeFqn(encl.type, ir)}.${encl.method.name}`;
  const visitKey = `${fqn}:${paramIdx}`;
  if (visiting.has(visitKey)) return false;
  visiting.add(visitKey);

  let resolvedToMethod = 0;
  for (const site of ctx.callsByName.get(encl.method.name) ?? []) {
    const r = ctx.resolver.resolveCall(site.call, site.file);
    // Rule 3, as at the sink: one call of this name that does not resolve exactly might be
    // this relay receiving tainted data, so the relay's argument is not known to be constant.
    if (!r || r.resolution !== 'exact') {
      visiting.delete(visitKey);
      return false;
    }
    if (r.targetMethod !== fqn) continue;
    const callerIr = ctx.fileAnalyses.find(f => f.file === site.file)?.analysis;
    const callerLines = ctx.sourceLinesByFile.get(site.file);
    if (!callerIr || !callerLines) {
      visiting.delete(visitKey);
      return false;
    }
    if (!isConstantArgRecursive(ctx, callerIr, callerLines, site.call, paramIdx, depth + 1, visiting)) {
      visiting.delete(visitKey);
      return false;
    }
    resolvedToMethod++;
  }
  visiting.delete(visitKey);
  return resolvedToMethod > 0;
}

export function applyConstantCallerGate(
  fileAnalyses: ReadonlyArray<{ file: string; analysis: CircleIR }>,
  projectGraph: ProjectGraph,
  sourceLinesByFile: ReadonlyMap<string, string[]>,
): void {
  const candidates = fileAnalyses.filter(fa =>
    GATE_LANGUAGES.has(fa.analysis.meta.language)
    && (fa.analysis.taint?.flows ?? []).some(f => f.source_type === 'interprocedural_param'));
  if (candidates.length === 0) return;

  const resolver = projectGraph.resolver;
  const gated = fileAnalyses.filter(fa => GATE_LANGUAGES.has(fa.analysis.meta.language));
  const callsByName = new Map<string, CallSite[]>();
  const derivedFrom = new Set<string>();
  for (const fa of gated) {
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

  const gateCtx: ConstantCallerCtx = {
    fileAnalyses,
    callsByName,
    resolver,
    sourceLinesByFile,
    derivedFrom,
  };

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

      if (!hasEnumerableCallers(type, method, derivedFrom, ir.meta.language)) return true;
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
        if (!callerIr || !lines || !isConstantArgRecursive(gateCtx, callerIr, lines, site.call, position, 0, new Set())) return true;
        resolvedToMethod++;
      }
      return resolvedToMethod === 0;
    });
    if (kept.length !== flows.length) ir.taint.flows = kept;
  }
}
