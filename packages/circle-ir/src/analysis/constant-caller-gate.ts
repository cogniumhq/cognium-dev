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
  if (isConstantReturnLocal(ctx, ir, lines, call, position)) return true;
  if (depth >= TRANSITIVE_MAX_DEPTH) return false;

  const arg = call.arguments.find(a => a.position === position);
  if (!arg?.variable || (arg.expression ?? '').trim() !== arg.variable) return false;

  const encl = enclosingMethod(ir, call.location.line);
  if (!encl) return false;
  if (!hasEnumerableCallers(encl.type, encl.method, ctx.derivedFrom, ir.meta.language)) return false;
  const paramIdx = encl.method.parameters.findIndex(p => p.name === arg.variable);
  if (paramIdx < 0) return false;

  const fqn = `${typeFqn(encl.type, ir)}.${encl.method.name}`;
  const relayFile = ctx.fileAnalyses.find(f => f.analysis === ir)?.file;
  const visitKey = `${fqn}:${paramIdx}`;
  if (visiting.has(visitKey)) return false;
  visiting.add(visitKey);

  let resolvedToMethod = 0;
  for (const site of ctx.callsByName.get(encl.method.name) ?? []) {
    if (relayFile !== undefined && site.file !== relayFile && declaresType(ctx.fileAnalyses, site.file, encl.type.name)) continue;
    const r = ctx.resolver.resolveCall(site.call, site.file);
    // Rule 3, as at the sink: one call of this name that does not resolve exactly might be
    // this relay receiving tainted data, so the relay's argument is not known to be constant.
    if (resolvesElsewhere(r, fqn)) continue;
    if (!r || r.resolution !== 'exact') {
      visiting.delete(visitKey);
      return false;
    }
    if (r.targetMethod !== fqn || (relayFile !== undefined && site.file !== relayFile && r.targetFile !== relayFile)) continue;
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
    && (fa.analysis.taint?.flows ?? []).some(f => f.source_type === 'interprocedural_param'
      || (f.source_type === 'plugin_param' && fa.analysis.meta.language === 'java')));
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
    const lines0 = sourceLinesByFile.get(fa.file) ?? [];
    /** Every in-project caller of `method` passes a constant at `position`; false keeps the flow. */
    const callersConstant = (type: TypeInfo, method: MethodInfo, position: number): boolean => {
      const fqn = `${typeFqn(type, ir)}.${method.name}`;
      let resolvedToMethod = 0;
      for (const site of callsByName.get(method.name) ?? []) {
        if (site.file !== fa.file && declaresType(fileAnalyses, site.file, type.name)) continue;
        const r = resolver.resolveCall(site.call, site.file);
        if (resolvesElsewhere(r, fqn)) continue;
        if (!r || r.resolution !== 'exact') return false;
        // Same FQN in another file is another method: nested classes of the
        // same simple name in sibling files share it (every OWASP test has its
        // own inner `Test.doSomething`, cognium-dev#976).
        if (r.targetMethod !== fqn || (site.file !== fa.file && r.targetFile !== fa.file)) continue;
        const callerIr = fileAnalyses.find(f => f.file === site.file)?.analysis;
        const lines = sourceLinesByFile.get(site.file);
        if (!callerIr || !lines || !isConstantArgRecursive(gateCtx, callerIr, lines, site.call, position, 0, new Set())) return false;
        resolvedToMethod++;
      }
      return resolvedToMethod > 0;
    };
    const kept = flows.filter(flow => {
      if (flow.source_type === 'plugin_param' && ir.meta.language === 'java') {
        if (flows.some(o => o !== flow && o.sink_line === flow.sink_line &&
            o.source_type !== 'interprocedural_param' && o.source_type !== 'plugin_param')) return true;
        const encl = enclosingMethod(ir, flow.source_line);
        if (!encl || !hasEnumerableCallers(encl.type, encl.method, derivedFrom, ir.meta.language)) return true;
        const positions = localMapParamPositions(lines0, encl.method, flow.source_line);
        if (!positions) return true;
        return !positions.every(pos => callersConstant(encl.type, encl.method, pos));
      }
      if (flow.source_type !== 'interprocedural_param') return true;
      // The first step names the parameter, or (#976) carries the source's
      // location text `"String param in doSomething"`: take the name from it.
      const raw = flow.path[0]?.variable;
      const variable = raw ? (/^\S+\s+([A-Za-z_]\w*)\s+in\s+\S+$/.exec(raw)?.[1] ?? raw) : raw;
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

      return !callersConstant(type, method, position);
    });
    if (kept.length !== flows.length) ir.taint.flows = kept;
  }
}

/**
 * A dispatch that provably cannot land on `fqn`: a polymorphic resolution
 * (interface call) whose candidate implementations exclude it. OWASP's
 * `thing.doSomething(x)` on `ThingInterface` is not the test's own inner
 * `Test.doSomething`, so it no longer disables the gate for every helper of
 * that name (#976).
 */
function resolvesElsewhere(
  r: { resolution: string; targetMethod: string; candidates?: string[] } | undefined,
  fqn: string,
): boolean {
  if (!r || r.resolution !== 'polymorphic' || r.targetMethod === fqn) return false;
  return Array.isArray(r.candidates) && r.candidates.length > 0 && !r.candidates.includes(fqn);
}

/**
 * The argument is a local whose every assignment in the caller is a string
 * literal or a call that resolves exactly to a project method returning only
 * string literals (OWASP `String param = scr.getTheValue("…")`, whose body is
 * `return "bar";`, cognium-dev#976).
 */
function isConstantReturnLocal(
  ctx: ConstantCallerCtx,
  ir: CircleIR,
  lines: string[],
  call: CallInfo,
  position: number,
): boolean {
  if (ir.meta.language !== 'java') return false;
  const arg = call.arguments.find(a => a.position === position);
  const name = arg?.variable;
  if (!name || (arg.expression ?? '').trim() !== name || !/^[A-Za-z_]\w*$/.test(name)) return false;
  const encl = enclosingMethod(ir, call.location.line);
  if (!encl || encl.method.parameters.some(p => p.name === name)) return false;
  const file = ctx.fileAnalyses.find(f => f.analysis === ir)?.file;
  if (!file) return false;
  const assign = new RegExp(`(?:^|[;{]|\\b(?:if|else)\\b[^;]*?)\\s*(?:[\\w<>\\[\\].]+\\s+)?${name}\\s*=(?!=)\\s*(.+?);`);
  const literal = /^"(?:[^"\\]|\\.)*"$/;
  let viaCall = 0;
  for (let l = encl.method.start_line; l < call.location.line; l++) {
    const text = (lines[l - 1] ?? '').replace(/\/\/.*$/, '');
    if (new RegExp(`(?:\\+\\+|--)\\s*${name}\\b|\\b${name}\\s*(?:\\+\\+|--|[-+*/%&|^]=)`).test(text)) return false;
    const m = assign.exec(text);
    if (!m) continue;
    const rhs = m[1].trim();
    if (literal.test(rhs)) continue;
    const callee = ir.calls.find(c => c.location.line === l && rhs.includes(`${c.method_name}(`));
    if (!callee) return false;
    const r = ctx.resolver.resolveCall(callee, file);
    if (!r || r.resolution !== 'exact' || !methodReturnsOnlyLiterals(ctx, r.targetFile, r.targetMethod)) return false;
    viaCall++;
  }
  return viaCall > 0;
}

function methodReturnsOnlyLiterals(ctx: ConstantCallerCtx, file: string, fqn: string): boolean {
  const ir = ctx.fileAnalyses.find(f => f.file === file)?.analysis;
  const lines = ctx.sourceLinesByFile.get(file);
  if (!ir || !lines) return false;
  const name = fqn.split('.').pop();
  for (const type of ir.types) {
    if (fqn !== `${typeFqn(type, ir)}.${name}`) continue;
    const methods = type.methods.filter(m => m.name === name);
    if (methods.length !== 1) return false; // overloaded: which one is unknown
    const m = methods[0];
    let returns = 0;
    for (let l = m.start_line; l <= m.end_line; l++) {
      const text = (lines[l - 1] ?? '').replace(/\/\/.*$/, '');
      if (!/\breturn\b/.test(text)) continue;
      for (const m of text.matchAll(/\breturn\b([^;]*);?/g)) {
        if (!/^\s*"(?:[^"\\]|\\.)*"\s*$/.test(m[1])) return false;
        returns++;
      }
    }
    return returns > 0;
  }
  return false;
}

/**
 * Does `file` declare its own type named `name`? Its unqualified uses of that
 * name are its own type (Java shadowing), whatever the shared FQN says.
 */
function declaresType(
  fileAnalyses: ReadonlyArray<{ file: string; analysis: CircleIR }>,
  file: string,
  name: string,
): boolean {
  const ir = fileAnalyses.find(f => f.file === file)?.analysis;
  return !!ir && ir.meta.language === 'java' && ir.types.some(t => t.name === name);
}

/**
 * A `plugin_param` read `x = (T) m.get("k")` from a map `m` the method builds
 * itself (`m = new …Map…()`, never reassigned or passed out), whose every
 * `m.put(_, v)` value is a string literal or one of the method's parameters:
 * the positions of those parameters (an empty list when only literals go in).
 * Anything else answers null and the flow is kept (#976, OWASP map helpers fed
 * by `scr.getTheValue`).
 */
function localMapParamPositions(lines: string[], method: MethodInfo, sourceLine: number): number[] | null {
  const read = /([A-Za-z_]\w*)\s*\.\s*get\s*\(/.exec(lines[sourceLine - 1] ?? '');
  if (!read) return null;
  const map = read[1];
  const body: string[] = [];
  for (let l = method.start_line; l <= method.end_line; l++) body.push((lines[l - 1] ?? '').replace(/\/\/.*$/, ''));
  const text = body.join('\n');
  const created = new RegExp(`\\b${map}\\s*=\\s*new\\s+[\\w.]*Map\\b`).test(text);
  const assigned = text.match(new RegExp(`(?<![\\w.])${map}\\s*=(?!=)`, 'g'))?.length ?? 0;
  if (!created || assigned !== 1) return null;
  // Passed to a call or returned: its contents are no longer the method's own.
  if (new RegExp(`[(,]\\s*${map}\\s*[,)]|\\breturn\\s+${map}\\b`).test(text)) return null;
  const params = method.parameters.map(p => p.name);
  const positions = new Set<number>();
  let puts = 0;
  for (const m of text.matchAll(new RegExp(`\\b${map}\\s*\\.\\s*(put|putAll|putIfAbsent|compute\\w*|merge|replace\\w*)\\s*\\(([^;]*)\\)\\s*;`, 'g'))) {
    if (m[1] !== 'put') return null;
    const comma = m[2].indexOf(',');
    if (comma < 0) return null;
    const value = m[2].slice(comma + 1).trim();
    puts++;
    if (/^"(?:[^"\\]|\\.)*"$/.test(value)) continue;
    const idx = params.indexOf(value);
    if (idx < 0) return null;
    positions.add(idx);
  }
  return puts > 0 ? [...positions] : null;
}
