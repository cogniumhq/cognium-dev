/**
 * Project-callee escape gate (cognium-dev#637, C#).
 *
 * A file analysed on its own cannot see a method defined in another file, so
 * a tainted argument passed to it is reported as an `external_taint_escape`
 * (data handed to an unknown method). Inside `analyzeProject` the callee is
 * known: the call is project code, not data leaving the program, and whether
 * the value reaches a sink is decided by the cross-file phase and its callee
 * reach check. With both classes in one file the same call reports nothing,
 * so this step makes the project result agree with it.
 *
 * Runs after the per-file analyses and before the cross-file phase, so no
 * cross-file path is built from the dropped sink. A sink is dropped only when
 * every call at its line to that method name resolves exactly to a method
 * declared in a different project file AND that method contains a registered
 * sink and does not forward any of its parameters (directly, through an
 * identity local alias, a field/property store, a return of a non-void method,
 * or an interpolated-string hole): the cross-file phase and its callee-reach
 * check then decide what is reported. A callee with no registered sink is a
 * shape the registry does not know (for example a header or cookie write), and
 * one that forwards the parameter elsewhere leaks it there; in both the escape
 * is the only signal. An unresolved, inferred or polymorphic call also keeps
 * it. When the call's receiver is a type-like name it must match the resolved
 * class, so a second same-line call such as `Unknown.Run(data)` cannot inherit
 * another call's cached resolution.
 *
 * The decision is transitive for a pure forwarder: a callee with no sink of its
 * own whose only use of the parameter is to pass it to calls that each resolve
 * exactly to a method in another project file is decided by those methods, to a
 * depth of four hops with a visited set (so a loop stops). Any hop that does not
 * resolve, ends without a sink, forwards elsewhere as well, stores or returns the
 * value, or lies beyond the depth keeps the escape.
 */

import type { CircleIR, CallInfo, DFGDef, MethodInfo } from '../types/index.js';
import type { ProjectGraph } from '../graph/project-graph.js';

const ESCAPE = 'external_taint_escape';

/**
 * Blank string literals but keep the contents of `{...}` holes in interpolated
 * strings (`$"…"`, `$@"…"`), so `Sender.Post($"hello {data}")` still sees `data`.
 */
function textOf(expr: string): string {
  return expr.replace(
    /\$@?"(?:[^"\\]|\\.|\{[^}]*\})*"|\$?"(?:[^"\\]|\\.|\{[^}]*\})*"|@?"(?:[^"\\]|\\.)*"/g,
    (lit) => {
      if (lit.startsWith('$')) {
        const holes = [...lit.matchAll(/\{([^}]*)\}/g)].map(m => m[1]).join(' ');
        return ` ${holes} `;
      }
      return ' ';
    },
  );
}

function mentionsName(expr: string, name: string): boolean {
  return new RegExp(`(?<![\\w.])${name}(?!\\w)`).test(textOf(expr));
}

/**
 * Identity aliases of parameters (`string x = data`), not transforms
 * (`data.Split(...)`). A local chained from a known name counts only when its
 * def line has a use of that name and no call with that name as receiver.
 */
function identityAliases(ir: CircleIR, methodStart: number, methodEnd: number, params: string[]): Set<string> {
  const names = new Set(params);
  const defs = ir.dfg?.defs ?? [];
  const uses = ir.dfg?.uses ?? [];
  const chains = ir.dfg?.chains ?? [];
  const inMethod = (d: DFGDef): boolean => d.line >= methodStart && d.line <= methodEnd;

  let grew = true;
  while (grew) {
    grew = false;
    const nameDefIds = new Set(
      defs.filter(d => inMethod(d) && names.has(d.variable)).map(d => d.id),
    );
    for (const ch of chains) {
      if (!nameDefIds.has(ch.from_def)) continue;
      const from = defs.find(d => d.id === ch.from_def);
      const to = defs.find(d => d.id === ch.to_def);
      if (!from || !to || !inMethod(to) || to.kind !== 'local') continue;
      if (names.has(to.variable)) continue;
      if (!uses.some(u => u.line === to.line && u.variable === from.variable)) continue;
      const transform = ir.calls.some(c =>
        c.location.line === to.line && c.receiver === from.variable);
      if (transform) continue;
      names.add(to.variable);
      grew = true;
    }
  }
  return names;
}

function fieldNamesOf(ir: CircleIR): Set<string> {
  return new Set(ir.types.flatMap(t => (t.fields ?? []).map(f => f.name)));
}

function isVoidReturn(m: MethodInfo): boolean {
  const t = (m.return_type ?? 'void').trim().toLowerCase();
  return t === '' || t === 'void';
}

/**
 * True when every method named like `targetFqn` in `ir` contains a registered
 * sink and does not forward a parameter elsewhere. A parameter bound with
 * `x.Parameters.Add*(...)` is a binding, and a call on a registered sink line
 * is covered by the reach check. Forwarding includes: a call argument that
 * mentions the parameter or an identity local alias of it (including `{data}`
 * holes in interpolated strings), a store into a field/property, and a return
 * of the parameter from a non-void method. Null-checks and transforms like
 * `data.Split(...)` are not forwarding.
 */
const MAX_FORWARD_DEPTH = 4;

function calleeDecidedBySinks(
  projectGraph: ProjectGraph,
  file: string,
  targetFqn: string,
  depth = 0,
  visited: Set<string> = new Set(),
): boolean {
  const ir = projectGraph.getIR(file);
  if (!ir) return false;
  const visitKey = `${file}#${targetFqn}`;
  if (visited.has(visitKey)) return false;
  visited.add(visitKey);
  const name = targetFqn.split('.').pop();
  const methods = ir.types.flatMap(t => t.methods).filter(m => m.name === name);
  if (methods.length === 0) return false;
  const sinks = ir.taint?.sinks ?? [];
  const sinkLines = new Set(sinks.filter(k => k.type !== ESCAPE).map(k => k.line));
  const fields = fieldNamesOf(ir);
  const defs = ir.dfg?.defs ?? [];
  const uses = ir.dfg?.uses ?? [];

  return methods.every(m => {
    const hasSink = sinks.some(k => k.type !== ESCAPE && k.line >= m.start_line && k.line <= m.end_line);
    const params = m.parameters.map(p => p.name).filter(Boolean);
    if (params.length === 0) return hasSink;
    const aliases = identityAliases(ir, m.start_line, m.end_line, params);

    // Call-argument forwarding (direct, identity alias, or interpolated hole).
    const forwards = ir.calls.filter(c =>
      c.location.line >= m.start_line && c.location.line <= m.end_line
      && !sinkLines.has(c.location.line)
      && !/(?:^|\.)Parameters$/.test(c.receiver ?? '')
      && c.arguments.some(a => [...aliases].some(p => mentionsName(a.expression ?? '', p))));
    if (forwards.length > 0) {
      // A callee with its own sink that forwards elsewhere leaks there. One without
      // a sink is decided by the methods it forwards to, when every forward resolves
      // exactly to a method in another project file and that method is decided.
      if (hasSink || depth >= MAX_FORWARD_DEPTH) return false;
      // Only a bare parameter handed on as an argument counts: a transform, alias or
      // interpolation of it is not followed (the cross-file phase does not either).
      const bare = forwards.every(c => c.arguments.every(a => {
        const e = (a.expression ?? '').trim();
        return params.includes(e) || ![...aliases].some(p => mentionsName(e, p));
      }));
      if (!bare) return false;
      const resolver = projectGraph.resolver;
      const chained = forwards.every(call => {
        const r = resolver.resolveCall(call, file);
        return !!r && r.resolution === 'exact' && r.targetFile !== file
          && receiverMatchesTarget(call, r.targetClass)
          && calleeDecidedBySinks(projectGraph, r.targetFile, r.targetMethod, depth + 1, new Set(visited));
      });
      if (!chained) return false;
    } else if (!hasSink) {
      return false;
    }

    // Field/property store: `saved = data` / `this.saved = data` / `Prop = data`.
    for (const u of uses) {
      if (u.line < m.start_line || u.line > m.end_line) continue;
      if (!aliases.has(u.variable)) continue;
      if (sinkLines.has(u.line)) continue;
      const lineDefs = defs.filter(d => d.line === u.line);
      if (lineDefs.some(d => d.kind === 'field' || fields.has(d.variable))) return false;
      if (uses.some(o => o.line === u.line && o.variable !== u.variable && fields.has(o.variable))) return false;
    }

    // Return of a parameter/alias from a non-void method: use on a line with
    // no calls and no new local def (null-checks in void methods stay silent).
    if (!isVoidReturn(m)) {
      for (const u of uses) {
        if (u.line < m.start_line || u.line > m.end_line) continue;
        if (!aliases.has(u.variable)) continue;
        if (sinkLines.has(u.line)) continue;
        if (ir.calls.some(c => c.location.line === u.line)) continue;
        if (defs.some(d => d.line === u.line && d.kind === 'local')) continue;
        return false;
      }
    }

    return true;
  });
}

/** Receiver looks like a type name and must match the resolved target class. */
function receiverMatchesTarget(call: CallInfo, targetClass: string): boolean {
  const recv = call.receiver;
  if (!recv || !/^[A-Z]/.test(recv)) return true;
  if (recv.includes('.')) return true; // namespace-qualified / member chain: leave to resolver
  const simple = targetClass.split('.').pop() ?? targetClass;
  return recv === simple || recv === targetClass;
}

export function dropEscapesToProjectCallees(
  fileAnalyses: ReadonlyArray<{ file: string; analysis: CircleIR }>,
  projectGraph: ProjectGraph,
): void {
  const resolver = projectGraph.resolver;
  for (const fa of fileAnalyses) {
    const ir = fa.analysis;
    if (ir.meta.language !== 'csharp') continue;
    const sinks = ir.taint?.sinks ?? [];
    if (!sinks.some(s => s.type === ESCAPE)) continue;

    const dropped = new Set<number>();
    for (const sink of sinks) {
      if (sink.type !== ESCAPE || !sink.method) continue;
      const calls = ir.calls.filter(c => c.location.line === sink.line && c.method_name === sink.method);
      if (calls.length === 0) continue;
      const projectCall = calls.every(call => {
        const r = resolver.resolveCall(call, fa.file);
        return !!r && r.resolution === 'exact' && r.targetFile !== fa.file
          && receiverMatchesTarget(call, r.targetClass)
          && calleeDecidedBySinks(projectGraph, r.targetFile, r.targetMethod);
      });
      if (projectCall) dropped.add(sink.line);
    }
    if (dropped.size === 0) continue;

    const isDropped = (type: string, line: number): boolean => type === ESCAPE && dropped.has(line);
    // In place: the project graph holds the same arrays.
    for (let i = sinks.length - 1; i >= 0; i--) {
      if (isDropped(sinks[i].type, sinks[i].line)) sinks.splice(i, 1);
    }
    const flows = ir.taint.flows ?? [];
    for (let i = flows.length - 1; i >= 0; i--) {
      if (isDropped(flows[i].sink_type, flows[i].sink_line)) flows.splice(i, 1);
    }
  }
}
