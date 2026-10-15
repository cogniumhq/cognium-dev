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
 * sink and does not forward any of its parameters (directly, through a local
 * alias, a field/property store, a return, or an interpolated-string hole):
 * the cross-file phase and its callee-reach check then decide what is reported.
 * A callee with no registered sink is a shape the registry does not know (for
 * example a header or cookie write), and one that forwards the parameter
 * elsewhere leaks it there; in both the escape is the only signal. An
 * unresolved, inferred or polymorphic call also keeps it. When the call's
 * receiver is a type-like name it must match the resolved class, so a second
 * same-line call such as `Unknown.Run(data)` cannot inherit another call's
 * cached resolution.
 */

import type { CircleIR, CallInfo, DFGDef } from '../types/index.js';
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

/** Locals (and further aliases) that DFG-chain from the method's parameters. */
function aliasesOfParams(ir: CircleIR, methodStart: number, methodEnd: number, params: string[]): Set<string> {
  const names = new Set(params);
  const defs = ir.dfg?.defs ?? [];
  const chains = ir.dfg?.chains ?? [];
  const inMethod = (d: DFGDef): boolean => d.line >= methodStart && d.line <= methodEnd;
  const aliasDefIds = new Set(
    defs.filter(d => inMethod(d) && d.kind === 'param' && params.includes(d.variable)).map(d => d.id),
  );
  let grew = true;
  while (grew) {
    grew = false;
    for (const ch of chains) {
      if (!aliasDefIds.has(ch.from_def) || aliasDefIds.has(ch.to_def)) continue;
      const to = defs.find(d => d.id === ch.to_def);
      if (!to || !inMethod(to)) continue;
      aliasDefIds.add(ch.to_def);
      names.add(to.variable);
      grew = true;
    }
  }
  return names;
}

function isParametersBindingLine(ir: CircleIR, line: number, methodStart: number, methodEnd: number): boolean {
  return ir.calls.some(c =>
    c.location.line === line
    && c.location.line >= methodStart && c.location.line <= methodEnd
    && /(?:^|\.)Parameters$/.test(c.receiver ?? ''));
}

/**
 * True when every method named like `targetFqn` in `ir` contains a registered
 * sink and does not forward a parameter elsewhere. Allowed mentions of a
 * parameter (or a local alias of one) are only: a registered-sink line, or a
 * `x.Parameters.Add*(...)` binding. Any other use — a call argument (including
 * interpolated holes), a local alias assignment, a field/property store, or a
 * return — is forwarding, which the escape reports.
 */
function calleeDecidedBySinks(ir: CircleIR | undefined, targetFqn: string): boolean {
  if (!ir) return false;
  const name = targetFqn.split('.').pop();
  const methods = ir.types.flatMap(t => t.methods).filter(m => m.name === name);
  if (methods.length === 0) return false;
  const sinks = ir.taint?.sinks ?? [];
  const sinkLines = new Set(sinks.filter(k => k.type !== ESCAPE).map(k => k.line));
  return methods.every(m => {
    if (!sinks.some(k => k.type !== ESCAPE && k.line >= m.start_line && k.line <= m.end_line)) return false;
    const params = m.parameters.map(p => p.name).filter(Boolean);
    if (params.length === 0) return true;
    const aliases = aliasesOfParams(ir, m.start_line, m.end_line, params);

    // Call-argument forwarding (direct or via alias / interpolated hole).
    const callForward = ir.calls.some(c =>
      c.location.line >= m.start_line && c.location.line <= m.end_line
      && !sinkLines.has(c.location.line)
      && !/(?:^|\.)Parameters$/.test(c.receiver ?? '')
      && c.arguments.some(a => {
        const e = a.expression ?? '';
        return [...aliases].some(p => mentionsName(e, p));
      }));
    if (callForward) return false;

    // Any other use of a parameter/alias outside sink / Parameters lines
    // (local alias assignment, field/property store, return, object initializer).
    const uses = ir.dfg?.uses ?? [];
    const otherUse = uses.some(u =>
      u.line >= m.start_line && u.line <= m.end_line
      && aliases.has(u.variable)
      && !sinkLines.has(u.line)
      && !isParametersBindingLine(ir, u.line, m.start_line, m.end_line));
    if (otherUse) return false;

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
          && calleeDecidedBySinks(projectGraph.getIR(r.targetFile), r.targetMethod);
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
