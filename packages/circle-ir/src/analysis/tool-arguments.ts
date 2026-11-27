/**
 * A path-traversal flow whose source is the tool's own arguments.
 *
 * A command-line tool or a Maven plugin opens the files its own user names:
 * the `String[]` of `main`, an option read from a commons-cli `CommandLine`,
 * a Mojo `@Parameter`. Whoever passes that path already runs the tool with
 * their own rights, so for a local tool the flow is lower risk. It is still
 * reported (the same code can end up behind a server): the flow is tagged
 * `tool-arguments:local-input` and its confidence is halved. Severity is
 * unchanged. Java only.
 */
import type { CircleIR, MethodInfo, TaintFlowInfo, TaintPath, TypeInfo } from '../types/index.js';

export const TOOL_ARGUMENTS_TAG = 'tool-arguments:local-input';

/** The words a reader sees next to a tagged finding. */
export const TOOL_ARGUMENTS_NOTE = "input from the tool's own arguments (lower risk for a local tool)";

const CONFIDENCE_FACTOR = 0.5;

/** `CommandLine` reads that return what the user typed. */
const COMMONS_CLI_READS: ReadonlySet<string> = new Set([
  'getOptionValue', 'getOptionValues', 'getOptionProperties', 'getParsedOptionValue', 'getArgs', 'getArgList',
]);
const COMMONS_CLI_PARSERS: ReadonlySet<string> = new Set([
  'CommandLineParser', 'DefaultParser', 'BasicParser', 'GnuParser', 'PosixParser',
]);

type ToolArgumentsIR = Pick<CircleIR, 'meta' | 'types' | 'calls' | 'imports' | 'taint'>;

const annotationName = (a: string): string => (a.match(/^[\w.]+/)?.[0] ?? '').split('.').pop()!;
const isStringArray = (type: string | null): boolean => type !== null && type.replace(/\s+/g, '') === 'String[]';

const isMain = (m: MethodInfo): boolean =>
  m.name === 'main' && m.modifiers.includes('static')
  && m.parameters.length === 1 && isStringArray(m.parameters[0].type);

function isMojo(t: TypeInfo): boolean {
  return t.extends === 'AbstractMojo' || t.annotations.some(a => annotationName(a) === 'Mojo');
}

/** The innermost method around `line` that declares a parameter named `variable`. */
function methodOfParam(ir: ToolArgumentsIR, line: number, variable: string): { type: TypeInfo; method: MethodInfo } | undefined {
  let best: { type: TypeInfo; method: MethodInfo } | undefined;
  for (const type of ir.types) {
    for (const method of type.methods) {
      if (line < method.start_line || line > method.end_line) continue;
      if (!method.parameters.some(p => p.name === variable)) continue;
      if (!best || method.end_line - method.start_line < best.method.end_line - best.method.start_line) best = { type, method };
    }
  }
  return best;
}

/**
 * A non-public `String[]` method whose every call in the file is `main`
 * handing over its own array, as in `loadConfig(args)`.
 */
function receivesOnlyMainArgs(ir: ToolArgumentsIR, type: TypeInfo, method: MethodInfo): boolean {
  if (method.modifiers.includes('public') || method.parameters.length !== 1 || !isStringArray(method.parameters[0].type)) return false;
  const main = type.methods.find(isMain);
  if (!main) return false;
  const mainArgs = main.parameters[0].name;
  const calls = ir.calls.filter(c => c.method_name === method.name && (c.receiver === null || c.receiver === 'this' || c.receiver === type.name));
  return calls.length > 0 && calls.every(c =>
    c.in_method === 'main'
    && c.location.line >= main.start_line && c.location.line <= main.end_line
    && c.arguments.length === 1 && c.arguments[0].expression.trim() === mainArgs);
}

/** The setter Maven calls for a Mojo `@Parameter` field: `setReportFile` for `reportFile`. */
function isMojoParameterSetter(type: TypeInfo, method: MethodInfo): boolean {
  if (!isMojo(type) || method.parameters.length !== 1 || !/^set[A-Z]/.test(method.name)) return false;
  const field = method.name.charAt(3).toLowerCase() + method.name.slice(4);
  return type.fields.some(f => f.name === field && f.annotations.some(a => annotationName(a) === 'Parameter'));
}

function importsCommonsCli(ir: ToolArgumentsIR): boolean {
  return ir.imports.some(i => i.from_package === 'org.apache.commons.cli' || (i.from_package ?? '').startsWith('org.apache.commons.cli.'));
}

function readsCommandLine(ir: ToolArgumentsIR, line: number): boolean {
  return ir.calls.some(c => c.location.line === line && (
    (COMMONS_CLI_READS.has(c.method_name) && c.receiver_type === 'CommandLine')
    || (c.method_name === 'parse' && COMMONS_CLI_PARSERS.has(c.receiver_type ?? ''))));
}

/** `line:type` keys of the file's taint sources that are the tool's own arguments. */
export function toolArgumentSourceKeys(ir: ToolArgumentsIR): Set<string> {
  const keys = new Set<string>();
  if (ir.meta.language !== 'java') return keys;
  const cli = importsCommonsCli(ir);
  for (const s of ir.taint.sources) {
    if (s.type === 'interprocedural_param' && s.variable) {
      const at = methodOfParam(ir, s.line, s.variable);
      if (at && (isMain(at.method) || receivesOnlyMainArgs(ir, at.type, at.method) || isMojoParameterSetter(at.type, at.method))) {
        keys.add(`${s.line}:${s.type}`);
      }
    } else if (s.type === 'io_input' && cli && readsCommandLine(ir, s.line)) {
      keys.add(`${s.line}:${s.type}`);
    }
  }
  return keys;
}

function mark(item: { tags?: string[]; confidence: number }): void {
  item.tags = [...(item.tags ?? []), TOOL_ARGUMENTS_TAG];
  item.confidence *= CONFIDENCE_FACTOR;
}

/** Tag the file's own path-traversal flows whose source is a tool argument. */
export function markToolArgumentFlows(ir: ToolArgumentsIR): void {
  const flows = ir.taint.flows ?? [];
  if (!flows.some(f => f.sink_type === 'path_traversal')) return;
  const keys = toolArgumentSourceKeys(ir);
  if (keys.size === 0) return;
  for (const f of flows) {
    if (f.sink_type === 'path_traversal' && keys.has(`${f.source_line}:${f.source_type}`) && !f.tags?.includes(TOOL_ARGUMENTS_TAG)) mark(f);
  }
}

/**
 * Tag cross-file path-traversal paths whose source, in its own file, is a
 * tool argument, and the copy of each in the sink file's flows
 * (`promoteCrossFilePathsToSinkFlows`).
 */
export function markCrossFileToolArgumentPaths(
  fileAnalyses: Array<{ file: string; analysis: ToolArgumentsIR }>,
  taintPaths: TaintPath[],
): void {
  const keysByFile = new Map<string, Set<string>>();
  for (const tp of taintPaths) {
    if (tp.sink.type !== 'path_traversal' || tp.tags?.includes(TOOL_ARGUMENTS_TAG)) continue;
    let keys = keysByFile.get(tp.source.file);
    if (!keys) {
      const fa = fileAnalyses.find(f => f.file === tp.source.file);
      keys = fa ? toolArgumentSourceKeys(fa.analysis) : new Set();
      keysByFile.set(tp.source.file, keys);
    }
    if (!keys.has(`${tp.source.line}:${tp.source.type}`)) continue;
    mark(tp);
    if (tp.source.file === tp.sink.file) continue;
    const sinkFlows: TaintFlowInfo[] = fileAnalyses.find(f => f.file === tp.sink.file)?.analysis.taint.flows ?? [];
    for (const f of sinkFlows) {
      if (f.sink_line === tp.sink.line && f.sink_type === tp.sink.type && f.source_line === tp.source.line
        && f.source_type === tp.source.type && !f.tags?.includes(TOOL_ARGUMENTS_TAG)) mark(f);
    }
  }
}
