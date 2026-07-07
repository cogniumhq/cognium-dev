/**
 * MyBatisAnnotationSqlSinkPass — cognium-dev #241 Java
 *
 * Detects SQL injection sinks on MyBatis annotation-driven Mapper interface
 * methods. MyBatis distinguishes two placeholder syntaxes in `@Select` /
 * `@Update` / `@Insert` / `@Delete` (and their `*Provider` variants):
 *
 *   - `#{name}` — JDBC PreparedStatement parameter binding. SAFE.
 *   - `${name}` — raw string interpolation into the SQL string. **SQLi.**
 *
 * The taint-matcher's YAML sink registry (`configs/sinks/sql.yaml`) covers
 * standard Mapper method names (insert/update/select-wildcard/delete) via a
 * generic `mybatis_mapper_call` discovery marker, but cannot inspect the
 * contents of an annotation string. Custom method names (`findByName`,
 * `getUserById`) with `${}` interpolation therefore fall through both the
 * name-based Mapper matcher and any downstream SQLi flow generator.
 *
 * This pass closes that gap. For every Java interface whose method carries
 * a MyBatis SQL annotation containing at least one `${varname}`, the pass
 * records the tainted parameter positions (correlated to `@Param("name")`
 * annotations or MyBatis positional convention `${param1}` / `${0}`), then
 * walks `graph.calls` for call sites targeting those Mapper methods and
 * emits a synthetic `sql_injection` (CWE-89) `TaintSink` at each match.
 *
 * The synthetic sinks are pushed onto the `TaintMatcherResult.sinks` list
 * so `SinkFilterPass` (which merges taint-matcher + language-sources) and
 * downstream flow generators pick them up without any registry changes.
 *
 * Pipeline slot: runs after `LanguageSourcesPass` and before
 * `SinkFilterPass` so the synthetic sinks are visible to the four-stage
 * FP-elimination filter and to `TaintPropagationPass` / `InterproceduralPass`.
 *
 * Language scope: Java only. Non-Java files short-circuit at run().
 *
 * Kill switch: opt out via `disabledPasses: ['mybatis-annotation-sql-sink']`.
 */

import type {
  TaintSink,
  TypeInfo,
  MethodInfo,
  CallInfo,
} from '../../types/index.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { TaintMatcherResult } from './taint-matcher-pass.js';

export interface MyBatisAnnotationSqlSinkResult {
  /** Number of annotated Mapper methods with `${}` interpolation found. */
  annotatedMethodCount: number;
  /** Number of synthetic `sql_injection` sinks added. */
  addedSinkCount: number;
}

/**
 * MyBatis SQL annotations. The `*Provider` variants take a
 * `type = X.class, method = "y"` pair whose provider method returns the
 * SQL string; we still scan the annotation-attached literal (if any) for
 * `${}` markers as a best-effort recall bump.
 */
const MYBATIS_SQL_ANNOTATIONS = new Set([
  'Select',
  'Update',
  'Insert',
  'Delete',
  'SelectProvider',
  'UpdateProvider',
  'InsertProvider',
  'DeleteProvider',
]);

/**
 * Regex to extract `${varname}` interpolation markers from an annotation
 * string. Deliberately does NOT match `#{name}` (safe binding).
 * Variable names follow the MyBatis convention (identifier + optional
 * dotted property access, e.g. `${user.id}`) — we only use the leading
 * identifier when correlating to `@Param`.
 */
const DOLLAR_BRACE_RE = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z0-9_.]+)?\}/g;

/**
 * MyBatis positional convention: `${param1}` refers to the first argument
 * (1-based). `${0}` — some MyBatis versions — refers to the first argument
 * (0-based). We map both forms to a 0-based index.
 */
function parsePositionalRef(name: string): number | null {
  const paramMatch = /^param(\d+)$/.exec(name);
  if (paramMatch) {
    const oneBased = Number.parseInt(paramMatch[1]!, 10);
    if (Number.isFinite(oneBased) && oneBased >= 1) return oneBased - 1;
  }
  const zeroMatch = /^(\d+)$/.exec(name);
  if (zeroMatch) {
    const zeroBased = Number.parseInt(zeroMatch[1]!, 10);
    if (Number.isFinite(zeroBased) && zeroBased >= 0) return zeroBased;
  }
  return null;
}

/**
 * Extract the raw annotation-argument string from a stored annotation.
 * Annotations are stored as e.g. `Select("SELECT ... ${x} ...")` (without
 * the leading `@`). We return the substring between the outermost
 * parentheses, or `null` for a marker annotation with no arguments.
 */
function extractAnnotationBody(annotation: string): string | null {
  const openIdx = annotation.indexOf('(');
  if (openIdx < 0) return null;
  const closeIdx = annotation.lastIndexOf(')');
  if (closeIdx <= openIdx) return null;
  return annotation.substring(openIdx + 1, closeIdx);
}

/**
 * Given a stored annotation `Foo(...)`, return the leading identifier
 * `Foo`. For marker annotations without parens, returns the whole string.
 */
function annotationName(annotation: string): string {
  const openIdx = annotation.indexOf('(');
  return openIdx < 0 ? annotation : annotation.substring(0, openIdx);
}

/**
 * Return the value of the first string argument to a `@Param("name")`
 * annotation, or `null` if the annotation is not `@Param` or has no
 * literal string argument.
 */
function extractParamName(annotation: string): string | null {
  if (annotationName(annotation) !== 'Param') return null;
  const body = extractAnnotationBody(annotation);
  if (body === null) return null;
  // Match "..." or '...' at the start of the body. MyBatis @Param only
  // takes a single string literal, so a simple match is sufficient.
  const strMatch = /^\s*["']([^"']*)["']/.exec(body);
  return strMatch ? strMatch[1]! : null;
}

/**
 * Extract every `${varname}` reference from a MyBatis annotation body
 * (typically a single quoted string literal, sometimes concatenated).
 * Returns the deduplicated ordered list of leading identifiers.
 */
function extractDollarBraceRefs(annotationBody: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  DOLLAR_BRACE_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = DOLLAR_BRACE_RE.exec(annotationBody)) !== null) {
    const name = m[1]!;
    if (!seen.has(name)) {
      seen.add(name);
      out.push(name);
    }
  }
  return out;
}

/**
 * Check if the file imports MyBatis annotations, either directly or via
 * wildcard. Used to distinguish MyBatis `@Select` from unrelated libraries
 * (e.g. Reactor's `@Select`, custom application `@Select`) that happen to
 * share the simple annotation name.
 */
function fileImportsMyBatis(imports: readonly { from_package: string | null }[]): boolean {
  for (const imp of imports) {
    const pkg = imp.from_package;
    if (!pkg) continue;
    if (
      pkg === 'org.apache.ibatis.annotations' ||
      pkg.startsWith('org.apache.ibatis.annotations.') ||
      pkg === 'org.apache.ibatis' ||
      pkg.startsWith('org.apache.ibatis.')
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Correlate every `${name}` reference to a 0-based parameter index. When
 * the method carries `@Param("name")` on any parameter, that mapping wins.
 * Otherwise MyBatis positional convention is used (`${param1}`, `${0}`).
 * Returns the deduplicated ascending list of tainted arg positions.
 */
function correlateDollarBraceToArgPositions(
  method: MethodInfo,
  refs: readonly string[],
): number[] {
  const paramNameToIndex = new Map<string, number>();
  method.parameters.forEach((param, idx) => {
    for (const ann of param.annotations) {
      const paramName = extractParamName(ann);
      if (paramName !== null) {
        paramNameToIndex.set(paramName, idx);
      }
    }
  });

  const positions = new Set<number>();
  for (const ref of refs) {
    const namedIdx = paramNameToIndex.get(ref);
    if (namedIdx !== undefined) {
      positions.add(namedIdx);
      continue;
    }
    const positionalIdx = parsePositionalRef(ref);
    if (
      positionalIdx !== null &&
      positionalIdx < method.parameters.length
    ) {
      positions.add(positionalIdx);
    }
  }
  return Array.from(positions).sort((a, b) => a - b);
}

/**
 * Return the fully-qualified name of a Mapper interface method for use as
 * a callee lookup key. Falls back to `<simpleName>.<methodName>` when the
 * interface has no declared package.
 */
function mapperMethodKey(type: TypeInfo, method: MethodInfo): string {
  const iface = type.package ? `${type.package}.${type.name}` : type.name;
  return `${iface}.${method.name}`;
}

/**
 * Match a call site against a Mapper interface method by callee tail. We
 * accept:
 *   - `resolution.target` equal to or ending with the mapper key
 *   - simple `method_name` equal to the mapper's method AND
 *     `receiver_type` or `receiver_type_fqn` equal to the mapper's
 *     interface (simple- or fully-qualified name).
 *
 * Conservative on both sides — unresolved receivers fall through.
 */
function isMapperMethodCall(
  call: CallInfo,
  interfaceSimpleName: string,
  interfaceFqn: string,
  methodName: string,
): boolean {
  // Path 1 — resolution target tail match.
  const target = call.resolution?.target;
  if (target) {
    const suffix = `${interfaceSimpleName}.${methodName}`;
    const suffixFqn = `${interfaceFqn}.${methodName}`;
    if (
      target === suffix ||
      target === suffixFqn ||
      target.endsWith('.' + suffix) ||
      target.endsWith('.' + suffixFqn)
    ) {
      return true;
    }
  }

  // Path 2 — method name + receiver type match.
  if (call.method_name !== methodName) return false;
  if (call.receiver_type === interfaceSimpleName) return true;
  if (call.receiver_type_fqn === interfaceFqn) return true;
  return false;
}

export class MyBatisAnnotationSqlSinkPass
  implements AnalysisPass<MyBatisAnnotationSqlSinkResult>
{
  readonly name = 'mybatis-annotation-sql-sink';
  readonly category = 'security' as const;

  run(ctx: PassContext): MyBatisAnnotationSqlSinkResult {
    if (ctx.language !== 'java') {
      return { annotatedMethodCount: 0, addedSinkCount: 0 };
    }

    const { types, imports, calls } = ctx.graph.ir;

    // Gate on file-level MyBatis import to distinguish real Mapper
    // interfaces from unrelated libraries reusing the `@Select` name.
    if (!fileImportsMyBatis(imports)) {
      return { annotatedMethodCount: 0, addedSinkCount: 0 };
    }

    // Collect Mapper methods with `${}` interpolation and their tainted
    // argument positions.
    interface MapperMethodRecord {
      interfaceSimpleName: string;
      interfaceFqn: string;
      methodName: string;
      taintedArgPositions: number[];
    }
    const mapperMethods: MapperMethodRecord[] = [];

    for (const type of types) {
      if (type.kind !== 'interface') continue;
      for (const method of type.methods) {
        // Find MyBatis SQL annotation, extract body, scan for `${}`.
        let matchedRefs: string[] = [];
        for (const ann of method.annotations) {
          if (!MYBATIS_SQL_ANNOTATIONS.has(annotationName(ann))) continue;
          const body = extractAnnotationBody(ann);
          if (body === null) continue;
          const refs = extractDollarBraceRefs(body);
          if (refs.length > 0) {
            matchedRefs = [...matchedRefs, ...refs];
          }
        }
        if (matchedRefs.length === 0) continue;

        const positions = correlateDollarBraceToArgPositions(
          method,
          matchedRefs,
        );
        if (positions.length === 0) continue;

        const interfaceFqn = type.package
          ? `${type.package}.${type.name}`
          : type.name;
        mapperMethods.push({
          interfaceSimpleName: type.name,
          interfaceFqn,
          methodName: method.name,
          taintedArgPositions: positions,
        });
      }
    }

    if (mapperMethods.length === 0) {
      return {
        annotatedMethodCount: 0,
        addedSinkCount: 0,
      };
    }

    // Grab the taint-matcher sinks array to append into. When the pass is
    // run stand-alone (unit-test harness) without TaintMatcherPass, we
    // fall back to graph.ir.taint.sinks so tests can still observe the
    // added sinks.
    const sinks: TaintSink[] = ctx.hasResult('taint-matcher')
      ? ctx.getResult<TaintMatcherResult>('taint-matcher').sinks
      : ctx.graph.ir.taint.sinks;

    let addedSinkCount = 0;
    for (const call of calls) {
      for (const rec of mapperMethods) {
        if (
          !isMapperMethodCall(
            call,
            rec.interfaceSimpleName,
            rec.interfaceFqn,
            rec.methodName,
          )
        ) {
          continue;
        }
        // Dedup: skip if a `sql_injection` sink already exists at this
        // call site.
        const line = call.location.line;
        if (
          sinks.some(
            (s) =>
              s.line === line &&
              s.type === 'sql_injection' &&
              s.method === rec.methodName,
          )
        ) {
          continue;
        }
        const receiverLoc = call.receiver
          ? `${call.receiver}.${rec.methodName}()`
          : `${rec.methodName}()`;
        sinks.push({
          type: 'sql_injection',
          cwe: 'CWE-89',
          location: call.in_method
            ? `${receiverLoc} in ${call.in_method}`
            : receiverLoc,
          line,
          confidence: 0.95,
          method: rec.methodName,
          argPositions: rec.taintedArgPositions,
          class: rec.interfaceSimpleName,
        });
        addedSinkCount++;
      }
    }

    return {
      annotatedMethodCount: mapperMethods.length,
      addedSinkCount,
    };
  }
}
