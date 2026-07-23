/**
 * DeserializationSafetyGatePass — cognium-dev #258
 *
 * Drops `deserialization` sinks whose surrounding library configuration
 * renders them non-exploitable. Java-only in the MVP scope; runs after
 * `SinkSemanticsPass` (so upstream registry gates have already fired)
 * and before `TaintPropagationPass` (so flow generators never see the
 * dropped sinks).
 *
 * Three sub-gates:
 *
 *   Gate A — Fastjson `*_noneautotype` build (manifest-based).
 *     Reads `AnalyzerOptions.dependencyContext.java.pomXml`, resolves
 *     the effective Fastjson coordinate, and drops
 *     `JSON.parseObject` / `JSON.parse` deserialization sinks when the
 *     version literally matches the hardened classifier — UNLESS the
 *     file itself re-enables autotype via `setAutoTypeSupport(true)`
 *     (in which case the pinned build's protection is defeated and the
 *     sink continues to fire).
 *
 *   Gate B — Jackson polymorphism not enabled (in-file scan).
 *     `ObjectMapper.readValue(json, targetType)` is safe on Jackson
 *     ≥ 2.10 unless the file enables polymorphic type handling via
 *     `enableDefaultTyping` / `activateDefaultTyping` or applies
 *     `@JsonTypeInfo` somewhere. When none of those signals appear in
 *     the file, drop `ObjectMapper.readValue` deserialization sinks.
 *
 *   Gate C — SnakeYAML `SafeConstructor` (in-file scan).
 *     `new Yaml(new SafeConstructor())` gives a Yaml instance whose
 *     `.load(...)` cannot instantiate arbitrary classes. When the file
 *     builds any Yaml with SafeConstructor, drop `Yaml.load` /
 *     `Yaml.loadAs` / `Yaml.loadAll` deserialization sinks.
 *
 * Each sub-gate is defensive: on missing signal it defaults to *do
 * not drop* (the sink continues to fire). So a resolver bug can only
 * ever regress toward the current over-firing behaviour, never toward
 * a false negative.
 *
 * See `docs/PASSES.md` for the canonical pass registry entry.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { TaintSink } from '../../types/index.js';
import type { SinkFilterResult } from './sink-filter-pass.js';
import type { DependencyContext } from '../../analyzer.js';
import {
  resolveFastjsonFromPom,
  resolveFastjsonFromGradle,
  resolvePyYamlFromRequirements,
  resolvePyYamlFromPyproject,
  fileHasUnsafePyYamlLoader,
  fileReenablesFastjsonAutotype,
  fileEnablesJacksonPolymorphism,
  fileConfiguresSnakeYamlSafely,
} from '../dependency-versions.js';

export interface DeserializationSafetyGateResult {
  /** Sinks dropped by Gate A (Fastjson noneautotype). */
  droppedFastjson: number;
  /** Sinks dropped by Gate B (Jackson polymorphism not enabled). */
  droppedJackson: number;
  /** Sinks dropped by Gate C (SnakeYAML SafeConstructor). */
  droppedSnakeYaml: number;
  /** Sinks dropped by Gate D (Python PyYAML ≥ 6.0 default-safe). */
  droppedPyYaml: number;
}

const FASTJSON_METHODS = new Set(['parseObject', 'parse']);
const FASTJSON_CLASSES = new Set(['JSON', 'JSONObject']);

const JACKSON_METHODS = new Set(['readValue', 'convertValue', 'treeToValue']);
const JACKSON_CLASSES = new Set(['ObjectMapper', 'ObjectReader']);

const SNAKEYAML_METHODS = new Set(['load', 'loadAs', 'loadAll']);
const SNAKEYAML_CLASSES = new Set(['Yaml']);

// Python PyYAML gate (Gate D — cognium-dev #261 Python slice).
const PYYAML_METHODS = new Set(['load']);
const PYYAML_CLASSES = new Set(['yaml']);

export class DeserializationSafetyGatePass
  implements AnalysisPass<DeserializationSafetyGateResult>
{
  readonly name = 'deserialization-safety-gate';
  readonly category = 'security' as const;

  constructor(private readonly dependencyContext?: DependencyContext) {}

  run(ctx: PassContext): DeserializationSafetyGateResult {
    const { graph, language, code } = ctx;

    // Java + Python for the MVP. Other languages (JS Deserialize,
    // Rust bincode) can extend the gate on their own manifests in
    // follow-up scopes.
    if (language !== 'java' && language !== 'python') {
      return { droppedFastjson: 0, droppedJackson: 0, droppedSnakeYaml: 0, droppedPyYaml: 0 };
    }

    // Same sink-source discovery as SinkSemanticsPass: prefer
    // SinkFilterResult when the real pipeline has run, otherwise fall
    // back to the graph's initial (usually empty) sink array so
    // stand-alone unit-test harnesses can drive the gate directly.
    const sinks: TaintSink[] = ctx.hasResult('sink-filter')
      ? ctx.getResult<SinkFilterResult>('sink-filter').sinks
      : graph.ir.taint.sinks;

    // --- Gate A: Fastjson _noneautotype ------------------------------------
    // Consult pom.xml first; fall back to build.gradle when pom does
    // not resolve. Both manifests may be supplied by a caller that
    // scans a multi-build project; either one indicating the hardened
    // classifier is sufficient to drop the sink.
    const pomXml = this.dependencyContext?.java?.pomXml;
    const buildGradle = this.dependencyContext?.java?.buildGradle;
    const fastjson =
      (pomXml ? resolveFastjsonFromPom(pomXml) : null) ??
      (buildGradle ? resolveFastjsonFromGradle(buildGradle) : null);
    const fastjsonHardened =
      fastjson?.noneAutotype === true &&
      !fileReenablesFastjsonAutotype(code);

    // --- Gate B: Jackson polymorphism ---------------------------------------
    const jacksonSafe = !fileEnablesJacksonPolymorphism(code);

    // --- Gate C: SnakeYAML SafeConstructor ----------------------------------
    const snakeYamlSafe = fileConfiguresSnakeYamlSafely(code);

    // --- Gate D: PyYAML ≥ 6.0 (Python) --------------------------------------
    // Under pyyaml ≥ 6.0, `yaml.load(x)` without an explicit `Loader=`
    // keyword arg raises TypeError (safe-by-default); callers that pass
    // `Loader=SafeLoader` are safe; callers that pass an unsafe Loader
    // (`Loader=Loader` / `UnsafeLoader` / `FullLoader`) are still
    // dangerous regardless of the version pin — those need per-call
    // inspection to preserve.
    const requirementsTxt = this.dependencyContext?.python?.requirementsTxt;
    const pyprojectToml = this.dependencyContext?.python?.pyprojectToml;
    const pyYaml =
      (requirementsTxt ? resolvePyYamlFromRequirements(requirementsTxt) : null) ??
      (pyprojectToml ? resolvePyYamlFromPyproject(pyprojectToml) : null);
    const pyYamlSafeByDefault = pyYaml?.safeByDefault === true;
    // Lazy: only split source lines when we actually need per-call
    // inspection (i.e. gate D is active and could fire).
    let sourceLines: string[] | null = null;
    const getSourceLines = (): string[] => {
      if (sourceLines === null) sourceLines = code.split('\n');
      return sourceLines;
    };

    let droppedFastjson = 0;
    let droppedJackson = 0;
    let droppedSnakeYaml = 0;
    let droppedPyYaml = 0;

    const kept = sinks.filter((sink) => {
      if (sink.type !== 'deserialization') return true;
      if (!sink.method) return true;

      // Gate A — Fastjson
      if (
        fastjsonHardened &&
        FASTJSON_METHODS.has(sink.method) &&
        (sink.class === undefined || FASTJSON_CLASSES.has(sink.class))
      ) {
        droppedFastjson++;
        return false;
      }

      // Gate B — Jackson
      if (
        jacksonSafe &&
        JACKSON_METHODS.has(sink.method) &&
        sink.class !== undefined &&
        JACKSON_CLASSES.has(sink.class)
      ) {
        droppedJackson++;
        return false;
      }

      // Gate C — SnakeYAML
      if (
        snakeYamlSafe &&
        SNAKEYAML_METHODS.has(sink.method) &&
        sink.class !== undefined &&
        SNAKEYAML_CLASSES.has(sink.class)
      ) {
        droppedSnakeYaml++;
        return false;
      }

      // Gate D — PyYAML (Python). `sink.class` may be `undefined` for
      // Python: unlike Java, Python calls do not carry receiver-type
      // resolution into the CallInfo, so the taint-matcher's sinkMap
      // assigns undefined for the class field. Accept undefined OR
      // exact-`'yaml'` (mirrors Gate A's Fastjson check).
      if (
        language === 'python' &&
        pyYamlSafeByDefault &&
        PYYAML_METHODS.has(sink.method) &&
        (sink.class === undefined || PYYAML_CLASSES.has(sink.class)) &&
        !fileHasUnsafePyYamlLoader(getSourceLines(), sink.line)
      ) {
        droppedPyYaml++;
        return false;
      }

      return true;
    });

    const totalDropped = droppedFastjson + droppedJackson + droppedSnakeYaml + droppedPyYaml;
    if (totalDropped > 0) {
      // Mutate in place so downstream passes see the reduced sink set.
      // Matches SinkSemanticsPass's contract.
      sinks.length = 0;
      sinks.push(...kept);
    }

    return { droppedFastjson, droppedJackson, droppedSnakeYaml, droppedPyYaml };
  }
}
