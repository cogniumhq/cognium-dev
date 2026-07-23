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
}

const FASTJSON_METHODS = new Set(['parseObject', 'parse']);
const FASTJSON_CLASSES = new Set(['JSON', 'JSONObject']);

const JACKSON_METHODS = new Set(['readValue', 'convertValue', 'treeToValue']);
const JACKSON_CLASSES = new Set(['ObjectMapper', 'ObjectReader']);

const SNAKEYAML_METHODS = new Set(['load', 'loadAs', 'loadAll']);
const SNAKEYAML_CLASSES = new Set(['Yaml']);

export class DeserializationSafetyGatePass
  implements AnalysisPass<DeserializationSafetyGateResult>
{
  readonly name = 'deserialization-safety-gate';
  readonly category = 'security' as const;

  constructor(private readonly dependencyContext?: DependencyContext) {}

  run(ctx: PassContext): DeserializationSafetyGateResult {
    const { graph, language, code } = ctx;

    // Java-only for the MVP. Other languages (Python pyyaml, JS
    // Deserialize, Rust bincode) can extend the gate on their own
    // manifests in follow-up scopes.
    if (language !== 'java') {
      return { droppedFastjson: 0, droppedJackson: 0, droppedSnakeYaml: 0 };
    }

    // Same sink-source discovery as SinkSemanticsPass: prefer
    // SinkFilterResult when the real pipeline has run, otherwise fall
    // back to the graph's initial (usually empty) sink array so
    // stand-alone unit-test harnesses can drive the gate directly.
    const sinks: TaintSink[] = ctx.hasResult('sink-filter')
      ? ctx.getResult<SinkFilterResult>('sink-filter').sinks
      : graph.ir.taint.sinks;

    // --- Gate A: Fastjson _noneautotype ------------------------------------
    const pomXml = this.dependencyContext?.java?.pomXml;
    const fastjson = pomXml ? resolveFastjsonFromPom(pomXml) : null;
    const fastjsonHardened =
      fastjson?.noneAutotype === true &&
      !fileReenablesFastjsonAutotype(code);

    // --- Gate B: Jackson polymorphism ---------------------------------------
    const jacksonSafe = !fileEnablesJacksonPolymorphism(code);

    // --- Gate C: SnakeYAML SafeConstructor ----------------------------------
    const snakeYamlSafe = fileConfiguresSnakeYamlSafely(code);

    let droppedFastjson = 0;
    let droppedJackson = 0;
    let droppedSnakeYaml = 0;

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

      return true;
    });

    const totalDropped = droppedFastjson + droppedJackson + droppedSnakeYaml;
    if (totalDropped > 0) {
      // Mutate in place so downstream passes see the reduced sink set.
      // Matches SinkSemanticsPass's contract.
      sinks.length = 0;
      sinks.push(...kept);
    }

    return { droppedFastjson, droppedJackson, droppedSnakeYaml };
  }
}
