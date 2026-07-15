/**
 * Catalog loaders — expose circle-ir's embedded taint sources / sinks /
 * sanitizers in a shape that MCP tools and resources can consume.
 *
 * We deliberately re-export the in-memory `DEFAULT_*` arrays from
 * `circle-ir` rather than reading the YAML/JSON config files off disk.
 * The defaults are the exact source of truth used at analysis time and
 * are always in sync with the installed version of the analyzer.
 */

import {
  DEFAULT_SANITIZERS,
  DEFAULT_SOURCES,
  DEFAULT_SINKS,
  type SinkType,
  type SourceType,
} from 'circle-ir';

/**
 * Normalized sanitizer catalog entry consumed by `check_sanitizer` and
 * `describe_sink` tools.
 */
export interface SanitizerCatalogEntry {
  /** Function / method names or `Class.method` combos that neutralize taint. */
  patterns: string[];
  /**
   * Restrict this entry to a specific sink category. `undefined` means the
   * sanitizer applies to every sink type it covers (`removes` list).
   */
  sinkType?: string;
  /** Optional language restriction (not currently distinguished in defaults). */
  language?: string;
  /** Provenance label — always `circle-ir:default` for embedded defaults. */
  source: string;
  /** Free-form note from the underlying pattern definition. */
  note?: string;
}

export interface SinkCatalogEntry {
  method: string;
  class?: string;
  type: SinkType;
  cwe: string;
  severity: string;
  argPositions: number[];
  languages?: string[];
  note?: string;
}

export interface SourceCatalogEntry {
  method?: string;
  class?: string;
  property?: string;
  object?: string;
  annotation?: string;
  methodAnnotation?: string;
  type: SourceType;
  severity: string;
  returnTainted?: boolean;
  paramTainted?: boolean;
  propertyTainted?: boolean;
  languages?: string[];
  note?: string;
}

let sanitizerCache: SanitizerCatalogEntry[] | null = null;
let sinkCache: SinkCatalogEntry[] | null = null;
let sourceCache: SourceCatalogEntry[] | null = null;

/**
 * Return the normalized sanitizer catalog. One catalog entry is produced
 * per `<pattern, sink-type>` combination so downstream filters can match
 * on `sinkType` cheaply.
 */
export function loadSanitizerCatalog(): SanitizerCatalogEntry[] {
  if (sanitizerCache) return sanitizerCache;

  const entries: SanitizerCatalogEntry[] = [];
  for (const s of DEFAULT_SANITIZERS) {
    const patterns: string[] = [];
    if (s.method && s.class) patterns.push(`${s.class}.${s.method}`);
    if (s.method) patterns.push(s.method);
    if (s.class && !s.method) patterns.push(s.class);
    if (s.annotation) patterns.push(s.annotation);

    if (patterns.length === 0) continue;
    const uniquePatterns = [...new Set(patterns)];

    if (s.removes && s.removes.length > 0) {
      for (const sinkType of s.removes) {
        entries.push({
          patterns: uniquePatterns,
          sinkType,
          source: 'circle-ir:default',
          note: s.note,
        });
      }
    } else {
      entries.push({
        patterns: uniquePatterns,
        source: 'circle-ir:default',
        note: s.note,
      });
    }
  }
  sanitizerCache = entries;
  return entries;
}

export function loadSinkCatalog(): SinkCatalogEntry[] {
  if (sinkCache) return sinkCache;
  sinkCache = DEFAULT_SINKS.map((s) => ({
    method: s.method,
    class: s.class,
    type: s.type,
    cwe: s.cwe,
    severity: s.severity,
    argPositions: s.arg_positions ?? [],
    languages: s.languages,
    note: s.note,
  }));
  return sinkCache;
}

export function loadSourceCatalog(): SourceCatalogEntry[] {
  if (sourceCache) return sourceCache;
  sourceCache = DEFAULT_SOURCES.map((s) => ({
    method: s.method,
    class: s.class,
    property: s.property,
    object: s.object,
    annotation: s.annotation,
    methodAnnotation: s.method_annotation,
    type: s.type,
    severity: s.severity,
    returnTainted: s.return_tainted,
    paramTainted: s.param_tainted,
    propertyTainted: s.property_tainted,
    languages: s.languages,
    note: s.note,
  }));
  return sourceCache;
}
