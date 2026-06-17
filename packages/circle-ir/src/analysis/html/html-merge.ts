/**
 * HTML Result Merger
 *
 * Merges multiple CircleIR results (one per script block) and attribute-level
 * security findings into a single CircleIR for the HTML file.
 *
 * Key operation: adjusts all line numbers by (lineOffset - 1) for each script block
 * and normalizes file paths to the HTML file path.
 */

import type {
  CircleIR,
  Meta,
  TypeInfo,
  CallInfo,
  CFG,
  CFGBlock,
  CFGEdge,
  DFG,
  DFGDef,
  DFGUse,
  Taint,
  TaintSource,
  TaintSink,
  TaintSanitizer,
  TaintFlowInfo,
  ImportInfo,
  ExportInfo,
  SastFinding,
} from '../../types/index.js';

export interface ScriptBlockResult {
  ir: CircleIR;
  lineOffset: number;
}

/**
 * Merge HTML analysis results into a single CircleIR.
 *
 * @param htmlMeta - Meta for the HTML file itself
 * @param scriptResults - CircleIR results from each script block with line offsets
 * @param attributeFindings - SastFindings from attribute-level security checks
 */
export function mergeHtmlResults(
  htmlMeta: Meta,
  scriptResults: ScriptBlockResult[],
  attributeFindings: SastFinding[],
): CircleIR {
  const allTypes: TypeInfo[] = [];
  const allCalls: CallInfo[] = [];
  const allCfgBlocks: CFGBlock[] = [];
  const allCfgEdges: CFGEdge[] = [];
  const allDfgDefs: DFGDef[] = [];
  const allDfgUses: DFGUse[] = [];
  const allSources: TaintSource[] = [];
  const allSinks: TaintSink[] = [];
  const allSanitizers: TaintSanitizer[] = [];
  const allFlows: TaintFlowInfo[] = [];
  const allImports: ImportInfo[] = [];
  const allExports: ExportInfo[] = [];
  const allFindings: SastFinding[] = [];

  let cfgBlockIdOffset = 0;
  let dfgDefIdOffset = 0;
  let dfgUseIdOffset = 0;

  for (const { ir, lineOffset } of scriptResults) {
    const lineShift = lineOffset - 1;
    const htmlFile = htmlMeta.file;

    // Shift types
    for (const type of ir.types) {
      allTypes.push({
        ...type,
        start_line: type.start_line + lineShift,
        end_line: type.end_line + lineShift,
        methods: type.methods.map(m => ({
          ...m,
          start_line: m.start_line + lineShift,
          end_line: m.end_line + lineShift,
        })),
        fields: [...type.fields],
      });
    }

    // Shift calls
    for (const call of ir.calls) {
      allCalls.push({
        ...call,
        location: {
          ...call.location,
          line: call.location.line + lineShift,
        },
      });
    }

    // Shift CFG blocks and edges (with ID remapping)
    const maxBlockId = ir.cfg.blocks.reduce((max, b) => Math.max(max, b.id), 0);
    for (const block of ir.cfg.blocks) {
      allCfgBlocks.push({
        ...block,
        id: block.id + cfgBlockIdOffset,
        start_line: block.start_line + lineShift,
        end_line: block.end_line + lineShift,
      });
    }
    for (const edge of ir.cfg.edges) {
      allCfgEdges.push({
        ...edge,
        from: edge.from + cfgBlockIdOffset,
        to: edge.to + cfgBlockIdOffset,
      });
    }
    cfgBlockIdOffset += maxBlockId + 1;

    // Shift DFG defs and uses (with ID remapping)
    const maxDefId = ir.dfg.defs.reduce((max, d) => Math.max(max, d.id), 0);
    const maxUseId = ir.dfg.uses.reduce((max, u) => Math.max(max, u.id), 0);
    for (const def of ir.dfg.defs) {
      allDfgDefs.push({
        ...def,
        id: def.id + dfgDefIdOffset,
        line: def.line + lineShift,
      });
    }
    for (const use of ir.dfg.uses) {
      allDfgUses.push({
        ...use,
        id: use.id + dfgUseIdOffset,
        def_id: use.def_id !== null ? use.def_id + dfgDefIdOffset : null,
        line: use.line + lineShift,
      });
    }
    dfgDefIdOffset += maxDefId + 1;
    dfgUseIdOffset += maxUseId + 1;

    // Shift taint sources/sinks/sanitizers
    for (const source of ir.taint.sources) {
      allSources.push({
        ...source,
        line: source.line + lineShift,
      });
    }
    for (const sink of ir.taint.sinks) {
      allSinks.push({
        ...sink,
        line: sink.line + lineShift,
      });
    }
    for (const sanitizer of ir.taint.sanitizers ?? []) {
      allSanitizers.push({
        ...sanitizer,
        line: sanitizer.line + lineShift,
      });
    }
    for (const flow of ir.taint.flows ?? []) {
      allFlows.push({
        ...flow,
        source_line: flow.source_line + lineShift,
        sink_line: flow.sink_line + lineShift,
        path: flow.path.map(step => ({ ...step, line: step.line + lineShift })),
      });
    }

    // Shift imports
    for (const imp of ir.imports) {
      allImports.push({
        ...imp,
        line_number: imp.line_number !== null ? imp.line_number + lineShift : null,
      });
    }

    // Exports
    allExports.push(...ir.exports);

    // Shift findings and normalize file paths
    for (const finding of ir.findings ?? []) {
      allFindings.push({
        ...finding,
        file: htmlFile,
        line: finding.line + lineShift,
      });
    }
  }

  // Add attribute-level findings
  allFindings.push(...attributeFindings);

  const taint: Taint = {
    sources: allSources,
    sinks: allSinks,
    sanitizers: allSanitizers.length > 0 ? allSanitizers : undefined,
    flows: allFlows.length > 0 ? allFlows : undefined,
  };

  const cfg: CFG = {
    blocks: allCfgBlocks,
    edges: allCfgEdges,
  };

  const dfg: DFG = {
    defs: allDfgDefs,
    uses: allDfgUses,
  };

  return {
    meta: htmlMeta,
    types: allTypes,
    calls: allCalls,
    cfg,
    dfg,
    taint,
    imports: allImports,
    exports: allExports,
    unresolved: [],
    enriched: {},
    findings: allFindings.length > 0 ? allFindings : undefined,
  };
}
