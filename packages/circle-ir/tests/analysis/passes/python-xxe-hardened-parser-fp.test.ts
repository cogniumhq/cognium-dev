/**
 * Tests for cognium-dev #216 sanitizer-wrapped FP cluster — Python `xxe`
 * (CWE-611) FP suppression on hardened-parser scopes
 * (Stage 18 in `sink-filter-pass.ts`, Sprint 52).
 *
 * The suppression rule: an xxe sink (fromstring / parse) is dropped when
 * `XMLParser(...resolve_entities=False...)` appears within the same
 * enclosing function body (≤30 lines above, halted at `def` boundary).
 *
 * Recall locks:
 *   - `resolve_entities=True` keeps firing (the regex requires `=False`)
 *   - sibling-function hardening does NOT suppress an unsafe sink
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countXxeSinks = (sinks: Array<{ type?: string }> | undefined) =>
  (sinks ?? []).filter(s => s.type === 'xxe').length;
const countXxeFlows = (flows: Array<{ sink_type?: string }> | undefined) =>
  (flows ?? []).filter(f => f.sink_type === 'xxe').length;

describe('cognium-dev #216 — Python xxe hardened-parser FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ---------------------------------------------------------------------------
  // FP suppression
  // ---------------------------------------------------------------------------

  it('FP — safe_parse wrapper with resolve_entities=False', async () => {
    const code = `import lxml.etree as ET
from flask import Flask, request

app = Flask(__name__)


def safe_parse(xml_bytes):
    parser = ET.XMLParser(resolve_entities=False, no_network=True)
    return ET.fromstring(xml_bytes, parser)


@app.route("/wrapped")
def wrapped():
    xml = request.args.get("xml", "")
    safe_parse(xml.encode())
`;
    const r = await analyze(code, 'sanitizer_combos_xxe.py', 'python');
    expect(countXxeSinks(r.taint?.sinks)).toBe(0);
    expect(countXxeFlows(r.taint?.flows)).toBe(0);
  });

  it('FP — class method with hardened parser (OOP wrapper)', async () => {
    const code = `import lxml.etree as ET
from flask import Flask, request

app = Flask(__name__)


class Importer:
    def __init__(self, xml):
        self.xml = xml

    def parse_direct(self):
        parser = ET.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
        return ET.fromstring(self.xml.encode(), parser)


@app.route("/import")
def imp():
    i = Importer(request.args.get("xml", ""))
    i.parse_direct()
    return "ok"
`;
    const r = await analyze(code, 'safe_oop_xxe.py', 'python');
    expect(countXxeSinks(r.taint?.sinks)).toBe(0);
    expect(countXxeFlows(r.taint?.flows)).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // Recall locks
  // ---------------------------------------------------------------------------

  it('recall — resolve_entities=True still fires xxe', async () => {
    const code = `import lxml.etree as ET
from flask import Flask, request

app = Flask(__name__)


@app.route("/unsafe")
def unsafe():
    xml = request.args.get("xml", "")
    parser = ET.XMLParser(resolve_entities=True, no_network=False)
    ET.fromstring(xml.encode(), parser)
`;
    const r = await analyze(code, 'unsafe_parser.py', 'python');
    expect(countXxeFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('recall — sibling-function hardening does NOT suppress unsafe sink', async () => {
    // Hardened parser exists in a sibling function (`safe_parse`), but the
    // unsafe sink in `unsafe()` builds its own resolve_entities=True parser.
    // The scope-aware backward scan must stop at the def boundary.
    const code = `import lxml.etree as ET
from flask import Flask, request

app = Flask(__name__)


def safe_parse(xml_bytes):
    parser = ET.XMLParser(resolve_entities=False, no_network=True)
    return ET.fromstring(xml_bytes, parser)


@app.route("/unsafe")
def unsafe():
    xml = request.args.get("xml", "")
    parser = ET.XMLParser(resolve_entities=True, no_network=False)
    ET.fromstring(xml.encode(), parser)
`;
    const r = await analyze(code, 'sibling_scope.py', 'python');
    expect(countXxeFlows(r.taint?.flows)).toBeGreaterThan(0);
  });
});
