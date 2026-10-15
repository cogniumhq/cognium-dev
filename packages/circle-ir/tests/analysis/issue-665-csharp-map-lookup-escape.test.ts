/**
 * cognium-dev#665 — a C# dictionary lookup keyed by a request value was
 * reported as `external_taint_escape`. `Map.TryGetValue(key, out var v)` reads
 * an in-memory collection; nothing leaves the program, and the miss branch
 * rejecting the request is the allowlist shape.
 *
 * The escape gate (`isCSharpNonEscapeCall`) now treats the lookup verbs like
 * the collection stores it already covered. A tainted value handed to a real
 * external call in the same handler must still escape.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const escapes = async (code: string): Promise<number[]> => {
  const r = await analyze(code, 'Shop.cs', 'csharp');
  return (r.taint?.flows ?? [])
    .filter(f => f.sink_type === 'external_taint_escape')
    .map(f => f.sink_line)
    .sort((a, b) => a - b);
};

describe('#665 C# dictionary lookup is not an external escape', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('TryGetValue keyed by a form field is clean', async () => {
    const lines = await escapes(`using Microsoft.AspNetCore.Mvc;
public class OrderDesk : Controller {
  static readonly System.Collections.Generic.Dictionary<string, double> Prices = new() {
    ["a1"] = 3.5, ["b2"] = 7.25
  };
  [HttpPost("/buy")]
  public IActionResult Buy([FromForm] string item, [FromForm] int count) {
    if (!Prices.TryGetValue(item, out var unit)) return BadRequest();
    return Ok(new { total = unit * count });
  }
}`);
    expect(lines).toEqual([]);
  });

  it('ContainsKey / GetValueOrDefault lookups are clean', async () => {
    const lines = await escapes(`using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
public class Rates : Controller {
  static readonly Dictionary<string, int> Table = new();
  [HttpGet("/rate")]
  public IActionResult Rate([FromQuery] string code) {
    if (!Table.ContainsKey(code)) return NotFound();
    var hits = Table.GetValueOrDefault(code, 0);
    return Ok();
  }
}`);
    expect(lines).toEqual([]);
  });

  it('a tainted value passed to an unknown external call still escapes', async () => {
    const lines = await escapes(`using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
public class Relay : Controller {
  static readonly Dictionary<string, double> Prices = new();
  [HttpPost("/relay")]
  public IActionResult Send([FromForm] string item) {
    if (!Prices.TryGetValue(item, out var unit)) return BadRequest();
    PartnerGateway.Forward(item);
    return Ok(unit);
  }
}`);
    expect(lines).toEqual([8]);
  });
});
