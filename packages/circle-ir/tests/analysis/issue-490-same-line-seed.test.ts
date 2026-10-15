/**
 * cognium-dev #490 (slice) — taint seeding on a source line.
 *
 * `findInitialTaint` seeded every definition on a source's line. Two cases
 * are narrowed here:
 *  - a second statement on the line (`q := r.FormValue("q"); x := "fixed"`)
 *    no longer inherits the named source's taint;
 *  - a bare-parameter source seeds the parameter binding only, not other
 *    definitions on the signature line (covered with #684).
 * Definitions linked to the source through data flow still get it.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function cmdi(code: string): Promise<number> {
  const ir = await analyze(code, 'probe_handler.go', 'go');
  return (ir.taint.flows ?? []).filter(f => f.sink_type === 'command_injection').length;
}

const wrap = (body: string) => `package main

import (
\t"net/http"
\t"os/exec"
)

func probe(w http.ResponseWriter, r *http.Request) {
${body}
}
`;

beforeAll(async () => {
  await initAnalyzer();
});

describe('#490 same-line second statement', () => {
  it('a constant defined beside the read is not tainted', async () => {
    expect(await cmdi(wrap('\tname := r.FormValue("name"); tool := "uptime"\n\t_ = name\n\texec.Command(tool).Run()'))).toBe(0);
  });

  it('split onto two lines: unchanged, still clean', async () => {
    expect(await cmdi(wrap('\tname := r.FormValue("name")\n\ttool := "uptime"\n\t_ = name\n\texec.Command(tool).Run()'))).toBe(0);
  });

  it('the read itself still reaches the sink on a shared line', async () => {
    expect(await cmdi(wrap('\tname := r.FormValue("name"); _ = 1\n\texec.Command(name).Run()'))).toBeGreaterThan(0);
  });

  it('a neighbour built from the read still reaches the sink', async () => {
    expect(await cmdi(wrap('\tname := r.FormValue("name"); tool := "ping " + name\n\texec.Command("sh", "-c", tool).Run()'))).toBeGreaterThan(0);
  });
});
