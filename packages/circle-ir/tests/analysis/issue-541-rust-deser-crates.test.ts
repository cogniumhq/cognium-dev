/**
 * cognium-dev #541 — a false-negative regression shipped in 4.9.28.
 *
 * #484 removed the classless `from_str` / `from_slice` deserialization rows,
 * which were matching every `T::from_str` — `u32::from_str`, `Url::from_str`,
 * `PublicKey::from_slice` — i.e. ordinary `FromStr` and byte parsing that
 * cannot instantiate an attacker-chosen type. That removal was right.
 *
 * What was missed is that those classless rows had also been the *only* thing
 * covering every serde data format without an explicit entry. Four formats had
 * class-scoped rows and kept working; the rest silently lost their sink. The
 * reported case was `rmp_serde::from_slice` on bytes read straight off a
 * `TcpStream`, which took the Rust synthetic suite from 92.3% to 89.6%.
 *
 * These tests pin both directions: the data formats register, and the ordinary
 * parsing that #484 cleaned up stays clean.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const run = (code: string) => analyze(code, 'm.rs', 'rust');
const deserLines = (r: Awaited<ReturnType<typeof run>>) =>
  (r.taint.sinks ?? []).filter(s => s.type === 'deserialization').map(s => s.line);

describe('#541 Rust serde data formats register as deserialization sinks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // One row per data format, path-qualified call form.
  const formats: Array<[string, string]> = [
    ['rmp_serde', 'from_slice(&buffer)'],
    ['rmp_serde', 'from_read(reader)'],
    ['serde_json', 'from_slice(&buffer)'],
    ['serde_yaml', 'from_slice(&buffer)'],
    ['toml', 'from_slice(&buffer)'],
    ['postcard', 'from_bytes(&buffer)'],
    ['serde_cbor', 'from_slice(&buffer)'],
    ['ciborium', 'from_reader(reader)'],
    ['bincode', 'from_slice(&buffer)'],
    ['quick_xml', 'from_str(&text)'],
    ['serde_xml_rs', 'from_str(&text)'],
  ];

  for (const [crate, call] of formats) {
    it(`registers ${crate}::${call.split('(')[0]}`, async () => {
      const r = await run(`
fn f(buffer: &[u8], text: &str, reader: R) -> Packet {
    ${crate}::${call}.unwrap()
}
`);
      expect(deserLines(r)).toContain(3);
    });
  }

  it('registers the imported call form and links it to a flow', async () => {
    // The `::` separator fix (#484) is what makes the class-scoped row match a
    // bare imported call; without it these rows would be inert for this shape.
    const r = await run(`
use rmp_serde::from_slice;
fn f(buffer: &[u8]) -> Packet {
    from_slice(buffer).unwrap()
}
`);
    expect(deserLines(r)).toContain(4);
  });

  it('still does not flag ordinary FromStr and byte parsing (#484 must hold)', async () => {
    const r = await run(`
use std::str::FromStr;
fn a(s: &str) -> u32 { u32::from_str(s).unwrap() }
fn b(b: &[u8]) -> PublicKey { PublicKey::from_slice(b).unwrap() }
fn c(s: &str) -> Url { Url::from_str(s).unwrap() }
fn d(s: &str) -> IpAddr { IpAddr::from_str(s).unwrap() }
`);
    expect(deserLines(r)).toEqual([]);
  });

  it('reports MessagePack deserialization of bytes read off a socket', async () => {
    // The exact shape from the issue.
    const r = await run(`
use std::net::TcpStream;
use std::io::Read;
fn receive_packet(mut stream: TcpStream) -> Packet {
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).unwrap();
    rmp_serde::from_slice(&buffer).unwrap()
}
`);
    expect(deserLines(r)).toContain(7);
  });
});
