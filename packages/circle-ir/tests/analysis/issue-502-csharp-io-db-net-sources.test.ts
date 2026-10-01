/**
 * #502 — C# had no source model for data read from a socket, an HTTP client, a
 * file or a database row, so every flow from those reads was silent. Seven of
 * the ten scored Juliet C# CWE families were at 0.0% partly for this reason.
 *
 * Mirrors Java one-for-one, including the severity split: console/file I/O is
 * `io_input` at high, a database row read is `db_input` at medium
 * (`BufferedReader.readLine` vs `ResultSet.getString`). There is no separate
 * confidence tier — `type` + `severity` IS the tier.
 *
 * Declared-type scoped because the method names are generic: matching
 * `ReadLine` or `GetString` on any receiver would fire on unrelated types.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const run = async (code: string) => {
  const r = await analyze(code, 'P.cs', 'csharp');
  const t = r.taint ?? ({} as NonNullable<typeof r.taint>);
  return {
    sources: t.sources ?? [],
    sinks: t.sinks ?? [],
    flows: t.flows ?? [],
  };
};

describe('#502 C# I/O, network and database sources', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('seeds a file read through StreamReader and reaches a command sink', async () => {
    const { sources, flows } = await run(`using System.IO; using System.Diagnostics;
public class P { public void Bad() {
  StreamReader sr = new StreamReader("f.txt");
  string data = sr.ReadLine();
  Process.Start("cmd /c " + data);
} }`);
    expect(sources.some(s => s.type === 'io_input' && s.variable === 'data')).toBe(true);
    expect(flows.length).toBeGreaterThan(0);
  });

  it('seeds a database row read as db_input at medium, not high', async () => {
    const { sources, flows } = await run(`using System.Data.SqlClient; using System.Diagnostics;
public class P { public void Bad(SqlDataReader rdr) {
  string data = rdr.GetString(0);
  Process.Start("cmd /c " + data);
} }`);
    const db = sources.find(s => s.type === 'db_input');
    expect(db).toBeDefined();
    // Java parity: ResultSet.getString is medium while BufferedReader.readLine is high.
    expect(db?.severity).toBe('medium');
    expect(flows.length).toBeGreaterThan(0);
  });

  it('seeds a WebClient response read', async () => {
    const { flows } = await run(`using System.IO; using System.Net; using System.Diagnostics;
public class P { public void Bad() {
  WebClient wc = new WebClient();
  StreamReader sr = new StreamReader(wc.OpenRead("http://h/"));
  string data = sr.ReadLine();
  Process.Start("cmd /c " + data);
} }`);
    expect(flows.length).toBeGreaterThan(0);
  });

  it('seeds a TcpListener accept chain', async () => {
    const { flows } = await run(`using System.IO; using System.Net.Sockets; using System.Diagnostics;
public class P { public void Bad(TcpListener l) {
  TcpClient c = l.AcceptTcpClient();
  StreamReader sr = new StreamReader(c.GetStream());
  string data = sr.ReadLine();
  Process.Start("cmd /c " + data);
} }`);
    expect(flows.length).toBeGreaterThan(0);
  });

  it('does not report path_traversal for the StreamReader(Stream) overload', async () => {
    // `new StreamReader(tcp.GetStream())` takes no path. This FP was latent
    // while C# had no socket sources and became live with this change, so the
    // `safe_if_stream_arg_at` discriminator lands with it.
    const { sinks } = await run(`using System.IO; using System.Net.Sockets;
public class P { public void Bad(TcpClient tcp) {
  StreamReader sr = new StreamReader(tcp.GetStream());
  string data = sr.ReadLine();
  System.Console.WriteLine(data.Length);
} }`);
    expect(sinks.some(s => s.type === 'path_traversal')).toBe(false);
  });

  it('keeps path_traversal for the StreamReader(string path) overload', async () => {
    const { sinks } = await run(`using System.IO;
public class P { public void Bad(string p) {
  StreamReader sr = new StreamReader(p);
  System.Console.WriteLine(sr.ReadLine());
} }`);
    expect(sinks.some(s => s.type === 'path_traversal')).toBe(true);
  });

  it('binds the inner assignment, not the reader, on a one-line using block', async () => {
    // `assignRe` is anchored and greedy: it captured `sr` with the whole rest
    // of the line as its RHS, so the line was bound to the reader rather than
    // to `data`.
    const { sources } = await run(`using System.IO; using System.Net.Sockets; using System.Diagnostics;
public class P { public void Bad() {
  string data;
  using (TcpClient tcp = new TcpClient("h", 1)) {
    using (StreamReader sr = new StreamReader(tcp.GetStream())) { data = sr.ReadLine(); }
  }
  Process.Start("cmd /c " + data);
} }`);
    expect(sources.some(s => s.type === 'io_input' && s.variable === 'data')).toBe(true);
    expect(sources.some(s => s.type === 'io_input' && s.variable === 'sr')).toBe(false);
  });

  it('does not seed a read on an unrelated receiver of the same method name', async () => {
    const { sources } = await run(`public class P { public void Fine(MyThing t) {
  string data = t.GetString(0);
  System.Console.WriteLine(data);
} }`);
    expect(sources.some(s => s.type === 'db_input')).toBe(false);
  });
});
