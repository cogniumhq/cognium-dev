/**
 * cognium-dev#637 — C# cross-file taint paths skipped the callee-reach check
 * that the per-file inter-procedural phase applies. A request value passed
 * into a method in another file that only binds it as a query parameter was
 * reported as sql_injection at that method's sink.
 *
 * Both cross-file phases (direct call-argument flows and multi-hop paths) now
 * require the tainted argument to reach the callee's sink, judged with the
 * same C# reach check and credit as the per-file phase.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const handler = `using System.Web;
public class Orders
{
    public void Lookup(HttpRequest req)
    {
        string sku = req.QueryString["sku"];
        Store.FindRaw(sku);
    }
    public void LookupBound(HttpRequest req)
    {
        string sku = req.QueryString["sku"];
        Store.FindBound(sku);
    }
    public void LookupTenant(HttpRequest req)
    {
        string sku = req.QueryString["sku"];
        Store.ByTenant(sku, "widgets");
    }
    public void LookupName(HttpRequest req)
    {
        string sku = req.QueryString["sku"];
        Store.ByTenant("acme", sku);
    }
    public void Count(HttpRequest req)
    {
        string sku = req.QueryString["sku"];
        Store.CountOnly(sku);
    }
}
`;

const store = `using System.Data.SqlClient;
public class Store
{
    public static void FindRaw(string sku)
    {
        var conn = new SqlConnection("cs");
        var cmd = new SqlCommand("select * from items where sku='" + sku + "'", conn);
        cmd.ExecuteReader();
    }
    public static void FindBound(string sku)
    {
        var conn = new SqlConnection("cs");
        var cmd = new SqlCommand("select * from items where sku=@sku", conn);
        cmd.Parameters.AddWithValue("@sku", sku);
        cmd.ExecuteReader();
    }
    public static void ByTenant(string tenant, string name)
    {
        var conn = new SqlConnection("cs");
        var cmd = new SqlCommand("select * from items where tenant=@t and name='" + name + "'", conn);
        cmd.Parameters.AddWithValue("@t", tenant);
        cmd.ExecuteReader();
    }
    public static void CountOnly(string sku)
    {
        var conn = new SqlConnection("cs");
        var cmd = new SqlCommand("select count(*) from items", conn);
        System.Console.WriteLine(sku.Length);
        cmd.ExecuteScalar();
    }
}
`;

describe('#637 C# cross-file paths apply the callee-reach check', () => {
  let sqlPaths: string[] = [];

  beforeAll(async () => {
    await initAnalyzer();
    const r = await analyzeProject([
      { code: handler, filePath: 'Orders.cs', language: 'csharp' },
      { code: store, filePath: 'Store.cs', language: 'csharp' },
    ]);
    sqlPaths = r.taint_paths
      .filter(p => p.sink.type === 'sql_injection')
      .map(p => `${p.source.file}:${p.source.line}->${p.sink.file}:${p.sink.line}`);
  });

  it('a concatenated query in another file is still reported', () => {
    expect(sqlPaths).toContain('Orders.cs:6->Store.cs:8');
  });

  it('a value bound as a query parameter in another file is clean', () => {
    expect(sqlPaths.filter(p => p.startsWith('Orders.cs:11->'))).toEqual([]);
  });

  it('the bound argument of a two-parameter callee is clean', () => {
    expect(sqlPaths.filter(p => p.startsWith('Orders.cs:16->'))).toEqual([]);
  });

  it('the concatenated argument of the same callee is reported', () => {
    expect(sqlPaths).toContain('Orders.cs:21->Store.cs:22');
  });

  it('a value the callee never puts in the query is clean', () => {
    expect(sqlPaths.filter(p => p.startsWith('Orders.cs:26->'))).toEqual([]);
  });
});
