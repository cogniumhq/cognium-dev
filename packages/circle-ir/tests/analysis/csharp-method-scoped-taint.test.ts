/**
 * C#: taint and sanitizer credit are scoped to the method that declares the
 * variable (#548, #579).
 *
 * Before, both were matched by bare name across the whole file. A local `cmd`
 * tainted in `Bad()` tainted `cmd` in `GoodG2B()` (#548: all 27 Juliet CWE-89
 * false positives), and `s` encoded in one action silenced an unencoded `s` in
 * another (#579). Taint still crosses methods where data really does: through a
 * class field or a return value.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type Flow = { source_line: number; sink_line: number; sink_type: string };
const flowsOf = async (code: string, type: string): Promise<Flow[]> => {
  const ir = await analyze(code, 'T.cs', 'csharp');
  return (ir.taint.flows ?? []).filter(f => f.sink_type === type);
};
/** 1-based line of the first line containing `needle`. */
const lineOf = (code: string, needle: string): number =>
  code.split('\n').findIndex(l => l.includes(needle)) + 1;

describe('C# taint does not cross methods by variable name (#548)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const pair = (goodData: string) => `
using System.Data.SqlClient;
using System.Web;
public class Repo {
    public void Bad(HttpRequest req, SqlConnection dbConnection) {
        string data = req.QueryString["name"];
        using (SqlCommand badSqlCommand = new SqlCommand(null, dbConnection)) {
            badSqlCommand.CommandText = "select * from users where name='" + data + "'";
            badSqlCommand.ExecuteScalar(); // BAD-SINK
        }
    }
    private void Other(HttpRequest req, SqlConnection dbConnection) {
        string data = ${goodData};
        using (SqlCommand badSqlCommand = new SqlCommand(null, dbConnection)) {
            badSqlCommand.CommandText = "select * from users where name='" + data + "'";
            badSqlCommand.ExecuteScalar(); // OTHER-SINK
        }
    }
}
`;

  it('a command object tainted in one method does not taint its namesake in another', async () => {
    const code = pair('"foo"');
    const flows = await flowsOf(code, 'sql_injection');
    expect(flows.some(f => f.sink_line === lineOf(code, 'BAD-SINK'))).toBe(true);
    expect(flows.some(f => f.sink_line === lineOf(code, 'OTHER-SINK'))).toBe(false);
  });

  it('a second method that reuses the names with its own source is reported too', async () => {
    const code = pair('req.QueryString["other"]');
    const flows = await flowsOf(code, 'sql_injection');
    expect(flows.some(f => f.sink_line === lineOf(code, 'BAD-SINK'))).toBe(true);
    expect(flows.some(f => f.sink_line === lineOf(code, 'OTHER-SINK'))).toBe(true);
  });

  const viaField = (goodValue: string) => `
using System.Data.SqlClient;
using System.Web;
public class Carried {
    private string dataBad;
    private string dataGood;
    private void BadSink(SqlConnection c) {
        string data = dataBad;
        using (SqlCommand cmd = new SqlCommand(null, c)) {
            cmd.CommandText = "select * from t where n='" + data + "'";
            cmd.ExecuteScalar(); // BAD-SINK
        }
    }
    public void Bad(HttpRequest req, SqlConnection c) {
        string data = req.QueryString["name"];
        dataBad = data;
        BadSink(c);
    }
    private void GoodSink(SqlConnection c) {
        string data = dataGood;
        using (SqlCommand cmd = new SqlCommand(null, c)) {
            cmd.CommandText = "select * from t where n='" + data + "'";
            cmd.ExecuteScalar(); // GOOD-SINK
        }
    }
    public void Good(HttpRequest req, SqlConnection c) {
        string data = ${goodValue};
        dataGood = data;
        GoodSink(c);
    }
}
`;

  it('taint carried through a class field reaches the sink in another method', async () => {
    const code = viaField('"foo"');
    const flows = await flowsOf(code, 'sql_injection');
    expect(flows.some(f => f.sink_line === lineOf(code, 'BAD-SINK'))).toBe(true);
    expect(flows.some(f => f.sink_line === lineOf(code, 'GOOD-SINK'))).toBe(false);
  });

  const viaReturn = `
using System.Data.SqlClient;
using System.Web;
public class Returned {
    private static string BadSource(HttpRequest req) {
        string data = req.QueryString["name"];
        return data;
    }
    public void Bad(HttpRequest req, SqlConnection c) {
        string data = BadSource(req);
        using (SqlCommand cmd = new SqlCommand(null, c)) {
            cmd.CommandText = "select * from t where n='" + data + "'";
            cmd.ExecuteScalar(); // BAD-SINK
        }
    }
    private static string GoodSource(HttpRequest req) {
        string data = "foo";
        return data;
    }
    public void Good(HttpRequest req, SqlConnection c) {
        string data = GoodSource(req);
        using (SqlCommand cmd = new SqlCommand(null, c)) {
            cmd.CommandText = "select * from t where n='" + data + "'";
            cmd.ExecuteScalar(); // GOOD-SINK
        }
    }
}
`;

  it('taint returned from a helper reaches the caller, and a constant helper does not', async () => {
    const flows = await flowsOf(viaReturn, 'sql_injection');
    expect(flows.some(f => f.sink_line === lineOf(viaReturn, 'BAD-SINK'))).toBe(true);
    expect(flows.some(f => f.sink_line === lineOf(viaReturn, 'GOOD-SINK'))).toBe(false);
  });
});

describe('C# sanitizer credit is per method and follows the last assignment (#579)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('encoding `s` in one action does not silence an unencoded `s` in another', async () => {
    const code = `
using System.Net; using Microsoft.AspNetCore.Mvc;
public class PageController : Controller {
  public async System.Threading.Tasks.Task A() {
    var q = Request.Query["q"];
    var s = WebUtility.HtmlEncode(q);
    await Response.WriteAsync("<div>" + s + "</div>"); // SAFE
  }
  public async System.Threading.Tasks.Task B() {
    var s = Request.Query["name"];
    await Response.WriteAsync("<div>" + s + "</div>"); // VULN
  }
}
`;
    const flows = await flowsOf(code, 'xss');
    expect(flows.some(f => f.sink_line === lineOf(code, '// VULN'))).toBe(true);
    expect(flows.some(f => f.sink_line === lineOf(code, '// SAFE'))).toBe(false);
  });

  it('a sanitized name in one action does not hide a path sink in another', async () => {
    const code = `
using System.IO; using Microsoft.AspNetCore.Mvc;
public class FileController : Controller {
  public IActionResult A() {
    var name = Path.GetFileName(Request.Query["f"]);
    return Ok(System.IO.File.ReadAllText("/data/" + name));
  }
  public IActionResult B() {
    var name = Request.Query["g"].ToString();
    return Ok(System.IO.File.ReadAllText(name)); // VULN
  }
}
`;
    const flows = await flowsOf(code, 'path_traversal');
    expect(flows.some(f => f.sink_line === lineOf(code, '// VULN'))).toBe(true);
  });

  it('reassigning an encoded variable to the raw input takes the credit back', async () => {
    const code = `
using System.Net; using Microsoft.AspNetCore.Mvc;
public class PageController : Controller {
  public async System.Threading.Tasks.Task A() {
    var q = Request.Query["q"];
    var s = WebUtility.HtmlEncode(q);
    s = q;
    await Response.WriteAsync("<div>" + s + "</div>"); // VULN
  }
}
`;
    const flows = await flowsOf(code, 'xss');
    expect(flows.some(f => f.sink_line === lineOf(code, '// VULN'))).toBe(true);
  });

  it('an encoded value derived in the same method stays clean', async () => {
    const code = `
using System.Net; using Microsoft.AspNetCore.Mvc;
public class PageController : Controller {
  public async System.Threading.Tasks.Task A() {
    var q = Request.Query["q"];
    var s = WebUtility.HtmlEncode(q);
    var html = "<div>" + s + "</div>";
    await Response.WriteAsync(html);
  }
}
`;
    expect(await flowsOf(code, 'xss')).toHaveLength(0);
  });

  it('a plain reassignment from tainted input carries taint, like a declaration', async () => {
    const code = `
using Microsoft.AspNetCore.Mvc;
public class PageController : Controller {
  public async System.Threading.Tasks.Task A() {
    var q = Request.Query["q"];
    string s;
    s = q;
    await Response.WriteAsync("<div>" + s + "</div>"); // VULN
  }
}
`;
    const flows = await flowsOf(code, 'xss');
    expect(flows.some(f => f.sink_line === lineOf(code, '// VULN'))).toBe(true);
  });
});
