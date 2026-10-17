/**
 * cognium-dev#808 — a C# field written through a sanitizer in one method and
 * read at a sink in another carries no taint for the sanitizer's sink types.
 * The field is credited only when every write to it is credited, so a raw
 * write in another method, or a sanitizer for a different sink type, still
 * reports.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const sqlClean = `
using System.Data.SqlClient;
using System.Text.RegularExpressions;
public class TicketLookup {
  static SqlConnection db;
  string _ticket;
  public void Remember(string raw) { _ticket = Regex.Replace(raw, "[^0-9]", ""); }
  public void Fetch() {
    var q = new SqlCommand("SELECT title FROM tickets WHERE no=" + _ticket, db);
  }
}
`;

const sqlRaw = `
using System.Data.SqlClient;
public class TicketLookup {
  static SqlConnection db;
  string _ticket;
  public void Remember(string raw) { _ticket = raw; }
  public void Fetch() {
    var q = new SqlCommand("SELECT title FROM tickets WHERE no=" + _ticket, db);
  }
}
`;

const sqlWrongSanitizer = `
using System.Data.SqlClient;
using System.Net;
public class TicketLookup {
  static SqlConnection db;
  string _ticket;
  public void Remember(string raw) { _ticket = WebUtility.HtmlEncode(raw); }
  public void Fetch() {
    var q = new SqlCommand("SELECT title FROM tickets WHERE no=" + _ticket, db);
  }
}
`;

const sqlRawElsewhere = `
using System.Data.SqlClient;
using System.Text.RegularExpressions;
public class TicketLookup {
  static SqlConnection db;
  string _ticket;
  public void Remember(string raw) { _ticket = Regex.Replace(raw, "[^0-9]", ""); }
  public void Replace(string other) { _ticket = other; }
  public void Fetch() {
    var q = new SqlCommand("SELECT title FROM tickets WHERE no=" + _ticket, db);
  }
}
`;

const sqlRawElsewhereMultiline = `
using System.Data.SqlClient;
using System.Text.RegularExpressions;
public class TicketLookup {
  static SqlConnection db;
  string _ticket;
  public void Remember(string raw) {
    _ticket = Regex.Replace(raw, "[^0-9]", "");
  }
  public void Replace(string other) {
    _ticket = other;
  }
  public void Fetch() {
    var q = new SqlCommand("SELECT title FROM tickets WHERE no=" + _ticket, db);
  }
}
`;

const sqlCleanWithDefault = `
using System.Data.SqlClient;
using System.Text.RegularExpressions;
public class TicketLookup {
  static SqlConnection db;
  string _ticket;
  public TicketLookup() { _ticket = ""; }
  public void Remember(string raw) {
    var digits = Regex.Replace(raw, "[^0-9]", "");
    _ticket = digits;
  }
  public void Fetch() {
    var q = new SqlCommand("SELECT title FROM tickets WHERE no=" + _ticket, db);
  }
}
`;

const xssClean = `
using System.Net;
public class Greeting {
  string _who;
  public void Remember(string raw) { _who = WebUtility.HtmlEncode(raw); }
  public object Render() {
    return Html.Raw("<p>Hello " + _who + "</p>");
  }
}
`;

const pathClean = `
using System.IO;
public class Attachment {
  string _file;
  public void Remember(string raw) { _file = Path.GetFileName(raw); }
  public string Open() {
    return File.ReadAllText("/uploads/" + _file);
  }
}
`;

const cmdClean = `
using System.Diagnostics;
using System.Text.RegularExpressions;
public class Runner {
  string _task;
  public void Remember(string raw) { _task = Regex.Replace(raw, "[^a-z0-9]", ""); }
  public void Go() {
    Process.Start("bash -c " + _task);
  }
}
`;

async function flowsOf(code: string, sinkType: string) {
  const ir = await analyze(code, 'Fixture.cs', 'csharp');
  return (ir.taint.flows ?? []).filter(f => f.sink_type === sinkType && !f.sanitized);
}

describe('issue #808 C# field written through a sanitizer', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('allowlist strip into a field clears sql_injection in the reader', async () => {
    expect(await flowsOf(sqlClean, 'sql_injection')).toHaveLength(0);
  });

  it('HtmlEncode into a field clears xss in the reader', async () => {
    expect(await flowsOf(xssClean, 'xss')).toHaveLength(0);
  });

  it('Path.GetFileName into a field clears path_traversal in the reader', async () => {
    expect(await flowsOf(pathClean, 'path_traversal')).toHaveLength(0);
  });

  it('allowlist strip into a field clears command_injection in the reader', async () => {
    expect(await flowsOf(cmdClean, 'command_injection')).toHaveLength(0);
  });

  it('a literal default plus a sanitized local stays clean', async () => {
    expect(await flowsOf(sqlCleanWithDefault, 'sql_injection')).toHaveLength(0);
  });

  it('the raw twin still reports', async () => {
    expect((await flowsOf(sqlRaw, 'sql_injection')).length).toBeGreaterThanOrEqual(1);
  });

  it('a sanitizer for another sink type does not clear sql_injection', async () => {
    expect((await flowsOf(sqlWrongSanitizer, 'sql_injection')).length).toBeGreaterThanOrEqual(1);
  });

  it('a raw write in another method keeps the field tainted', async () => {
    expect((await flowsOf(sqlRawElsewhere, 'sql_injection')).length).toBeGreaterThanOrEqual(1);
    expect((await flowsOf(sqlRawElsewhereMultiline, 'sql_injection')).length).toBeGreaterThanOrEqual(1);
  });
});
