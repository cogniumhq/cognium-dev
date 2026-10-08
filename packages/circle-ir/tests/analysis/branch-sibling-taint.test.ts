/**
 * A literal assigned in one branch does not overwrite the taint a sibling
 * branch assigned (#513, #582).
 *
 * `switch (6) { case 6: data = input; break; default: data = "foo"; break; }`
 * and `if (c) { data = input; } else { data = "foo"; }` both leave `data`
 * tainted on one path. Two things lost that flow: C# `switch` was unknown to
 * constant propagation, which visited every arm in order and kept the last
 * assignment; and the literal-reassignment guard treated a literal in any
 * branch as an overwrite. Juliet C# `_15` recall was 22.8% for it.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import type { SupportedLanguage } from '../../src/types/index.js';

const flows = async (code: string, file: string, language: SupportedLanguage, type: string) => {
  const ir = await analyze(code, file, language);
  return (ir.taint.flows ?? []).filter(f => f.sink_type === type);
};

const csharp = (body: string) => `
using System; using System.Xml;
public class T
{
    public void Run(XmlDocument doc)
    {
        string data;
${body}
        doc.SelectNodes("/users/user[name='" + data + "']");
    }
}
`;

describe('C# switch with a constant default arm (#513)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const sw = (value: number) => csharp(`
        switch (${value})
        {
        case 6:
            data = Console.ReadLine();
            break;
        default:
            data = "foo";
            break;
        }`);

  it('switch (6) selects the tainted case: xpath injection', async () => {
    expect((await flows(sw(6), 'T.cs', 'csharp', 'xpath_injection')).length).toBeGreaterThanOrEqual(1);
  });

  it('switch (7) selects the constant default: clean', async () => {
    expect(await flows(sw(7), 'T.cs', 'csharp', 'xpath_injection')).toHaveLength(0);
  });

  it('a query built over several lines after the switch still reaches the sink', async () => {
    const code = `
using System; using System.Xml.XPath;
public class T
{
    public void Run(XPathNavigator xPath)
    {
        string data;
        switch (6)
        {
        case 6:
            data = Console.ReadLine();
            break;
        default:
            data = null;
            break;
        }
        string[] tokens = data.Split("||".ToCharArray());
        string username = tokens[0];
        string query = "//users/user[name/text()='" + username +
                       "']" +
                       "/secret/text()";
        string secret = (string)xPath.Evaluate(query);
    }
}
`;
    expect((await flows(code, 'T.cs', 'csharp', 'xpath_injection')).length).toBeGreaterThanOrEqual(1);
    // Windows line endings must not break the multi-line join.
    const crlf = code.replace(/\n/g, '\r\n');
    expect((await flows(crlf, 'T.cs', 'csharp', 'xpath_injection')).length).toBeGreaterThanOrEqual(1);
  });
});

describe('if/else with a literal in the sibling branch (#582)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('C#, braces on their own lines: tainted in the if, literal in the else', async () => {
    const code = csharp(`
        if (DateTime.Now.Ticks > 0)
        {
            data = Console.ReadLine();
        }
        else
        {
            data = "foo";
        }`);
    expect((await flows(code, 'T.cs', 'csharp', 'xpath_injection')).length).toBeGreaterThanOrEqual(1);
  });

  it('C#: a literal in every branch is still an overwrite', async () => {
    const code = `
using System; using System.Xml;
public class T
{
    public void Run(XmlDocument doc)
    {
        string data = Console.ReadLine();
        if (DateTime.Now.Ticks > 0)
        {
            data = "bar";
        }
        else
        {
            data = "foo";
        }
        doc.SelectNodes("/users/user[name='" + data + "']");
    }
}
`;
    expect(await flows(code, 'T.cs', 'csharp', 'xpath_injection')).toHaveLength(0);
  });

  const java = (thenValue: string, cond = 'req.getHeader("x") != null') => `
import javax.servlet.http.*;
public class J extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        boolean cond = ${cond};
        String data = null;
        if (cond) {
            data = ${thenValue};
        } else {
            data = "foo";
        }
        Runtime.getRuntime().exec("cmd /c dir " + data);
    }
}
`;

  it('Java, multi-line: tainted in the if, literal in the else', async () => {
    const found = await flows(java('req.getParameter("q")'), 'J.java', 'java', 'command_injection');
    expect(found.length).toBeGreaterThanOrEqual(1);
  });

  it('Java: a literal in both branches is clean', async () => {
    expect(await flows(java('"bar"'), 'J.java', 'java', 'command_injection')).toHaveLength(0);
  });

  it('Java: a tainted assignment in a branch that never runs does not count', async () => {
    const code = `
import javax.servlet.http.*;
public class J extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String data = null;
        if (false) {
            data = req.getParameter("q");
        } else {
            data = "foo";
        }
        Runtime.getRuntime().exec("cmd /c dir " + data);
    }
}
`;
    expect(await flows(code, 'J.java', 'java', 'command_injection')).toHaveLength(0);
  });

  it('Go: tainted in the if, literal in the else', async () => {
    const code = `package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	data := ""
	if r.Header.Get("x") != "" {
		data = r.URL.Query().Get("q")
	} else {
		data = "foo"
	}
	exec.Command("sh", "-c", "ls "+data).Run()
}
`;
    expect((await flows(code, 'h.go', 'go', 'command_injection')).length).toBeGreaterThanOrEqual(1);
  });
});
