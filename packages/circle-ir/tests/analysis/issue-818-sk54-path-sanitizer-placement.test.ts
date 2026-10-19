/**
 * cognium-dev #818 / #562 (sk54 axis): path hardening must not suppress path_traversal
 * when the sanitizer is present but does not protect the value that reaches the sink
 * (wrong operand, wrong variable, statement-only call, or after the sink).
 *
 * SAST regression fixtures — handlers are deliberately vulnerable.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const unsanitizedPathTraversal = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint?.flows ?? []).filter(f => f.sink_type === 'path_traversal' && !f.sanitized);

describe('#818 sk54 path sanitizer placement (js)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TP: basename on a constant while the sink uses the raw query param', async () => {
    const code = `const fs = require('fs');
const path = require('path');
const express = require('express');
const app = express();
app.get('/files', (req, res) => {
  const userPath = req.query.f;
  const hardened = path.basename('uploads');
  fs.readFileSync('./data/' + userPath);
  res.end(hardened);
});
`;
    const r = await analyze(code, 'sk54_wrong_operand.js', 'javascript');
    expect(unsanitizedPathTraversal(r).length).toBeGreaterThan(0);
  });

  it('TP: basename on a sibling param while the sink uses the tainted one', async () => {
    const code = `const fs = require('fs');
const path = require('path');
const express = require('express');
const app = express();
app.get('/files', (req, res) => {
  const userPath = req.query.f;
  const other = req.query.g;
  path.basename(other);
  fs.readFileSync('./data/' + userPath);
  res.end('ok');
});
`;
    const r = await analyze(code, 'sk54_wrong_param.js', 'javascript');
    expect(unsanitizedPathTraversal(r).length).toBeGreaterThan(0);
  });

  it('TP: statement-only basename before the sink on the same param', async () => {
    const code = `const fs = require('fs');
const path = require('path');
const express = require('express');
const app = express();
app.get('/files', (req, res) => {
  const userPath = req.query.f;
  path.basename(userPath);
  fs.readFileSync('./data/' + userPath);
  res.end('ok');
});
`;
    const r = await analyze(code, 'sk54_presence_only.js', 'javascript');
    expect(unsanitizedPathTraversal(r).length).toBeGreaterThan(0);
  });

  it('TP: basename after the sink line must not retroactively sanitize', async () => {
    const code = `const fs = require('fs');
const path = require('path');
const express = require('express');
const app = express();
app.get('/files', (req, res) => {
  const userPath = req.query.f;
  fs.readFileSync('./data/' + userPath);
  const hardened = path.basename(userPath);
  res.end(hardened);
});
`;
    const r = await analyze(code, 'sk54_after_sink.js', 'javascript');
    expect(unsanitizedPathTraversal(r).length).toBeGreaterThan(0);
  });

  it('control: basename on the value that reaches the sink clears the flow', async () => {
    const code = `const fs = require('fs');
const path = require('path');
const express = require('express');
const app = express();
app.get('/files', (req, res) => {
  const userPath = req.query.f;
  const safe = path.basename(userPath);
  fs.readFileSync('./data/' + safe);
  res.end('ok');
});
`;
    const r = await analyze(code, 'sk54_effective.js', 'javascript');
    expect(unsanitizedPathTraversal(r)).toEqual([]);
  });
});

describe('#818 sk54 path sanitizer placement (java)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TP: getFileName on a constant while Files.readAllBytes uses the request param', async () => {
    const code = `import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Sk54JavaWrongOperand extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String userPath = request.getParameter("f");
    String hardened = Paths.get("/static/base").getFileName().toString();
    Files.readAllBytes(Paths.get("/uploads/" + userPath));
    response.getWriter().write(hardened);
  }
}
`;
    const r = await analyze(code, 'Sk54JavaWrongOperand.java', 'java');
    expect(unsanitizedPathTraversal(r).length).toBeGreaterThan(0);
  });

  it('TP: getFileName on a sibling param while the sink uses the tainted param', async () => {
    const code = `import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Sk54JavaWrongParam extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String userPath = request.getParameter("f");
    String other = request.getParameter("g");
    Paths.get(other).getFileName();
    Files.readAllBytes(Paths.get("/uploads/" + userPath));
    response.getWriter().write("ok");
  }
}
`;
    const r = await analyze(code, 'Sk54JavaWrongParam.java', 'java');
    expect(unsanitizedPathTraversal(r).length).toBeGreaterThan(0);
  });

  it('control: getFileName on the path reaching the sink clears the flow', async () => {
    const code = `import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Sk54JavaEffective extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String userPath = request.getParameter("f");
    String safe = Paths.get(userPath).getFileName().toString();
    Files.readAllBytes(Paths.get("/uploads/" + safe));
    response.getWriter().write("ok");
  }
}
`;
    const r = await analyze(code, 'Sk54JavaEffective.java', 'java');
    expect(unsanitizedPathTraversal(r)).toEqual([]);
  });
});
