/**
 * Python `if` / `elif` / `else`: a literal assigned in one arm does not
 * overwrite the taint a sibling arm assigned (#582, Python slice).
 *
 * The literal-reassignment guard found sibling branches by brace matching, so
 * for indentation-delimited Python a literal in `else:` counted as a plain
 * overwrite and the tainted `if` arm was dropped.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flows = async (code: string, type: string) => {
  const ir = await analyze(code, 'dispatch_view.py', 'python');
  return (ir.taint.flows ?? []).filter(f => f.sink_type === type);
};

type Family = { type: string; imports: string; sink: (v: string) => string; sanitize: (e: string) => string };

const families: Family[] = [
  {
    type: 'command_injection',
    imports: 'import os\nimport shlex',
    sink: v => `os.system("run-tool " + ${v})`,
    sanitize: e => `shlex.quote(${e})`,
  },
  {
    type: 'sql_injection',
    imports: 'import sqlite3',
    sink: v => `sqlite3.connect("app.db").cursor().execute("SELECT * FROM jobs WHERE name = '" + ${v} + "'")`,
    sanitize: e => `int(${e})`,
  },
  {
    type: 'path_traversal',
    imports: 'import os',
    sink: v => `open("/srv/jobs/" + ${v})`,
    sanitize: e => `os.path.basename(${e})`,
  },
];

const view = (f: Family, body: string) => `${f.imports}
from flask import Flask, request

app = Flask(__name__)

@app.route("/job")
def start_job():
    mode = request.args.get("mode")
${body}
    ${f.sink('target')}
`;

const TAINT = 'request.args.get("target")';

describe.each(families)('Python sibling-branch literal guard — $type (#582)', f => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('if/else: tainted first arm, literal else — flows', async () => {
    const code = view(f, `    if mode == "custom":
        target = ${TAINT}
    else:
        target = "default-target"`);
    expect((await flows(code, f.type)).length).toBeGreaterThanOrEqual(1);
  });

  it('if/elif/else: tainted first arm, literal elif and else — flows', async () => {
    const code = view(f, `    if mode == "custom":
        target = ${TAINT}
    elif mode == "other":
        target = "other-target"
    else:
        target = "default-target"`);
    expect((await flows(code, f.type)).length).toBeGreaterThanOrEqual(1);
  });

  it('control: tainted arm last — flows', async () => {
    const code = view(f, `    if mode == "custom":
        target = "default-target"
    else:
        target = ${TAINT}`);
    expect((await flows(code, f.type)).length).toBeGreaterThanOrEqual(1);
  });

  it('a literal in every arm — clean', async () => {
    const code = view(f, `    if mode == "custom":
        target = "custom-target"
    else:
        target = "default-target"`);
    expect(await flows(code, f.type)).toHaveLength(0);
    const chain = view(f, `    if mode == "custom":
        target = "custom-target"
    elif mode == "other":
        target = "other-target"
    else:
        target = "default-target"`);
    expect(await flows(chain, f.type)).toHaveLength(0);
  });

  it('straight-line overwrite — clean (last definition wins)', async () => {
    const code = view(f, `    target = ${TAINT}
    target = "fixed-value"`);
    expect(await flows(code, f.type)).toHaveLength(0);
  });

  it("own-arm overwrite: the literal's own arm is not a sibling — clean", async () => {
    const code = view(f, `    target = "start"
    if mode == "custom":
        if mode != "x":
            target = ${TAINT}
        target = "fixed-value"
    else:
        target = "default-target"`);
    expect(await flows(code, f.type)).toHaveLength(0);
  });

  it('sanitized tainted arm — clean', async () => {
    const code = view(f, `    if mode == "custom":
        target = ${f.sanitize(TAINT)}
    else:
        target = "default-target"`);
    expect(await flows(code, f.type)).toHaveLength(0);
  });
});
