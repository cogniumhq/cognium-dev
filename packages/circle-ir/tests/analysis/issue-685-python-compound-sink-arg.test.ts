/**
 * cognium-dev #685 (second slice) — Python Lambda entry points with compound
 * sink arguments: parameter-sourced flows when the sink arg is an expression
 * (e.g. string concat) rather than a bare parameter variable.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

beforeAll(async () => { await initAnalyzer(); });

function cmdFlows(code: string, file: string) {
  return analyze(code, file, 'python').then(ir =>
    (ir.taint.flows ?? []).filter(f => f.sink_type === 'command_injection'),
  );
}

describe('#685 Python compound sink arg under lambda_handler', () => {
  it('export_fn.py: event inside a concatenated os.system argument flows', async () => {
    const code = `import os

def lambda_handler(event, context):
    os.system("tar czf " + event["path"])
`;
    const flows = await cmdFlows(code, 'export_fn.py');
    expect(flows).toHaveLength(1);
    expect(flows[0].sink_line).toBe(4);
  });

  it('constant_cmd.py: constant command stays clean', async () => {
    const code = `import os

def lambda_handler(event, context):
    os.system("tar czf " + "/tmp/a.tar")
    print(event)
`;
    expect(await cmdFlows(code, 'constant_cmd.py')).toHaveLength(0);
  });

  it('not_entry.py: non-entry function stays gated', async () => {
    const code = `import os

def run_it(event, context):
    os.system("tar czf " + event["path"])
`;
    expect(await cmdFlows(code, 'not_entry.py')).toHaveLength(0);
  });

  it('one_arg.py: single-parameter handler stays gated', async () => {
    const code = `import os

def lambda_handler(event):
    os.system("tar czf " + event["path"])
`;
    expect(await cmdFlows(code, 'one_arg.py')).toHaveLength(0);
  });

  it('class_method.py: class method lambda_handler stays gated', async () => {
    const code = `import os

class Svc:
    def lambda_handler(self, event, context):
        os.system("tar czf " + event["path"])
`;
    expect(await cmdFlows(code, 'class_method.py')).toHaveLength(0);
  });
});
