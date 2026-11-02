/**
 * cognium-dev#1072 — Python list-form `subprocess` with a shell, a program that
 * runs its argv as a command, or an interpreter given `-c` / `-e` as argv[0]
 * keeps the command_injection sink. The list form without `shell=True` was
 * treated as safe whatever the program, so `subprocess.run(['sh', '-c', cmd])`
 * was silent.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const app = (call: string) => `import subprocess
from flask import Flask, request
app = Flask(__name__)

@app.route('/run')
def run():
    cmd = request.args.get('c')
    ${call}
    return 'ok'
`;
const cmdSinks = async (call: string) =>
  (await analyze(app(call), 'a.py', 'python')).taint.sinks.filter(s => s.type === 'command_injection');
const cmdFlows = async (call: string) =>
  (await analyze(app(call), 'a.py', 'python')).taint.flows.filter(f => f.sink_type === 'command_injection');

describe('#1072 Python list-form subprocess: argv[0] decides', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const kept: Array<[string, string]> = [
    ['sh -c', "subprocess.run(['sh', '-c', cmd])"],
    ['/bin/bash -c', 'subprocess.check_output(["/bin/bash", "-c", cmd])'],
    ['ssh', "subprocess.run(['ssh', 'deploy@host', cmd])"],
    ['sudo', "subprocess.Popen(['sudo', cmd])"],
    ['docker exec', "subprocess.call(['docker', 'exec', 'web', cmd])"],
    ['python -c', "subprocess.run(['python3', '-c', cmd])"],
    ['perl -e', "subprocess.run(['perl', '-e', cmd])"],
  ];
  for (const [name, call] of kept) {
    it(`${name}: still a command_injection sink`, async () => {
      expect((await cmdSinks(call)).length).toBeGreaterThan(0);
    });
  }

  it('a request value into sh -c is a flow', async () => {
    expect((await cmdFlows("subprocess.run(['sh', '-c', cmd])")).length).toBeGreaterThan(0);
  });

  it('stays filtered: a non-shell program, an interpreter running a script, a non-literal argv[0]', async () => {
    expect(await cmdSinks("subprocess.run(['git', 'log', cmd])")).toHaveLength(0);
    expect(await cmdSinks("subprocess.run(['python3', 'tool.py', cmd])")).toHaveLength(0);
    expect(await cmdSinks("subprocess.run([GIT, 'log', cmd])")).toHaveLength(0);
    // a look-alike name is not a shell
    expect(await cmdSinks("subprocess.run(['shellcheck', cmd])")).toHaveLength(0);
  });

  it('shell=True stays a sink (unchanged)', async () => {
    expect((await cmdSinks("subprocess.run(['ls', cmd], shell=True)")).length).toBeGreaterThan(0);
  });
});
