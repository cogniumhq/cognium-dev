/**
 * cognium-dev#1066 — #1059's fixed-program rule (Stage 15f2) must not treat a
 * program that runs its own argv as a command as safe: `spawn('ssh', [host,
 * userCmd])` runs `userCmd` on the host. Each of these stays a finding; an
 * ordinary fixed program (`git`, `/usr/bin/convert`) stays filtered.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const cmd = async (code: string) =>
  (await analyze(code, 'r.ts', 'typescript')).taint.sinks.filter(s => s.type === 'command_injection');

const wrap = (call: string) => `import { spawn, spawnSync, execFile, execFileSync } from 'child_process';\nexport function run(host: string, userCmd: string) {\n  ${call}\n}`;

describe('#1066 programs that execute their arguments keep the spawn sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const kept: Array<[string, string]> = [
    ['ssh', `spawn('ssh', [host, userCmd]);`],
    ['sudo', `spawnSync('sudo', [userCmd]);`],
    ['doas', `spawnSync('doas', [userCmd]);`],
    ['docker exec', `execFile('docker', ['exec', host, userCmd]);`],
    ['docker run (path)', `execFileSync('/usr/bin/docker', ['run', '--rm', 'alpine', userCmd]);`],
    ['kubectl exec', `spawn('kubectl', ['exec', host, '--', userCmd]);`],
    ['xargs', `spawn('xargs', [userCmd]);`],
    ['nohup', `spawn('nohup', [userCmd]);`],
    ['timeout', `spawnSync('timeout', ['5', userCmd]);`],
    ['nice', `spawn('nice', ['-n', '10', userCmd]);`],
    ['env (already a shell-like program)', `spawn('env', [userCmd]);`],
  ];
  for (const [name, call] of kept) {
    it(`${name}: still command injection`, async () => {
      expect((await cmd(wrap(call))).length).toBeGreaterThan(0);
    });
  }

  it('an ordinary fixed program with an argv array stays filtered (#1059 unchanged)', async () => {
    expect(await cmd(wrap(`spawnSync('git', ['log', '--', userCmd]);`))).toHaveLength(0);
    expect(await cmd(wrap(`execFile('/usr/bin/convert', [userCmd, 'out.png']);`))).toHaveLength(0);
    // a name that only contains one of the programs is not one of them
    expect(await cmd(wrap(`spawnSync('sshfs-helper', [userCmd]);`))).toHaveLength(0);
  });

  it('a request value reaching ssh argv is a command_injection flow', async () => {
    const code = `import { spawn } from 'child_process';
import express from 'express';
const app = express();
app.get('/run', (req, res) => {
  const c = req.query.cmd as string;
  spawn('ssh', ['deploy@host', c]);
  res.send('ok');
});`;
    const flows = (await analyze(code, 'app.ts', 'typescript')).taint.flows.filter(f => f.sink_type === 'command_injection');
    expect(flows.length).toBeGreaterThan(0);
  });

  // The same gate exists for Go, Rust and C#; the shared list applies to each.
  const sinksIn = async (code: string, file: string, lang: 'go' | 'rust' | 'csharp') =>
    (await analyze(code, file, lang)).taint.sinks.filter(s => s.type === 'command_injection');

  it('Go exec.Command: ssh keeps the sink, git stays filtered', async () => {
    const go = (prog: string) => `package main\nimport "os/exec"\nfunc run(host string, userCmd string) {\n\texec.Command("${prog}", host, userCmd).Run()\n}\n`;
    expect((await sinksIn(go('ssh'), 'm.go', 'go')).length).toBeGreaterThan(0);
    expect((await sinksIn(go('sudo'), 'm.go', 'go')).length).toBeGreaterThan(0);
    expect(await sinksIn(go('git'), 'm.go', 'go')).toHaveLength(0);
  });

  it('Rust Command::new: kubectl keeps the sink, git stays filtered', async () => {
    const rs = (prog: string) => `use std::process::Command;\nfn run(user_cmd: String) {\n    Command::new("${prog}").arg("exec").arg(user_cmd).spawn().unwrap();\n}\n`;
    expect((await sinksIn(rs('kubectl'), 'm.rs', 'rust')).length).toBeGreaterThan(0);
    expect(await sinksIn(rs('git'), 'm.rs', 'rust')).toHaveLength(0);
  });

  it('C# Process.Start(exe, args): ssh.exe keeps the sink, git.exe stays filtered', async () => {
    const cs = (exe: string) => `using System.Diagnostics;\nclass C {\n  void Run(string userCmd) {\n    Process.Start("${exe}", userCmd);\n  }\n}\n`;
    expect((await sinksIn(cs('ssh.exe'), 'C.cs', 'csharp')).length).toBeGreaterThan(0);
    expect(await sinksIn(cs('git.exe'), 'C.cs', 'csharp')).toHaveLength(0);
  });
});

