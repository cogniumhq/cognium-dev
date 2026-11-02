/**
 * cognium-dev#1066 — programs that run (part of) their own argv as a command.
 *
 * The execve-style safe gates (JS `spawn`/`execFile`, Go `exec.Command`, Rust
 * `Command::new`, C# `Process.Start(exe, args)`, and the JS fixed-program
 * filter of #1059) drop a `command_injection` sink when the program is a
 * fixed, non-shell literal: argv cannot become a command. That holds for `git`
 * or `convert`, not for these: `ssh host cmd`, `sudo cmd`, `docker exec c cmd`,
 * `kubectl exec p -- cmd`, `xargs cmd`, and the wrappers that exec what
 * follows them (`nohup`, `timeout`, `nice`, …). A tainted argv element still
 * becomes the command they run, so they keep the sink, like a shell.
 */
export const ARG_EXECUTING_PROGRAMS: ReadonlySet<string> = new Set([
  'ssh', 'sudo', 'doas', 'su', 'runuser', 'pkexec',
  'docker', 'podman', 'nerdctl', 'kubectl', 'oc',
  'xargs', 'parallel', 'env',
  'nohup', 'timeout', 'nice', 'ionice', 'stdbuf', 'setsid', 'chroot', 'flock', 'watch',
]);

/** True when the program (a literal: bare name, path, or `.exe`) runs its argv as a command. */
export function runsArgvAsCommand(program: string): boolean {
  const base = (program.split(/[\\/]/).pop() ?? program).toLowerCase().replace(/\.exe$/, '');
  return ARG_EXECUTING_PROGRAMS.has(base);
}
