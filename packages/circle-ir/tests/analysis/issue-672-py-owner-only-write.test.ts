/**
 * #672 — a secret written to a file that was created / opened with
 * owner-only permissions is not a CWE-256 `plaintext-password-storage`
 * finding. The same write to a default-permission or world-readable
 * destination still is.
 *
 * Fixtures use renamed identifiers on purpose: the fix keys on the
 * permission mode and on how the write's file handle was obtained, never on
 * file, function or variable names.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function plaintextLines(code: string): Promise<number[]> {
  const ir = await analyze(code, 'svc.py', 'python');
  return (ir.findings ?? [])
    .filter((f) => f.rule_id === 'plaintext-password-storage')
    .map((f) => f.line);
}

const HEAD = `import os\nfrom flask import Flask\n\napp = Flask(__name__)\n\n`;

describe('#672 owner-only destination is not plaintext password storage', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('os.open(..., 0o600) + os.fdopen + write scans clean', async () => {
    const lines = await plaintextLines(`${HEAD}@app.route("/dump")
def dump_settings():
    dest = "/srv/private/out.txt"
    handle_fd = os.open(dest, os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(handle_fd, "w") as out:
        out.write("API_KEY=" + os.environ.get("API_KEY", ""))
    return "ok"
`);
    expect(lines).toEqual([]);
  });

  it('owner-only mode 0o400 and 0o700 also count', async () => {
    for (const mode of ['0o400', '0o700']) {
      const lines = await plaintextLines(`${HEAD}def save(token_secret):
    n = os.open("/srv/p/x", os.O_WRONLY | os.O_CREAT, ${mode})
    with os.fdopen(n, "w") as sink:
        sink.write(token_secret)
`);
      expect(lines, mode).toEqual([]);
    }
  });

  it('inline os.fdopen(os.open(..., 0o600)).write is clean', async () => {
    const lines = await plaintextLines(`${HEAD}def save(db_password):
    os.fdopen(os.open("/srv/p/y", os.O_WRONLY | os.O_CREAT, 0o600), "w").write(db_password)
`);
    expect(lines).toEqual([]);
  });

  it('os.chmod(path, 0o600) before the write is clean', async () => {
    const lines = await plaintextLines(`${HEAD}def save(db_password):
    target = "/srv/p/z"
    os.chmod(target, 0o600)
    with open(target, "w") as fh:
        fh.write(db_password)
`);
    expect(lines).toEqual([]);
  });

  it('os.fchmod(fileno, 0o600) before the write is clean', async () => {
    const lines = await plaintextLines(`${HEAD}def save(db_password):
    with open("/srv/p/w", "w") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(db_password)
`);
    expect(lines).toEqual([]);
  });

  // ---- negatives: these must keep reporting ---------------------------------

  it('a default open() write still reports', async () => {
    const lines = await plaintextLines(`${HEAD}def export_cfg():
    with open("/var/www/static/config.txt", "w") as f:
        f.write("API_KEY=" + os.environ.get("API_KEY", ""))
`);
    expect(lines).toEqual([8]);
  });

  it('os.open with a world-readable mode (0o644) still reports', async () => {
    const lines = await plaintextLines(`${HEAD}def save(db_password):
    n = os.open("/srv/p/a", os.O_WRONLY | os.O_CREAT, 0o644)
    with os.fdopen(n, "w") as sink:
        sink.write(db_password)
`);
    expect(lines).toEqual([9]);
  });

  it('group-readable 0o640 and 0o660 still report', async () => {
    for (const mode of ['0o640', '0o660']) {
      const lines = await plaintextLines(`${HEAD}def save(db_password):
    n = os.open("/srv/p/b", os.O_WRONLY | os.O_CREAT, ${mode})
    with os.fdopen(n, "w") as sink:
        sink.write(db_password)
`);
      expect(lines, mode).toEqual([9]);
    }
  });

  it('os.chmod to a world-readable mode still reports', async () => {
    const lines = await plaintextLines(`${HEAD}def save(db_password):
    target = "/srv/p/c"
    os.chmod(target, 0o644)
    with open(target, "w") as fh:
        fh.write(db_password)
`);
    expect(lines).toEqual([10]);
  });

  it('an owner-only handle does not clear a different handle in the same function', async () => {
    const lines = await plaintextLines(`${HEAD}def save(db_password):
    n = os.open("/srv/p/d", os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(n, "w") as private_out:
        private_out.write("ok")
    with open("/var/www/static/d.txt", "w") as public_out:
        public_out.write(db_password)
`);
    expect(lines).toEqual([11]);
  });

  it('a chmod on an unrelated path does not clear the write', async () => {
    const lines = await plaintextLines(`${HEAD}def save(db_password):
    os.chmod("/srv/p/other", 0o600)
    with open("/var/www/static/e.txt", "w") as fh:
        fh.write(db_password)
`);
    expect(lines).toEqual([9]);
  });

  it('one-line with and write: a handle other than the owner-only one still reports', async () => {
    const lines = await plaintextLines(`${HEAD}def save(db_password, pub, p, f):
    with os.fdopen(os.open(p, f, 0o600)) as a, open(pub, "w") as b: b.write(db_password)
`);
    expect(lines).toEqual([7]);
  });

  it('a different handle on the with line reports when written in the with body', async () => {
    const lines = await plaintextLines(`${HEAD}def save(db_password, pub, p, f):
    with os.fdopen(os.open(p, f, 0o600)) as a, open(pub, "w") as b:
        b.write(db_password)
`);
    expect(lines).toEqual([8]);
  });

  it('the owner-only handle on a shared with line stays clear', async () => {
    const lines = await plaintextLines(`${HEAD}def save(db_password, pub, p, f):
    with os.fdopen(os.open(p, f, 0o600), "w") as a, open(pub, "w") as b:
        a.write(db_password)
`);
    expect(lines).toEqual([]);
  });

  it('a permissive chmod after an owner-only chmod, before the open, reports', async () => {
    const lines = await plaintextLines(`${HEAD}def save(db_password):
    t = "/srv/p/q"
    os.chmod(t, 0o600)
    os.chmod(t, 0o644)
    with open(t, "w") as fh:
        fh.write(db_password)
`);
    expect(lines).toEqual([11]);
  });

  it('an owner-only chmod after a permissive one (last wins) is clean', async () => {
    const lines = await plaintextLines(`${HEAD}def save(db_password):
    t = "/srv/p/r"
    os.chmod(t, 0o644)
    os.chmod(t, 0o600)
    with open(t, "w") as fh:
        fh.write(db_password)
`);
    expect(lines).toEqual([]);
  });
});
