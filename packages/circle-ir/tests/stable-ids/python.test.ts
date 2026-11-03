/**
 * `ids@0.1` for Python: dotted module plus enclosing names; signature is
 * arity plus annotations; bodies keep block structure.
 */

import { describe, it, expect } from 'vitest';
import { deriveStableIds, detectMoves, diffStableIds, pythonModuleName, type StableIdFile } from '../../src/stable-ids/index.js';

const py = (code: string, file = 'src/app/users.py') => deriveStableIds(code, file, 'python', { keepBodyTokens: true });
const rows = (f: StableIdFile) => f.decls.map(d => `${d.kind} ${d.qualified_name} ${d.signature}${d.flags.length ? ' ' + d.flags.join(',') : ''}`);

const USERS = `"""Users."""
from .db import session

LIMIT: int = 10
cache = {}

@app.route("/users/<int:uid>", methods=["GET"])
def get_user(uid: int, *, verbose=False) -> dict:
    """Fetch one."""
    row = session.get(uid)
    return {"id": row.id} if row else {}

class Repo(Base):
    """A repository."""
    table = "users"

    def __init__(self, db, *args, **kw):
        self.db = db

    @property
    def size(self):
        return len(self.db)

    def find(self, uid):
        def inner(x):
            return x + 1
        return sorted(self.db, key=lambda r: r.id)
`;

describe('Python ids', () => {
  it('declares the module, functions, classes, methods, fields and nested bodies', async () => {
    const f = await py(USERS);
    expect(f.language).toBe('python');
    expect(f.module).toBe('app.users');
    expect(rows(f)).toEqual([
      'module app.users ',
      'field app.users:LIMIT int',
      'field app.users:cache ',
      'function app.users:get_user (int,*,_?)->dict',
      'type app.users:Repo (Base)',
      'field app.users:Repo.table ',
      'method app.users:Repo.__init__ (_,_,*_,**_)',
      'method app.users:Repo.size (_)',
      'method app.users:Repo.find (_,_)',
      'function app.users:Repo.find/inner@2.0 (_) unstable:anonymous',
      'function app.users:Repo.find/<lambda>@2.1.0.1.1.1 (_) unstable:anonymous',
    ]);
  });

  it('comments, docstrings and blank lines are not body; indentation is', async () => {
    const a = await py(USERS);
    const b = await py(USERS.replace('    """Fetch one."""\n', '    # fetch\n').replace('"""Users."""\n', '').replace('    table = "users"\n', '    table = "users"  # name\n\n'));
    const d = diffStableIds([a], [b]);
    expect(d.added).toEqual([]);
    expect(d.body_changed).toEqual([]);
    const dedent = await py(USERS.replace('        return x + 1\n        return sorted', '        return x + 1\n    return sorted'));
    expect(diffStableIds([a], [dedent]).body_changed.map(([x]) => x.qualified_name)).toContain('app.users:Repo.find');
  });

  it('parameter names never key a function; arity and annotations do', async () => {
    const a = (await py('def f(a, b: int): pass')).decls[1];
    const b = (await py('def f(x, y: int): pass')).decls[1];
    const c = (await py('def f(a, b: str): pass')).decls[1];
    expect(b.id).toBe(a.id);
    expect(c.id).not.toBe(a.id);
  });

  it('a module moved to another package is a move', async () => {
    const a = await py(USERS, 'src/app/users.py');
    const b = await py(USERS, 'src/app/accounts/users.py');
    const m = detectMoves([a], [b]);
    expect(m.moves.find(x => x.from.name === 'get_user')?.to.qualified_name).toBe('app.accounts.users:get_user');
    expect(m.diff.removed).toEqual([]);
  });

  it('module names', async () => {
    expect(pythonModuleName('src/pkg/__init__.py')).toBe('pkg');
    expect(pythonModuleName('./tools/run.py')).toBe('tools.run');
    expect(pythonModuleName('__init__.py')).toBe('__main__');
    expect((await py('def f(:', 'x.py')).partial).toBe(true);
  });
});
