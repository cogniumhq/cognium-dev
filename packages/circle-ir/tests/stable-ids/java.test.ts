/**
 * `ids@0.1` for Java: qualified name plus erased signature; bodies change
 * when, and only when, the normalized body changes.
 */

import { describe, it, expect } from 'vitest';
import { deriveStableIds, detectMoves, diffStableIds, eraseJavaType, type StableIdFile } from '../../src/stable-ids/index.js';

const java = (code: string, file = 'src/main/java/app/Repo.java') => deriveStableIds(code, file, 'java', { keepBodyTokens: true });
const rows = (f: StableIdFile) => f.decls.map(d => `${d.kind} ${d.qualified_name} ${d.signature}${d.flags.length ? ' ' + d.flags.join(',') : ''}`);

const REPO = `package app;

import java.util.*;

/** A repository. */
@Service
public class Repo<T extends Item> implements Store {
  private final Map<String, T> rows = new HashMap<>(), spare = null;
  static int count;
  static { count = 0; }

  public Repo() { this(16); }
  public Repo(int size) { }

  public T find(String id) { return rows.get(id); }
  public List<T> find(Collection<String> ids, int... flags) {
    return ids.stream().map(this::find).filter(x -> x != null).toList();
  }
  void run() { new Thread(new Runnable() { public void run() { find("a"); } }).start(); }

  enum Mode { ON, OFF; void flip() {} }
  record Pair(String a, int b) { Pair { } }
  interface Hook { void on(String e); }
}
`;

describe('Java ids', () => {
  it('declares types, members, overloads and nested bodies', async () => {
    const f = await java(REPO);
    expect(f.language).toBe('java');
    expect(f.module).toBe('app/Repo');
    expect(f.partial).toBe(false);
    expect(rows(f)).toEqual([
      'module app/Repo ',
      'type app:Repo <T>',
      'field app:Repo.rows Map',
      'field app:Repo.spare Map',
      'field app:Repo.count int',
      'method app:Repo.<clinit> ',
      'method app:Repo.constructor ()',
      'method app:Repo.constructor (int)',
      'method app:Repo.find (String)',
      'method app:Repo.find (Collection,int...)',
      'function app:Repo.find/<lambda>@4.0.0.0.2.0 (_) unstable:anonymous',
      'method app:Repo.run ()',
      'type app:Repo.run/<anonymous Runnable>@3.0.0.0.1.0  unstable:anonymous',
      'type app:Repo.Mode ',
      'field app:Repo.Mode.ON ',
      'field app:Repo.Mode.OFF ',
      'method app:Repo.Mode.flip ()',
      'type app:Repo.Pair ',
      'field app:Repo.Pair.a String',
      'field app:Repo.Pair.b int',
      'method app:Repo.Pair.constructor <compact>',
      'type app:Repo.Hook ',
      'method app:Repo.Hook.on (String)',
    ]);
  });

  it('keeps ids under reformatting, comments, reordering and generic-argument changes', async () => {
    const a = await java(REPO);
    const b = await java(REPO
      .replace('/** A repository. */\n', '')
      .replace('  public Repo(int size) { }\n', '')
      .replace('  public T find(String id) { return rows.get(id); }', '  public T find(String id) {\n    // read\n    return rows.get(id);\n  }\n  public Repo(int size) {}')
      .replace('Collection<String> ids', 'Collection<? extends CharSequence> ids'));
    const d = diffStableIds([a], [b]);
    expect(d.added).toEqual([]);
    expect(d.removed).toEqual([]);
    // Member order and the generic argument changed the class body and find's body, nothing else.
    expect(d.body_changed.map(([x]) => x.qualified_name).sort()).toEqual(['app:Repo', 'app:Repo.find']);
  });

  it('a body edit changes only that body; a parameter type change re-keys the method', async () => {
    const a = await java(REPO);
    const b = await java(REPO.replace('return rows.get(id);', 'return rows.getOrDefault(id, null);'));
    expect(diffStableIds([a], [b]).body_changed.map(([x]) => x.qualified_name)).toEqual(['app:Repo.find']);
    const c = await java(REPO.replace('public T find(String id)', 'public T find(CharSequence id)'));
    const m = detectMoves([a], [c]);
    expect(m.moves.map(x => [x.relation, x.from.signature, x.to.signature])).toEqual([['signature-changed', '(String)', '(CharSequence)']]);
  });

  it('a class moved to another package is a move', async () => {
    const a = await java(REPO);
    const b = await java(REPO.replace('package app;', 'package app.data;'), 'src/main/java/app/data/Repo.java');
    const m = detectMoves([a], [b]);
    expect(m.moves.find(x => x.from.name === 'Repo' && x.from.kind === 'type')?.to.qualified_name).toBe('app.data:Repo');
    expect(m.diff.removed).toEqual([]);
  });

  it('the default package and parse errors', async () => {
    const f = await java('class A { void m( { }', 'A.java');
    expect(f.module).toBe('<default>/A');
    expect(f.partial).toBe(true);
  });

  it('erases types', () => {
    expect(eraseJavaType('java.util.Map<String, List<Integer>>')).toBe('Map');
    expect(eraseJavaType('@NonNull final String[] []')).toBe('String[][]');
    expect(eraseJavaType('Outer.Inner<T>[]')).toBe('Inner[]');
  });
});
