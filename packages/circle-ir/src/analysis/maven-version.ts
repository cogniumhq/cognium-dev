/**
 * Maven version ordering — the ordering Maven itself uses to compare
 * artifact versions (`org.apache.maven.artifact.versioning.ComparableVersion`),
 * reimplemented from its documented rules so advisory ranges keyed on Maven
 * versions (`introduced` / `fixed` / `last_affected`) are evaluated the way
 * the build resolves them.
 *
 * Rules:
 *   - case-insensitive; items are separated by `.` and `-`, and a transition
 *     between digits and letters splits an item too (`1rc2` = `1-rc-2`);
 *   - `-` (and a digit/letter transition) opens a nested sub-list, `.` does not,
 *     except before a qualifier (`1.RC1` = `1-RC1`, as Maven 3.9 orders it);
 *   - an empty item is `0`;
 *   - "null" items — `0`, `""`, `final`, `ga`, `release` — are trimmed from the
 *     end of every list, so `1.0.0` = `1` = `1.0-final` = `1-ga`;
 *   - qualifiers order `alpha < beta < milestone < rc (= cr) < snapshot <
 *     "" (release) < sp`; `a`, `b`, `m` directly followed by a digit mean
 *     `alpha`, `beta`, `milestone`; any other qualifier sorts after all known
 *     ones, lexically;
 *   - a number is greater than any qualifier, and greater than a sub-list.
 *
 * Pure and synchronous; numbers of any length are compared exactly.
 */

type Item = IntItem | StringItem | ListItem;

interface IntItem { kind: 'int'; value: bigint }
interface StringItem { kind: 'string'; value: string }
interface ListItem { kind: 'list'; items: Item[] }

const QUALIFIERS = ['alpha', 'beta', 'milestone', 'rc', 'snapshot', '', 'sp'];
const RELEASE_INDEX = String(QUALIFIERS.indexOf(''));
const ALIASES: Record<string, string> = { ga: '', final: '', release: '', cr: 'rc' };

function comparableQualifier(q: string): string {
  const i = QUALIFIERS.indexOf(q);
  return i === -1 ? `${QUALIFIERS.length}-${q}` : String(i);
}

function stringItem(value: string, followedByDigit: boolean): StringItem {
  let v = value;
  if (followedByDigit && v.length === 1) {
    if (v === 'a') v = 'alpha';
    else if (v === 'b') v = 'beta';
    else if (v === 'm') v = 'milestone';
  }
  return { kind: 'string', value: ALIASES[v] ?? v };
}

function parseItem(buf: string, isDigit: boolean, followedByDigit: boolean): Item {
  if (isDigit) return { kind: 'int', value: BigInt(buf) };
  return stringItem(buf, followedByDigit);
}

function isNull(item: Item): boolean {
  if (item.kind === 'int') return item.value === 0n;
  if (item.kind === 'string') return comparableQualifier(item.value) === RELEASE_INDEX;
  return item.items.length === 0;
}

function normalize(list: ListItem): void {
  for (let i = list.items.length - 1; i >= 0; i--) {
    const last = list.items[i];
    if (isNull(last)) list.items.splice(i, 1);
    else if (last.kind !== 'list') break;
  }
}

function parse(version: string): ListItem {
  // Maven 3.9 (MNG-7644): a qualifier after `.` sorts as if after `-`, so
  // `1.0.0.RC1` = `1.0.0-RC1` and `1.foo` = `1-foo`.
  const v = version.trim().toLowerCase().replace(/\.(?=[a-z])/g, '-');
  const root: ListItem = { kind: 'list', items: [] };
  let list = root;
  const stack: ListItem[] = [root];
  let isDigit = false;
  let start = 0;
  const isDigitAt = (i: number): boolean => i < v.length && v[i] >= '0' && v[i] <= '9';

  const pushSubList = (): void => {
    const sub: ListItem = { kind: 'list', items: [] };
    list.items.push(sub);
    list = sub;
    stack.push(sub);
  };

  for (let i = 0; i < v.length; i++) {
    const c = v[i];
    if (c === '.' || c === '-') {
      if (i === start) list.items.push({ kind: 'int', value: 0n });
      else list.items.push(parseItem(v.slice(start, i), isDigit, isDigitAt(i + 1)));
      start = i + 1;
      if (c === '-') pushSubList();
      isDigit = false;
    } else if (c >= '0' && c <= '9') {
      if (!isDigit && i > start) {
        list.items.push(stringItem(v.slice(start, i), true));
        start = i;
        pushSubList();
      }
      isDigit = true;
    } else {
      if (isDigit && i > start) {
        list.items.push(parseItem(v.slice(start, i), true, false));
        start = i;
        pushSubList();
      }
      isDigit = false;
    }
  }
  if (v.length > start) list.items.push(parseItem(v.slice(start), isDigit, false));
  while (stack.length > 0) normalize(stack.pop() as ListItem);
  return root;
}

function compareItem(a: Item | undefined, b: Item | undefined): number {
  if (a === undefined) {
    if (b === undefined) return 0;
    return -compareItem(b, undefined);
  }
  switch (a.kind) {
    case 'int':
      if (b === undefined) return a.value === 0n ? 0 : 1;
      if (b.kind === 'int') return a.value < b.value ? -1 : a.value > b.value ? 1 : 0;
      return 1; // a number beats a qualifier and a sub-list
    case 'string': {
      if (b === undefined) return cmpStr(comparableQualifier(a.value), RELEASE_INDEX);
      if (b.kind === 'int' || b.kind === 'list') return -1;
      return cmpStr(comparableQualifier(a.value), comparableQualifier(b.value));
    }
    case 'list': {
      if (b === undefined) return a.items.length === 0 ? 0 : compareItem(a.items[0], undefined);
      if (b.kind === 'int') return -1;
      if (b.kind === 'string') return 1;
      const n = Math.max(a.items.length, b.items.length);
      for (let i = 0; i < n; i++) {
        const r = compareItem(a.items[i], b.items[i]);
        if (r !== 0) return r;
      }
      return 0;
    }
  }
}

function cmpStr(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Compare two Maven versions: negative, zero or positive, as Maven orders them. */
export function compareMavenVersions(a: string, b: string): number {
  return Math.sign(compareItem(parse(a), parse(b)));
}

/** The canonical form Maven compares by (useful in tests and diagnostics). */
export function canonicalMavenVersion(version: string): string {
  const render = (list: ListItem): string => {
    let out = '';
    for (const item of list.items) {
      if (out.length > 0) out += item.kind === 'list' ? '-' : '.';
      out += item.kind === 'int' ? item.value.toString() : item.kind === 'string' ? item.value : render(item);
    }
    return out;
  };
  return render(parse(version));
}
