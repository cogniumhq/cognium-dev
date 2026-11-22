/**
 * cognium-devE2/E6 — where the taint sits in a JS/TS
 * `spawn` / `spawnSync` / `execFile` / `execFileSync` call.
 *
 * These take `(program, argv?, options?)`. Only the program and the argument
 * array make the command line; `options` (`env`, `cwd`, `stdio`, …) does not.
 * Without `shell`, Node passes argv to the program as-is, so a tainted argv
 * element is argument injection (CWE-88) at most, not a shell command.
 */
import { runsArgvAsCommand } from './arg-executing-programs.js';

/** A shell or interpreter that would run its arguments as a command. */
export const SHELL_PROGRAM = /(?:^|[\\/])(?:sh|bash|zsh|dash|ksh|fish|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|node|python3?|perl|ruby|php|osascript|env)$/i;

/** `shell: <anything but false>` in an options object (`shell: v` picks the shell). */
export const SHELL_OPTION_ON = /\bshell\s*:(?!\s*false\b)/;

/** Tag for a `command_injection` flow that is argument injection at most; reported at medium. */
export const ARGV_NO_SHELL_TAG = 'argv-no-shell:argument-injection';

export const JS_SPAWN_METHODS: ReadonlySet<string> = new Set(['spawn', 'spawnSync', 'execFile', 'execFileSync']);

/**
 * - `options-only`: the taint reaches only the options object; not a command.
 * - `argv-no-shell`: argv form, no shell, argument injection at most.
 * - `command`: anything else (keep as command injection).
 */
export type JsSpawnTaintShape = 'options-only' | 'argv-no-shell' | 'command';

/**
 * Top-level argument texts of the first `method(` call starting on `line`
 * (1-based), read across up to 12 lines. Null when the call is not found or
 * does not close.
 */
export function jsCallArgs(lines: readonly string[], line: number, method: string): string[] | null {
  const head = new RegExp(`\\b${method}\\s*\\(`).exec(lines[line - 1] ?? '');
  if (!head) return null;
  let text = (lines[line - 1] ?? '').slice(head.index + head[0].length);
  for (let k = 0; k < 12 && line + k < lines.length; k++) text += '\n' + lines[line + k];
  const args: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let cur = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quote) {
      cur += ch;
      if (ch === '\\') { cur += text[++i] ?? ''; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '\'' || ch === '"' || ch === '`') { quote = ch; cur += ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    if (ch === ')' || ch === ']' || ch === '}') {
      if (depth === 0) {
        if (cur.trim()) args.push(cur.trim());
        return args;
      }
      depth--;
    }
    if (ch === ',' && depth === 0) { args.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  return null;
}

const IDENT_RE = /^[A-Za-z_$][\w$]*$/;

function mentions(text: string, carrier: string): boolean {
  if (/^[A-Za-z_$][\w$.]*$/.test(carrier)) {
    const esc = carrier.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // Not a member of something else (`a.v`), but a spread (`...v`) counts.
    return new RegExp(`(?<![\\w$])(?<!(?<!\\.)\\.)${esc}(?![\\w$])`).test(text);
  }
  return text.replace(/\s+/g, ' ').includes(carrier.replace(/\s+/g, ' '));
}

/** `'git'` → `git`; `NAME` with a file-level `const NAME = 'git'` → `git`; else null. */
function resolveProgram(program: string, code: string): string | null {
  const lit = /^(['"`])([^'"`$]*)\1$/.exec(program);
  if (lit) return lit[2]!;
  if (!IDENT_RE.test(program)) return null;
  const decl = new RegExp(`\\bconst\\s+${program.replace(/\$/g, '\\$')}\\s*(?::\\s*string\\s*)?=\\s*(['"\`])([^'"\`$]*)\\1\\s*;?\\s*$`, 'm').exec(code);
  return decl ? decl[2]! : null;
}

const LOCATION_NAME_CHAR = /[\w$<>.]/;
const isSpace = (ch: string): boolean => ch.trim() === '';

/**
 * A source's location text without its trailing ` in <method>`
 * (`"cmd in run"` → `"cmd"`), trimmed. Same result as
 * `.replace(/\s+in\s+[\w$<>.]+$/, '').trim()`, scanned from the end so a long
 * run of spaces does not backtrack.
 */
export function stripInMethodSuffix(location: string): string {
  let i = location.length;
  while (i > 0 && LOCATION_NAME_CHAR.test(location[i - 1]!)) i--;
  if (i === location.length) return location.trim();
  let j = i;
  while (j > 0 && isSpace(location[j - 1]!)) j--;
  if (j === i || j < 3 || location.slice(j - 2, j) !== 'in' || !isSpace(location[j - 3]!)) return location.trim();
  return location.slice(0, j - 3).trim();
}

/**
 * Classify a `command_injection` flow into a spawn-family call.
 *
 * @param carriers   names or source text that carry the flow's taint into the call
 * @param envProgram the flow's source is the process environment (operator-set)
 */
export function classifyJsSpawnTaint(
  code: string,
  line: number,
  method: string,
  carriers: readonly string[],
  envProgram: boolean,
): JsSpawnTaintShape {
  if (!JS_SPAWN_METHODS.has(method) || carriers.length === 0) return 'command';
  const lines = code.split('\n');
  const args = jsCallArgs(lines, line, method);
  if (!args || args.length === 0) return 'command';
  const argvIndex = args.length > 1 && !args[1]!.startsWith('{') ? 1 : -1;
  const commandArgs = argvIndex === 1 ? args.slice(0, 2) : args.slice(0, 1);
  const options = args.slice(commandArgs.length).join(', ');
  const inCommand = commandArgs.some(a => carriers.some(c => mentions(a, c)));
  const shellOn = SHELL_OPTION_ON.test(options);
  if (!inCommand) {
    if (!options || !carriers.some(c => mentions(options, c))) return 'command';
    const shellValue = /\bshell\s*:\s*([^,}]+)/.exec(options)?.[1] ?? '';
    return carriers.some(c => mentions(shellValue, c)) ? 'command' : 'options-only';
  }
  // Argument-injection downgrade needs a visible options object without a
  // shell (or none at all) and an argument array literal.
  if (shellOn) return 'command';
  const opts = args[commandArgs.length];
  const isCallback = (a: string): boolean => /^(?:async\s+)?(?:function\b|(?:\([^()]*\)|[A-Za-z_$][\w$]*)\s*=>)/.test(a);
  if (opts !== undefined && !opts.startsWith('{') && !isCallback(opts)) return 'command';
  if (argvIndex !== 1 || !args[1]!.startsWith('[')) return 'command';
  if (/['"`]-(?:c|e|p|-eval|-print)['"`]/.test(args[1]!)) return 'command';
  const programTainted = carriers.some(c => mentions(args[0]!, c));
  if (programTainted) return envProgram ? 'argv-no-shell' : 'command';
  if (args[0] === 'process.execPath') return 'argv-no-shell';
  const program = resolveProgram(args[0]!, code);
  if (program === null || SHELL_PROGRAM.test(program) || runsArgvAsCommand(program)) return 'command';
  return 'argv-no-shell';
}
