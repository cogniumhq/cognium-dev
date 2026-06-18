/**
 * Pass: module-side-effect (CWE-829, category: security)
 *
 * Pattern pass — flags dangerous side effects executed at **module load /
 * install / build time**, where no taint flow is involved (the bad behavior
 * is hard-coded by an attacker, not user-driven). This is the canonical
 * delivery vector for supply-chain droppers: shai-hulud-style TruffleHog
 * harvesters in npm `postinstall`, Python `__init__.py` credential POST,
 * Go `init()` exfil, Rust `build.rs` exec.
 *
 * Detection per language:
 *   JavaScript / TypeScript:
 *     - module-level call (`in_method == null`) to a high-risk API:
 *       `child_process.{exec,spawn,execSync,spawnSync}`,
 *       `https.request`, `http.request`,
 *       `fetch` / `axios.*` whose args reference `process.env` or `os.homedir`.
 *     - `package.json` source-text scan (when `meta.file` ends with
 *       `package.json`): a `scripts.(pre|post)?install` value that invokes a
 *       shell (`curl`, `wget`, `node -e`, `sh -c`, `eval`). Benign install
 *       scripts (`node-gyp rebuild`, `prebuild-install`, `husky install`,
 *       `patch-package`) are allowlisted.
 *
 *   Python:
 *     - module-level call (`in_method == null`) to a high-risk API:
 *       `requests.{post,put}`, `urllib.request.urlopen`,
 *       `socket.{connect,create_connection}`, `subprocess.run`, `os.system`.
 *     - The call must reference an "env / secret" signal in any argument
 *       expression: `os.environ`, `pwd.getpw`, `glob.glob('/.../id_rsa`,
 *       `~/.ssh`, `/etc/passwd`, `home`, `pathlib.Path.home`. This keeps the
 *       FP rate near zero on benign module-level network setup.
 *
 *   Go:
 *     - call inside a function named `init` (`in_method === 'init'`) whose
 *       callee is `exec.Command`, `http.Post`, `http.Get`, `net.LookupTXT`,
 *       `os.Setenv`.
 *
 *   Rust:
 *     - file is a build script (`meta.file` ends with `build.rs`) AND callee
 *       is `Command::new` / `std::process::Command::new` / `reqwest::*`.
 *       `println!("cargo:...")` directives are the only intended `build.rs`
 *       side effect — those produce no IR call.
 *
 * Closes: cognium-dev #93 (npm postinstall dropper), #96 L47 (Python import-
 * time harvest), #98 (Go init() + Rust build.rs install-time harvest).
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

// JavaScript / TypeScript ----------------------------------------------------
//
// receiver+method tuples whose presence at module top is a strong supply-
// chain dropper signal.
const JS_EXEC_METHODS = new Set([
  'exec', 'spawn', 'execSync', 'spawnSync', 'execFile', 'execFileSync',
]);
const JS_EXEC_RECEIVERS = new Set([
  'child_process', 'cp',
]);
// The lower-bar "any module-top network call" methods. Modulo benign cases
// these are almost never legitimate as bare module-init effects.
const JS_NETWORK_RECEIVER_METHOD = new Set([
  'https:request', 'http:request', 'https:get', 'http:get',
]);
// Methods where the env-signal qualifier applies (e.g. fetch + process.env).
const JS_NETWORK_MAYBE = new Set([
  'fetch',
]);
const JS_ENV_SIGNAL_RE =
  /\bprocess\.env\b|\bos\.homedir\b|\/etc\/(passwd|shadow)\b|\.ssh\/id_(rsa|dsa|ed25519)\b|\bhomedir\b/;

// package.json install-script regexes. Benign install commands that we
// explicitly do NOT flag.
const PKG_JSON_BENIGN_INSTALL = new Set([
  'node-gyp rebuild',
  'prebuild-install',
  'prebuild-install || node-gyp rebuild',
  'husky install',
  'patch-package',
  'npm run build',
]);
const PKG_JSON_INSTALL_SHELL_RE =
  /\b(curl|wget|nc|ncat|node\s+-e|node\s+-r|sh\s+-c|bash\s+-c|eval|base64\s+-d)\b/;

// Python ---------------------------------------------------------------------
const PY_NETWORK_RECEIVER_METHODS: Array<{ receiver: string; method: string }> = [
  { receiver: 'requests',         method: 'post' },
  { receiver: 'requests',         method: 'put' },
  { receiver: 'urllib.request',   method: 'urlopen' },
  { receiver: 'socket',           method: 'create_connection' },
  { receiver: 'socket',           method: 'connect' },
  { receiver: 'subprocess',       method: 'run' },
  { receiver: 'subprocess',       method: 'Popen' },
  { receiver: 'os',               method: 'system' },
];
const PY_ENV_SIGNAL_RE =
  /\bos\.environ\b|\bpwd\.getpw\b|\bid_(rsa|dsa|ed25519)\b|\bhome\b|\b\/etc\/(passwd|shadow)\b|\bPath\.home\b|\bglob\.glob\b/;

// Go ------------------------------------------------------------------------
const GO_INIT_DANGEROUS: Array<{ receiver: string; method: string }> = [
  { receiver: 'exec', method: 'Command' },
  { receiver: 'http', method: 'Post' },
  { receiver: 'http', method: 'Get' },
  { receiver: 'net',  method: 'LookupTXT' },
  { receiver: 'os',   method: 'Setenv' },
];

// Rust ----------------------------------------------------------------------
const RUST_DANGEROUS_METHODS = new Set([
  'Command::new', 'process::Command::new', 'std::process::Command::new',
  'new', // Command::new appears as method='new', receiver='Command' / etc.
]);
const RUST_DANGEROUS_RECEIVERS = new Set([
  'Command', 'process::Command', 'std::process::Command',
  'reqwest', 'reqwest::blocking',
]);

export interface ModuleSideEffectResult {
  findings: Array<{
    line: number;
    language: string;
    pattern: string;
    api: string;
  }>;
}

export class ModuleSideEffectPass implements AnalysisPass<ModuleSideEffectResult> {
  readonly name = 'module-side-effect';
  readonly category = 'security' as const;

  run(ctx: PassContext): ModuleSideEffectResult {
    const { graph, language, code } = ctx;
    const file = graph.ir.meta.file;
    const findings: ModuleSideEffectResult['findings'] = [];

    const emit = (line: number, pattern: string, api: string) => {
      // Dedup by (line, pattern).
      if (findings.some((f) => f.line === line && f.pattern === pattern)) return;
      findings.push({ line, language, pattern, api });
      ctx.addFinding({
        id: `${this.name}-${file}-${line}-${pattern.replace(/\W+/g, '-')}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-829',
        severity: 'high',
        level: 'error',
        message:
          `Module-level / install-time side effect (${pattern}) in \`${api}\`. ` +
          `Code that runs at import / build / install time is invisible to ` +
          `runtime defenses and is the standard delivery vector for supply-` +
          `chain droppers (shai-hulud-style harvesters, malicious typosquats, ` +
          `build.rs exfil). If this side effect is intentional, move it into ` +
          `an explicit function invoked at runtime; if it is install-time ` +
          `configuration, restrict it to documented APIs (e.g. \`cargo:\` ` +
          `directives, \`node-gyp rebuild\`).`,
        file,
        line,
        fix: this.fixFor(language, pattern),
        evidence: { language, api, pattern },
      });
    };

    // For Rust, we only flag side effects inside `build.rs` — that is the
    // documented install-time entry. Cargo crates with a regular `main.rs`
    // exec subprocesses all the time and that is not a supply-chain signal.
    const isRustBuildScript =
      language === 'rust' && /\bbuild\.rs$/.test(file);

    // Call-layer detection ------------------------------------------------
    for (const call of graph.ir.calls) {
      if (language === 'rust' && !isRustBuildScript) continue;
      const det = this.detectCall(call, language);
      if (!det) continue;
      emit(call.location.line, det.pattern, det.api);
    }

    // Source-text layer ---------------------------------------------------
    if (language === 'javascript' || language === 'typescript') {
      if (/\bpackage\.json$/.test(file)) {
        for (const extra of this.scanPackageJson(code)) {
          emit(extra.line, extra.pattern, extra.api);
        }
      }
    }

    return { findings };
  }

  private detectCall(
    call: CallInfo,
    language: string,
  ): { pattern: string; api: string } | null {
    const method = call.method_name;
    const receiver = call.receiver ?? '';

    if (language === 'javascript' || language === 'typescript') {
      // Module-level only — calls inside any function are out of scope.
      if (call.in_method != null) return null;
      // child_process.{exec,spawn,...} — receiver is `child_process` or `cp`.
      if (JS_EXEC_RECEIVERS.has(receiver) && JS_EXEC_METHODS.has(method)) {
        return {
          pattern: 'module-level child_process call',
          api: `${receiver}.${method}`,
        };
      }
      // https.request, http.request, http.get, https.get — bare module-init
      // network calls are highly suspicious.
      const recvMethod = `${receiver}:${method}`;
      if (JS_NETWORK_RECEIVER_METHOD.has(recvMethod)) {
        return {
          pattern: 'module-level network request',
          api: `${receiver}.${method}`,
        };
      }
      // fetch + env-signal qualifier (process.env / os.homedir / sensitive file
      // path in any argument expression).
      if (JS_NETWORK_MAYBE.has(method) && receiver === '') {
        for (const arg of call.arguments) {
          if (JS_ENV_SIGNAL_RE.test(arg.expression ?? '')) {
            return {
              pattern: 'module-level fetch of process.env',
              api: method,
            };
          }
        }
      }
      return null;
    }

    if (language === 'python') {
      if (call.in_method != null) return null;
      for (const tuple of PY_NETWORK_RECEIVER_METHODS) {
        if (receiver === tuple.receiver && method === tuple.method) {
          // Require an env / secret signal in any argument to avoid flagging
          // benign top-level network setup.
          for (const arg of call.arguments) {
            if (PY_ENV_SIGNAL_RE.test(arg.expression ?? '')) {
              return {
                pattern: 'import-time network call with env signal',
                api: `${receiver}.${method}`,
              };
            }
          }
        }
      }
      return null;
    }

    if (language === 'go') {
      if (call.in_method !== 'init') return null;
      for (const tuple of GO_INIT_DANGEROUS) {
        if (receiver === tuple.receiver && method === tuple.method) {
          return {
            pattern: 'init() install-time side effect',
            api: `${receiver}.${method}`,
          };
        }
      }
      return null;
    }

    if (language === 'rust') {
      // The caller in run() guards by filename (build.rs only).
      // Rust IR doesn't surface in_method reliably; we instead match
      // dangerous receiver/method tuples directly.
      const recv = receiver.trim();
      if (RUST_DANGEROUS_RECEIVERS.has(recv) || recv.startsWith('Command::')) {
        if (
          method === 'new' ||
          RUST_DANGEROUS_METHODS.has(method) ||
          method === 'get' ||
          method === 'post'
        ) {
          return {
            pattern: 'build.rs side effect',
            api: `${recv || method}.${method}`,
          };
        }
      }
      return null;
    }

    return null;
  }

  /**
   * Scan a package.json file for dangerous install-lifecycle scripts.
   * Best-effort regex extraction — package.json is not a JS source per se but
   * the analyzer routes it through the JS pipeline.
   */
  private scanPackageJson(
    code: string,
  ): Array<{ line: number; pattern: string; api: string }> {
    const out: Array<{ line: number; pattern: string; api: string }> = [];
    const lines = code.split('\n');
    const installRe =
      /"(pre|post)?install"\s*:\s*"([^"]+)"/i;
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(installRe);
      if (!m) continue;
      const value = m[2].trim();
      if (PKG_JSON_BENIGN_INSTALL.has(value)) continue;
      if (!PKG_JSON_INSTALL_SHELL_RE.test(value)) continue;
      out.push({
        line: i + 1,
        pattern: 'npm lifecycle hook executes shell',
        api: `scripts.${m[1] ?? ''}install`,
      });
    }
    return out;
  }

  private fixFor(language: string, pattern: string): string {
    if (pattern.includes('child_process')) {
      return 'Remove the module-level child_process call. If an install-time ' +
        'step is genuinely required, move it into an explicit function and ' +
        'document why it must run at install time.';
    }
    if (pattern.includes('module-level network')) {
      return 'Network requests should not run at module load. Move the call ' +
        'inside an exported function called explicitly by the caller.';
    }
    if (pattern.includes('module-level fetch of process.env')) {
      return 'Exfiltrating `process.env` at module load is the canonical ' +
        'supply-chain dropper shape. Remove this code or, if intentional, ' +
        'gate it behind an explicit opt-in.';
    }
    if (pattern.includes('npm lifecycle hook')) {
      return 'Replace the install-script shell payload with a build tool ' +
        '(e.g. `node-gyp rebuild`, `prebuild-install`). Lifecycle scripts ' +
        'that invoke curl/wget/node -e/sh -c are how supply-chain droppers ' +
        'are delivered.';
    }
    if (pattern.includes('import-time network call')) {
      return 'Move the network call inside an explicit function. Sending ' +
        '`os.environ` or filesystem secrets at module import is the canonical ' +
        'credential-harvester shape.';
    }
    if (pattern.includes('init()')) {
      return 'Move the side effect out of `init()`. Go `init` functions ' +
        'run automatically on package import; network/exec calls there are ' +
        'invisible to the caller and are how supply-chain droppers operate.';
    }
    if (pattern.includes('build.rs')) {
      return '`build.rs` should only emit `cargo:` directives. ' +
        'Spawning subprocesses or making network requests at build time is ' +
        'a documented supply-chain attack vector (see RUSTSEC).';
    }
    void language;
    return 'Remove the module-level side effect or move it inside an ' +
      'explicit, runtime-invoked function.';
  }
}
