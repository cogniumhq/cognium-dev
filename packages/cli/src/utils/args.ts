/**
 * Lightweight argument parser
 * Replaces commander dependency with zero-dependency alternative
 */

export interface ParsedArgs {
  command?: string;
  args: string[];
  options: Record<string, string | boolean>;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const args: string[] = [];
  const options: Record<string, string | boolean> = {};
  let command: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    if (arg.startsWith('--')) {
      // Long option
      const key = arg.slice(2);
      if (key.includes('=')) {
        const [k, v] = key.split('=', 2);
        options[k] = v;
      } else {
        const nextArg = argv[i + 1];
        if (nextArg && !nextArg.startsWith('-')) {
          options[key] = nextArg;
          i++;
        } else {
          options[key] = true;
        }
      }
    } else if (arg.startsWith('-') && arg.length === 2) {
      // Short option
      const key = arg.slice(1);
      const nextArg = argv[i + 1];
      if (nextArg && !nextArg.startsWith('-')) {
        options[key] = nextArg;
        i++;
      } else {
        options[key] = true;
      }
    } else {
      // Positional argument
      if (!command) {
        command = arg;
      } else {
        args.push(arg);
      }
    }
  }

  return { command, args, options };
}

export function showHelp(): void {
  console.log(`
cognium-dev - Static Application Security Testing CLI

USAGE:
  cognium-dev <command> [options]

COMMANDS:
  scan <path>          Scan files or directories for security vulnerabilities
  metrics <path>       Report software quality metrics for files or directories
  list-passes [cat]    List all analysis passes (optionally filter by category)
  init                 Initialize a configuration file in your project
  version              Display version information

SCAN OPTIONS:
  -l, --language <lang>      Scan only files for language (bash|go|html|java|javascript|typescript|python|rust)
  -f, --format <format>      Output format (text|json|sarif) [default: text]
  --threads <n>              Parallel analysis threads [default: 4]
  --severity <level>         Filter by severity:
                               - Single level: minimum severity (e.g., "high" shows high+critical)
                               - Multiple levels: exact match (e.g., "critical,high" shows only those)
                               - Valid levels: low, medium, high, critical
  --category <cats>          Filter by finding category (comma-separated):
                               - Valid categories: security, reliability, performance,
                                 maintainability, architecture
  --exclude-cwe <cwes>       Exclude specific CWEs (comma-separated, e.g., "CWE-330,CWE-327")
  --disable-pass <passes>    Disable specific passes (comma-separated, e.g., "naming-convention,todo-in-prod")
  --exclude-tests            Exclude test files and directories
  --profile <file>           Load config from file [default: cognium.config.json]
  --project-profile <p>      Force project profile (shape/env). Disables auto-detection.
                               - shape: library|application|cli|server|plugin
                               - env:   production|dev|sample|benchmark|test
                               - Example: --project-profile library/production
                               - Default: auto-detect from build files (pom.xml, build.gradle)
  --no-project-profile       Disable project-profile auto-detection (every file → unknown).
  --project-profile-explain  Print detected per-module profiles + reason chain, then exit.
  -o, --output <file>        Write results to file
  -q, --quiet                Suppress progress output
  -v, --verbose              Show detailed output
  --log-level <level>        circle-ir logger level (silent|trace|debug|info|warn|error|fatal)
                               [default: silent — also settable via COGNIUM_LOG_LEVEL env var]
  --cross-file-budget-ms <n> Wall-time budget (ms) for the cross-file phase
                               [default: 300000 (5 min) — 0 = unlimited]
                               On exceed: partial taint paths kept, remaining
                               cross-file phases skipped, cross_file_budget_exceeded
                               surfaced in output (text warning / JSON / SARIF field).

METRICS OPTIONS:
  -l, --language <lang>      Analyze only files for language (bash|go|html|java|javascript|typescript|python|rust)
  -f, --format <format>      Output format (text|json) [default: text]
  --category <cats>          Filter by metric category (comma-separated):
                               - Valid categories: complexity, size, coupling,
                                 inheritance, cohesion, documentation, duplication
  --exclude-tests            Exclude test files and directories
  --profile <file>           Load config from file [default: cognium.config.json]
  -o, --output <file>        Write results to file
  -q, --quiet                Suppress progress output

EXAMPLES:
  cognium-dev scan src/
  cognium-dev scan app.java -f json -o results.json
  cognium-dev scan . --exclude-tests --severity high
  cognium-dev scan . --severity critical,high
  cognium-dev scan . --category security
  cognium-dev scan . --category reliability,performance
  cognium-dev scan . --exclude-cwe CWE-330,CWE-327
  cognium-dev scan . --disable-pass naming-convention,todo-in-prod
  cognium-dev scan . --profile custom-config.json
  cognium-dev scan . --log-level info        # phase markers to stderr
  COGNIUM_LOG_LEVEL=debug cognium-dev scan . # verbose via env var
  cognium-dev scan . --cross-file-budget-ms 60000   # 60s cross-file cap
  cognium-dev scan . --cross-file-budget-ms 0       # unlimited (pre-3.89.0 behaviour)
  cognium-dev metrics src/
  cognium-dev metrics src/ --category complexity
  cognium-dev metrics src/ --format json --profile custom-config.json
  cognium-dev list-passes
  cognium-dev list-passes reliability
  cognium-dev init

For more information, visit: https://cognium.dev
`);
}

export function showVersion(version: string): void {
  console.log(`cognium-dev v${version}`);
  console.log(`Powered by Cognium Labs`);
}
