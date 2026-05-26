import type { MetricValue } from '../../../types/index.js';
import type { MetricPass, MetricContext } from '../metric-pass.js';

const KEYWORDS = new Set([
  'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'return', 'new', 'delete',
  'typeof', 'instanceof', 'void', 'in', 'of', 'and', 'or', 'not', 'def', 'class',
  'fn', 'let', 'const', 'var', 'function', 'import', 'export', 'async', 'await',
  'try', 'catch', 'throw', 'finally', 'yield', 'break', 'continue', 'default',
  'public', 'private', 'protected', 'static', 'final', 'abstract', 'extends',
  'implements', 'interface', 'enum', 'this', 'super', 'null', 'true', 'false',
  'undefined', 'from', 'as', 'type', 'struct', 'impl', 'trait', 'use', 'mod',
  'pub', 'mut', 'match', 'where', 'with', 'pass', 'lambda', 'del', 'global',
  'nonlocal', 'assert', 'except', 'raise', 'elif', 'is', 'None', 'True', 'False',
]);

const KEYWORD_RE = /\b(if|else|for|while|do|switch|case|return|new|delete|typeof|instanceof|void|in|of|and|or|not|def|class|fn|let|const|var|function|import|export|async|await|try|catch|throw|finally|yield|break|continue|default|public|private|protected|static|final|abstract|extends|implements|interface|enum|this|super|null|true|false|undefined|from|as|type|struct|impl|trait|use|mod|pub|mut|match|where|with|pass|lambda|del|global|nonlocal|assert|except|raise|elif|is|None|True|False)\b/g;

const SYMBOL_RE = /[+\-*/%&|^~<>=!?:;.,[\]{}()]/g;

const IDENT_RE = /\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g;

const LITERAL_RE = /\b\d+(?:\.\d+)?\b|"[^"]*"|'[^']*'|`[^`]*`/g;

/**
 * Halstead Metrics Pass
 *
 * Emits: halstead_volume, halstead_difficulty, halstead_effort, halstead_bugs
 *
 * Uses a regex-based tokenizer on the full source text.
 * Operators = keywords + symbol characters
 * Operands  = identifiers (excluding keywords) + numeric/string literals
 */
export class HalsteadMetricsPass implements MetricPass {
  readonly name = 'halstead-metrics';

  run(ctx: MetricContext): MetricValue[] {
    const { code } = ctx;

    // Collect operators
    const allKeywords: string[] = Array.from(code.matchAll(KEYWORD_RE), m => m[0]);
    const allSymbols:  string[] = Array.from(code.matchAll(SYMBOL_RE),  m => m[0]);

    // Collect operands: identifiers that are not keywords + literals
    const allIdents: string[] = Array.from(code.matchAll(IDENT_RE), m => m[0])
      .filter(t => !KEYWORDS.has(t));
    const allLiterals: string[] = Array.from(code.matchAll(LITERAL_RE), m => m[0]);

    const operators = [...allKeywords, ...allSymbols];
    const operands  = [...allIdents, ...allLiterals];

    const N1 = operators.length;
    const N2 = operands.length;
    const n1 = new Set(operators).size;
    const n2 = new Set(operands).size;

    const n = n1 + n2;
    const N = N1 + N2;

    if (n === 0 || n2 === 0) {
      return this.emitZero();
    }

    const V = N * Math.log2(n);                      // volume
    const D = (n1 / 2) * (N2 / n2);                 // difficulty
    const E = D * V;                                 // effort
    const B = Math.pow(E, 2 / 3) / 3000;            // bugs estimate

    return [
      {
        name: 'halstead_volume',
        category: 'complexity',
        value: parseFloat(V.toFixed(2)),
        unit: 'bits',
        iso_25010: 'Maintainability.Analysability',
        description: 'Halstead Volume (V = N × log₂ n)',
      },
      {
        name: 'halstead_difficulty',
        category: 'complexity',
        value: parseFloat(D.toFixed(2)),
        unit: 'count',
        iso_25010: 'Maintainability.Analysability',
        description: 'Halstead Difficulty (D = (n1/2) × (N2/n2))',
      },
      {
        name: 'halstead_effort',
        category: 'complexity',
        value: parseFloat(E.toFixed(2)),
        unit: 'count',
        iso_25010: 'Maintainability.Analysability',
        description: 'Halstead Effort (E = D × V)',
      },
      {
        name: 'halstead_bugs',
        category: 'complexity',
        value: parseFloat(B.toFixed(4)),
        unit: 'count',
        iso_25010: 'Maintainability.Faultlessness',
        description: 'Halstead Bug Estimate (B = E^(2/3) / 3000)',
      },
    ];
  }

  private emitZero(): MetricValue[] {
    return [
      { name: 'halstead_volume',     category: 'complexity', value: 0, unit: 'bits' },
      { name: 'halstead_difficulty', category: 'complexity', value: 0, unit: 'count' },
      { name: 'halstead_effort',     category: 'complexity', value: 0, unit: 'count' },
      { name: 'halstead_bugs',       category: 'complexity', value: 0, unit: 'count' },
    ];
  }
}
