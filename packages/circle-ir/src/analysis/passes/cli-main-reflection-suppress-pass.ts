/**
 * CliMainReflectionSuppressPass — cognium-dev #162 Option B
 *
 * Drops Java reflection `code_injection` sinks in files that look like
 * a fat-jar CLI tool's own artifact — files that ship a `main(String[])`
 * entry point AND carry no web-framework entry-point signal anywhere
 * in the file. The `main(String[])` on the same compilation unit *is*
 * the trust boundary; the caller is the OS shell that invoked the jar.
 *
 * Motivation (from the ticket):
 *
 *     // antlr/tool/.../TestRig.java — 5 reflection sinks reported HIGH
 *     public static void main(String[] args) throws Exception {
 *         TestRig testRig = new TestRig(args);
 *         ...
 *     }
 *     public void process() throws Exception {
 *         String lexerName = grammarName + "Lexer";
 *         ClassLoader cl = Thread.currentThread().getContextClassLoader();
 *         Class<? extends Lexer> lexerClass =
 *             cl.loadClass(lexerName).asSubclass(Lexer.class);   // sink
 *         Constructor<? extends Lexer> lexerCtor =
 *             lexerClass.getConstructor(CharStream.class);
 *         Lexer lexer = lexerCtor.newInstance((CharStream)null);  // sink
 *         ...
 *     }
 *
 * This is documented behaviour of ANTLR's `TestRig` developer CLI —
 * same shape as `javac`, `java -jar`, `python -m`. The tool's whole
 * purpose is "give me a grammar name from the command line and I'll
 * run it." Blocked 5/49 HIGH FPs in the top-100 Java harness.
 *
 * ## Signal
 *
 * Language MUST be Java. Per-file signal (all must hold):
 *
 *   1. Some type in the file declares a `main(String[])` method
 *      (matches `looksLikeMainMethod` in `entry-point-detection.ts`).
 *   2. NO type in the file carries a Tier-1 class-level web-framework
 *      annotation (`@RestController`, `@Controller`, `@Service`,
 *      `@Component`, `@Path`, `@WebServlet`, `@ServerEndpoint`,
 *      `@FeignClient`, `@Repository`).
 *   3. NO method in the file carries a Tier-1 method-level
 *      web-framework annotation (Spring `@*Mapping`, `@KafkaListener`,
 *      `@JmsListener`, JAX-RS `@GET/@POST/…`, `@Scheduled`, `@Path`,
 *      `@DataBoundConstructor`/`@DataBoundSetter`).
 *   4. NO type in the file extends a Tier-1 supertype (HttpServlet,
 *      GenericServlet, Filter, HandlerInterceptor, CommandLineRunner,
 *      SimpleChannelInboundHandler, etc.).
 *
 * ## Action
 *
 * When the signal fires, drop from the `SinkFilterResult.sinks` list
 * (the authoritative sink array consumed by `TaintPropagationPass` and
 * folded into `taint.sinks` by `analyzer.ts`) every sink whose
 * `type === 'code_injection'` AND `method` is a Java reflection
 * / ClassLoader surface method. The gate does NOT touch other
 * `code_injection` shapes: ScriptEngine.eval / GroovyShell.evaluate /
 * SpEL `parseExpression` remain flagged in CLI tools because they
 * evaluate scripts (a genuinely dangerous CLI misuse), not just class
 * names.
 *
 * ## Pipeline slot
 *
 * Runs after `SinkSemanticsPass` (so its curated-registry drops have
 * already fired) and before `TaintPropagationPass` (so the flow
 * generators never see the dropped sinks). Emits no findings.
 *
 * ## Pillar I / safety
 *
 * - Pure per-file heuristic; no LLM, no filesystem, no config knobs.
 * - False-negative-safe: any web-framework signal in the file
 *   (annotation OR supertype OR Tier-1 method annotation) disables
 *   the gate. Recall preserved for `@RestController` classes,
 *   `HttpServlet` subclasses, Netty handlers, Jenkins plugins, and
 *   Kafka/JMS listeners that happen to also expose a `main`.
 * - Reflection-only: `Runtime.exec`, `ProcessBuilder.start`,
 *   `Statement.execute`, `ObjectInputStream.readObject`, SpEL,
 *   Groovy, ScriptEngine — all unaffected.
 * - Java-only: non-Java sources fall through untouched.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { SinkFilterResult } from './sink-filter-pass.js';

export interface CliMainReflectionSuppressResult {
  /** Whether the fat-jar CLI signal fired for this file. */
  cliMainSignal: boolean;
  /** Number of reflection `code_injection` sinks dropped. */
  droppedCount: number;
}

/**
 * Java reflection + ClassLoader methods that produce `code_injection`
 * sinks via `configs/sinks/code_injection.yaml`. Simple-name match on
 * `sink.method`. Kept intentionally narrow — script-engine /
 * expression-language sinks (`eval`, `evaluate`, `parseExpression`,
 * `getBeanInfo`, `getEngineByName`) are NOT in this set, so those
 * still fire in CLI artifacts.
 */
const REFLECTION_SINK_METHODS: ReadonlySet<string> = new Set([
  'forName',
  'newInstance',
  'invoke',
  'getMethod',
  'getDeclaredMethod',
  'getConstructor',
  'getDeclaredConstructor',
  'loadClass',
  'defineClass',
]);

/**
 * Tier-1 class-level web-framework annotations. Simple-name match
 * (annotation strings in `TypeInfo.annotations` may include the `@`
 * prefix and generic args — we strip both). Any single match kills
 * the gate for this file.
 */
const TIER_1_CLASS_ANNOTATIONS: ReadonlySet<string> = new Set([
  // Spring MVC
  'RestController',
  'Controller',
  // Spring stereotype beans
  'Service',
  'Repository',
  'Component',
  // JAX-RS resource class
  'Path',
  // Servlet 3.0 annotation-based servlet
  'WebServlet',
  // JSR-356 WebSocket endpoint
  'ServerEndpoint',
  // Declarative HTTP client
  'FeignClient',
]);

/**
 * Tier-1 method-level web-framework annotations. Any single match
 * kills the gate.
 */
const TIER_1_METHOD_ANNOTATIONS: ReadonlySet<string> = new Set([
  // Spring MVC
  'RequestMapping',
  'GetMapping',
  'PostMapping',
  'PutMapping',
  'DeleteMapping',
  'PatchMapping',
  // Spring messaging / WebSocket
  'MessageMapping',
  'SubscribeMapping',
  // Spring messaging listeners
  'KafkaListener',
  'KafkaHandler',
  'RabbitListener',
  'RabbitHandler',
  'JmsListener',
  'StreamListener',
  // Spring Cloud AWS
  'SqsListener',
  'SqsHandler',
  // Spring application events
  'EventListener',
  // CRON / scheduled
  'Scheduled',
  // JAX-RS
  'Path',
  'GET',
  'POST',
  'PUT',
  'DELETE',
  'PATCH',
  'HEAD',
  'OPTIONS',
  // Jenkins Stapler form-binding
  'DataBoundConstructor',
  'DataBoundSetter',
]);

/**
 * Tier-1 supertypes whose subclasses declare framework entry points
 * via lifecycle methods (HttpServlet.doGet, ChannelHandler.channelRead,
 * CommandLineRunner.run, etc.). Simple-name match on
 * `TypeInfo.extends` and each `TypeInfo.implements[]` entry (generics
 * stripped).
 */
const TIER_1_SUPERTYPES: ReadonlySet<string> = new Set([
  'HttpServlet',
  'GenericServlet',
  'Filter',
  'HandlerInterceptor',
  'AsyncHandlerInterceptor',
  'CommandLineRunner',
  'ApplicationRunner',
  'SimpleChannelInboundHandler',
  'ChannelInboundHandler',
  'ChannelInboundHandlerAdapter',
  'ChannelDuplexHandler',
  'NettyRequestProcessor',
  'Converter',
  'SingleValueConverter',
  'ConverterMatcher',
  'AbstractReflectionConverter',
  'AbstractSingleValueConverter',
  'AbstractCollectionConverter',
]);

/**
 * Normalize an annotation string to its simple name. Handles `@Foo`,
 * `Foo`, `@Foo(...)`, `pkg.Foo`, and `Foo<T>` shapes. Returns the
 * bare identifier (`Foo`) for the lookup.
 */
function normalizeAnnotation(raw: string): string {
  let s = raw.trim();
  if (s.startsWith('@')) s = s.slice(1);
  const parenIdx = s.indexOf('(');
  if (parenIdx >= 0) s = s.slice(0, parenIdx);
  const genericIdx = s.indexOf('<');
  if (genericIdx >= 0) s = s.slice(0, genericIdx);
  const dotIdx = s.lastIndexOf('.');
  if (dotIdx >= 0) s = s.slice(dotIdx + 1);
  return s.trim();
}

/** Strip generics + package qualifier from a supertype reference. */
function normalizeSupertype(raw: string): string {
  let s = raw.trim();
  const genericIdx = s.indexOf('<');
  if (genericIdx >= 0) s = s.slice(0, genericIdx);
  const dotIdx = s.lastIndexOf('.');
  if (dotIdx >= 0) s = s.slice(dotIdx + 1);
  return s.trim();
}

/**
 * Detect the `main(String[] args)` entry-point shape. Static isn't
 * required by the JVM launcher spec strictly (some launchers accept
 * instance mains), but every real Java CLI uses `public static void
 * main(String[])`. We match on the parameter shape only — one string
 * array — matching `looksLikeMainMethod` in
 * `src/analysis/entry-point-detection.ts`.
 */
function isMainMethod(name: string, paramTypes: readonly (string | null)[]): boolean {
  if (name !== 'main') return false;
  if (paramTypes.length !== 1) return false;
  const t = paramTypes[0];
  if (!t) return false;
  const bare = t.replace(/\s+/g, '');
  return bare === 'String[]' || bare === 'java.lang.String[]';
}

export class CliMainReflectionSuppressPass
  implements AnalysisPass<CliMainReflectionSuppressResult>
{
  readonly name = 'cli-main-reflection-suppress';
  readonly category = 'security' as const;

  run(ctx: PassContext): CliMainReflectionSuppressResult {
    const { graph, language } = ctx;

    // Java-only gate. Non-Java IR falls through untouched.
    if (language !== 'java') {
      return { cliMainSignal: false, droppedCount: 0 };
    }

    const types = graph.ir.types;
    if (!types || types.length === 0) {
      return { cliMainSignal: false, droppedCount: 0 };
    }

    // Signal condition (1): main(String[]) present anywhere in file.
    let hasMain = false;
    // Disqualifiers (2), (3), (4): any Tier-1 web-framework signal.
    let hasFrameworkSignal = false;

    for (const type of types) {
      // (2) class-level annotations
      for (const ann of type.annotations) {
        if (TIER_1_CLASS_ANNOTATIONS.has(normalizeAnnotation(ann))) {
          hasFrameworkSignal = true;
          break;
        }
      }
      if (hasFrameworkSignal) break;

      // (4) supertype match — `extends` slot + every `implements` slot.
      if (type.extends && TIER_1_SUPERTYPES.has(normalizeSupertype(type.extends))) {
        hasFrameworkSignal = true;
        break;
      }
      for (const impl of type.implements) {
        if (TIER_1_SUPERTYPES.has(normalizeSupertype(impl))) {
          hasFrameworkSignal = true;
          break;
        }
      }
      if (hasFrameworkSignal) break;

      for (const method of type.methods) {
        // (3) method-level annotations
        for (const ann of method.annotations) {
          if (TIER_1_METHOD_ANNOTATIONS.has(normalizeAnnotation(ann))) {
            hasFrameworkSignal = true;
            break;
          }
        }
        if (hasFrameworkSignal) break;

        // (1) main(String[]) shape
        if (!hasMain) {
          const paramTypes = method.parameters.map((p) => p.type);
          if (isMainMethod(method.name, paramTypes)) {
            hasMain = true;
          }
        }
      }
      if (hasFrameworkSignal) break;
    }

    const cliMainSignal = hasMain && !hasFrameworkSignal;
    if (!cliMainSignal) {
      return { cliMainSignal: false, droppedCount: 0 };
    }

    // Drop reflection code_injection sinks in place. The authoritative
    // sink list in the real pipeline is `SinkFilterResult.sinks` — that
    // is what `analyzer.ts` assembles the final `taint.sinks` from and
    // what `TaintPropagationPass` / `InterproceduralPass` consume.
    // `graph.ir.taint.sinks` starts empty and is never populated by the
    // pipeline, so mutating it alone would be a no-op. Prefer the
    // sink-filter result; fall back to `graph.ir.taint.sinks` for
    // stand-alone unit-test harnesses that don't run `SinkFilterPass`.
    const sinks: import('../../types/index.js').TaintSink[] = ctx.hasResult('sink-filter')
      ? ctx.getResult<SinkFilterResult>('sink-filter').sinks
      : graph.ir.taint.sinks;

    let droppedCount = 0;
    const kept = sinks.filter((sink) => {
      if (sink.type !== 'code_injection') return true;
      if (!sink.method) return true;
      if (!REFLECTION_SINK_METHODS.has(sink.method)) return true;
      droppedCount++;
      return false;
    });

    if (droppedCount > 0) {
      sinks.length = 0;
      sinks.push(...kept);
    }

    return { cliMainSignal: true, droppedCount };
  }
}
