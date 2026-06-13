/**
 * Pass #91: spring4shell (category: security, CWE-94)
 *
 * Detects the Spring4Shell (CVE-2022-22965) data-binding RCE pattern in
 * Spring MVC controllers. The vulnerable shape is a controller handler
 * method that takes a complex POJO parameter without an explicit binding
 * annotation:
 *
 *   @Controller
 *   public class Foo {
 *     @RequestMapping("/bar")
 *     public String bar(MyBean bean) { ... }   // implicit form-data binding
 *   }
 *
 * Spring's WebDataBinder walks the parameter's class graph and populates
 * setters from request parameters using reflection. CVE-2022-22965 abuses
 * this chain (`class.module.classLoader.resources.context...`) to write
 * attacker-controlled values into the Tomcat AccessLogValve and achieve
 * RCE. The vulnerability is mitigated by:
 *   - Using `@RequestBody` (JSON binding via Jackson, no DataBinder)
 *   - Using `@RequestParam` / `@PathVariable` (scalar binding only)
 *   - Restricting bindable fields via `@InitBinder` + `setAllowedFields`
 *
 * This pass is a PATTERN PASS (not a taint pass): it inspects controller
 * method signatures directly. The existing `code-injection` pass (#11)
 * already covers explicit `DataBinder.bind()` / `DataBinder.setPropertyValues()`
 * sink calls — Spring4Shell-vulnerable code typically does NOT make those
 * calls (Spring does it implicitly), so a taint flow alone misses it.
 *
 * False-positive control:
 *   - Only fires when the class is a Spring MVC controller (@Controller,
 *     @RestController, or @ControllerAdvice).
 *   - Only fires on methods with a route annotation (@RequestMapping or
 *     @GetMapping / @PostMapping / @PutMapping / @DeleteMapping /
 *     @PatchMapping).
 *   - Only fires on parameters with NO binding annotation. Any
 *     @RequestBody / @RequestParam / @PathVariable / @ModelAttribute /
 *     @RequestHeader / @CookieValue / @MatrixVariable / @Valid /
 *     @Validated on the parameter suppresses the finding.
 *   - Skips framework parameter types (HttpServletRequest, Model,
 *     Principal, MultipartFile, etc.) where Spring resolves the value
 *     directly without form-data binding.
 *   - Skips primitives, boxed primitives, String, and standard collection
 *     types (those use scalar conversion, not WebDataBinder).
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { MethodInfo, ParameterInfo, TypeInfo } from '../../types/index.js';

export interface Spring4ShellPassResult {
  /** Number of controller methods inspected. */
  controllerMethodsScanned: number;
  /** Number of findings emitted. */
  findingsEmitted: number;
}

/** Spring MVC class-level controller annotations. */
const CONTROLLER_ANNOTATIONS = new Set([
  'Controller',
  'RestController',
  'ControllerAdvice',
  'RestControllerAdvice',
]);

/** Spring MVC method-level route annotations. */
const ROUTE_ANNOTATIONS = new Set([
  'RequestMapping',
  'GetMapping',
  'PostMapping',
  'PutMapping',
  'DeleteMapping',
  'PatchMapping',
]);

/**
 * Parameter binding annotations that suppress the finding. If any of these
 * appear on a parameter, Spring uses an explicit (safe) binding path rather
 * than WebDataBinder's form-data reflection.
 */
const BINDING_ANNOTATIONS = new Set([
  'RequestBody',     // JSON via Jackson (no DataBinder)
  'RequestParam',    // scalar binding
  'PathVariable',    // scalar binding
  'RequestHeader',   // scalar binding
  'CookieValue',     // scalar binding
  'MatrixVariable',  // scalar binding
  'ModelAttribute',  // explicit form binding — user opted in
  'Valid',           // typically paired with @RequestBody / @ModelAttribute
  'Validated',
  'RequestPart',     // multipart, explicit
  'SessionAttribute',
  'RequestAttribute',
]);

/**
 * Framework-provided parameter types Spring resolves directly (not via
 * WebDataBinder). Comparing the *simple* type name only — the FQN check
 * would require receiver-type resolution and adds little.
 */
const FRAMEWORK_PARAM_TYPES = new Set([
  // Servlet / HTTP
  'HttpServletRequest', 'HttpServletResponse', 'ServletRequest', 'ServletResponse',
  'HttpSession', 'ServletContext', 'Cookie',
  // Spring MVC plumbing
  'Model', 'ModelMap', 'ModelAndView', 'Map',
  'BindingResult', 'Errors',
  'RedirectAttributes', 'SessionStatus',
  'WebRequest', 'NativeWebRequest', 'ServletWebRequest',
  'UriComponentsBuilder', 'UriBuilder',
  'HttpEntity', 'RequestEntity', 'ResponseEntity',
  'HttpHeaders',
  'InputStream', 'OutputStream', 'Reader', 'Writer',
  // Reactive
  'ServerHttpRequest', 'ServerHttpResponse', 'ServerWebExchange',
  // Security / locale
  'Principal', 'Authentication', 'Locale', 'TimeZone', 'ZoneId',
  // Multipart
  'MultipartFile', 'Part',
  // Misc
  'TimeZone',
]);

/**
 * Simple/primitive Java types that Spring resolves via scalar conversion,
 * never via WebDataBinder reflection. (For these, omitting @RequestParam is
 * a separate bug but not a Spring4Shell vector.)
 */
const SIMPLE_JAVA_TYPES = new Set([
  // Primitives
  'boolean', 'byte', 'char', 'short', 'int', 'long', 'float', 'double', 'void',
  // Boxed primitives
  'Boolean', 'Byte', 'Character', 'Short', 'Integer', 'Long', 'Float', 'Double',
  // Standard scalar-ish types
  'String', 'CharSequence',
  'BigInteger', 'BigDecimal',
  'UUID',
  // Date/time (Spring binds these via ConversionService, not DataBinder)
  'Date', 'Calendar', 'Instant', 'LocalDate', 'LocalTime', 'LocalDateTime',
  'OffsetDateTime', 'OffsetTime', 'ZonedDateTime', 'Duration', 'Period',
  // Collections — first-class scalar list binding (?names=a&names=b)
  'List', 'Set', 'Collection', 'Iterable', 'Optional',
  // Arrays (handled by suffix check below)
]);

export class Spring4ShellPass implements AnalysisPass<Spring4ShellPassResult> {
  readonly name = 'spring4shell';
  readonly category = 'security' as const;

  run(ctx: PassContext): Spring4ShellPassResult {
    const { graph, language } = ctx;

    // Java-only pattern; no value running on other languages.
    if (language !== 'java') {
      return { controllerMethodsScanned: 0, findingsEmitted: 0 };
    }

    const file = graph.ir.meta.file;
    let scanned = 0;
    let emitted = 0;

    for (const type of graph.ir.types) {
      if (!isController(type)) continue;

      for (const method of type.methods) {
        if (!isRouteHandler(method)) continue;
        scanned++;

        for (const param of method.parameters) {
          if (!isVulnerableParameter(param)) continue;

          ctx.addFinding({
            id: `${this.name}-${file}-${method.start_line}-${param.name}`,
            pass: this.name,
            category: this.category,
            rule_id: this.name,
            cwe: 'CWE-94',
            severity: 'high',
            level: 'error',
            message: `Spring MVC controller method '${type.name}.${method.name}' binds parameter '${param.name}' of type '${param.type ?? '?'}' via implicit form-data binding (no @RequestBody / @RequestParam / @ModelAttribute) — vulnerable to Spring4Shell (CVE-2022-22965) class-graph RCE on Spring < 5.3.18 / 5.2.20`,
            file,
            line: param.line ?? method.start_line,
            fix: 'Annotate the parameter with @RequestBody (JSON) or @ModelAttribute + @InitBinder/setAllowedFields whitelisting, upgrade Spring to ≥ 5.3.18 / 5.2.20, and ensure JDK is patched.',
            evidence: {
              controller_class: type.name,
              controller_annotations: type.annotations,
              method: method.name,
              method_annotations: method.annotations,
              parameter_name: param.name,
              parameter_type: param.type,
            },
          });
          emitted++;
        }
      }
    }

    return { controllerMethodsScanned: scanned, findingsEmitted: emitted };
  }
}

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

/**
 * The annotation strings stored on IR types/methods/params are the raw
 * annotation text without the leading `@`, possibly with arguments:
 *   "Controller"
 *   "RequestMapping(\"/foo\")"
 *   "GetMapping(value = \"/foo\", method = RequestMethod.GET)"
 * We match on the head name only.
 */
function annotationHead(annotation: string): string {
  const parenIdx = annotation.indexOf('(');
  return parenIdx >= 0 ? annotation.slice(0, parenIdx) : annotation;
}

function hasAnnotation(annotations: readonly string[], names: ReadonlySet<string>): boolean {
  for (const a of annotations) {
    if (names.has(annotationHead(a))) return true;
  }
  return false;
}

function isController(type: TypeInfo): boolean {
  return hasAnnotation(type.annotations, CONTROLLER_ANNOTATIONS);
}

function isRouteHandler(method: MethodInfo): boolean {
  return hasAnnotation(method.annotations, ROUTE_ANNOTATIONS);
}

function isVulnerableParameter(param: ParameterInfo): boolean {
  // Any binding annotation makes Spring use a specific (safe) resolver.
  if (hasAnnotation(param.annotations, BINDING_ANNOTATIONS)) return false;

  // Parameter must have a type to reason about.
  if (!param.type) return false;

  const type = stripGenerics(param.type).trim();
  if (!type) return false;

  // Arrays of primitives / strings are scalar (binding-safe).
  if (type.endsWith('[]')) {
    const elem = type.slice(0, -2).trim();
    return !SIMPLE_JAVA_TYPES.has(elem) && isPotentialPojo(elem);
  }

  // Skip simple types — scalar conversion, no WebDataBinder reflection.
  if (SIMPLE_JAVA_TYPES.has(type)) return false;

  // Skip framework-provided types Spring resolves directly.
  if (FRAMEWORK_PARAM_TYPES.has(type)) return false;

  // Reject obvious non-POJOs (lowercase first letter = primitive or unknown).
  if (!isPotentialPojo(type)) return false;

  return true;
}

/** Strip generic parameters: `Map<String, List<Foo>>` → `Map`. */
function stripGenerics(type: string): string {
  const ltIdx = type.indexOf('<');
  return ltIdx >= 0 ? type.slice(0, ltIdx) : type;
}

/**
 * Conservative POJO heuristic: starts with an uppercase ASCII letter
 * (Java class naming convention). Skips primitives (always lowercase) and
 * type-parameter names like `T` only if they're a single character — but
 * we keep `T` as potentially-vulnerable because real classes can be one
 * letter too (rare, but legal). The framework / simple-type sets above
 * filter the practically interesting cases.
 */
function isPotentialPojo(type: string): boolean {
  if (type.length === 0) return false;
  const first = type.charCodeAt(0);
  return first >= 65 /* A */ && first <= 90 /* Z */;
}
