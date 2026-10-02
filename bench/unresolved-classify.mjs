// unresolved-classify.mjs — attach, to each site in an unresolved-audit.mjs sample,
// the evidence needed to put it in the fixed reason vocabulary (external · dynamic ·
// generated · parse-error · unsupported-language · unknown), and a PROPOSED reason.
// The proposal is a rule output, not a determination: every site is reviewed by a
// human and the adjudicated column is what the audit reports.
//
//   CIRCLE_IR=... node bench/unresolved-classify.mjs <repo> <audit.json> > classified.json
//
// Rule order (first match wins), with the evidence recorded per site:
//   1 parse-error            the file's own parse_status.success is false
//   2 unsupported-language   the site is in a language circle-ir does not parse
//   3 dynamic                reflective invocation: the receiver's type is a
//                            reflection type (Class/Method/Field/Constructor) or the
//                            receiver is a getClass()/forName() chain
//   4 generated              the target is an accessor/builder that only exists after
//                            annotation processing on a project type or a project
//                            supertype (Lombok @Getter/@Setter/@Data/@Builder/@Slf4j)
//   5 unknown                the target IS declared in the project and the resolver
//                            still did not answer — a resolver gap, not a scope limit
//   6 external               the target is declared in no project file and the
//                            receiver's type comes from a non-project import, a
//                            non-project supertype, or a non-project static import
//   7 unknown                none of the above
import { readFileSync, readdirSync, statSync } from 'fs';
import { join, relative } from 'path';
const { initAnalyzer, analyze } = await import(process.env.CIRCLE_IR);

const ROOT = process.argv[2];
const audit = JSON.parse(readFileSync(process.argv[3], 'utf8'));
const PROJECT_PKG = (process.env.PROJECT_PKG ?? 'org.owasp.webgoat,org.dummy').split(',');
const isProjectPkg = (fqn) => !!fqn && PROJECT_PKG.some(p => fqn.startsWith(p));

function walk(d, out = []) {
  for (const e of readdirSync(d).sort()) {
    const p = join(d, e), s = statSync(p);
    if (s.isDirectory()) { if (!['node_modules', '.git', 'target'].includes(e)) walk(p, out); }
    else if (p.endsWith('.java')) out.push(p);
  }
  return out;
}

const LOMBOK_ACCESSOR = new Set(['Getter', 'Setter', 'Data', 'Value']);
const LOMBOK_BUILDER = new Set(['Builder', 'SuperBuilder']);
const LOMBOK_ANY = new Set([...LOMBOK_ACCESSOR, ...LOMBOK_BUILDER, 'Slf4j', 'Log',
  'RequiredArgsConstructor', 'AllArgsConstructor', 'NoArgsConstructor',
  'EqualsAndHashCode', 'ToString', 'With', 'Accessors']);
// reflective *receiver* types; the method name alone is too ambiguous in Java
// (HttpServletRequest.getMethod, XPathFactory.newInstance, Object.getClass are not reflection)
const REFLECT_TYPES = new Set(['Class', 'Method', 'Field', 'Constructor', 'AccessibleObject',
  'MethodHandle', 'MethodHandles', 'Lookup', 'ClassLoader', 'Proxy', 'InvocationHandler']);

await initAnalyzer();
const files = walk(ROOT);
const types = new Map();      // simple name -> type record (last writer wins; see byFqn)
const byFqn = new Map();      // fqn -> type record, for same-simple-name collisions
const fileInfo = new Map();
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  const ir = await analyze(text, f, 'java');
  const pkg = ir.meta?.package || '';
  fileInfo.set(relative(ROOT, f), {
    pkg,
    staticImports: [...text.matchAll(/^\s*import\s+static\s+([\w.*]+)\s*;/gm)].map(m => m[1]),
    normalImports: [...text.matchAll(/^\s*import\s+(?!static)([\w.*]+)\s*;/gm)].map(m => m[1]),
  });
  for (const t of ir.types || []) {
    // annotations and the extends/implements clause as written, plus the field names
    const decl = new RegExp(
      `((?:^[ \\t]*@[\\w.]+(?:\\([\\s\\S]*?\\))?[ \\t]*$\\n)*)[ \\t]*(?:public |protected |private |abstract |final |static |sealed |non-sealed )*(class|interface|enum|record) ${t.name}\\b([^{]*)\\{`, 'm');
    const m = text.match(decl);
    const anns = m ? [...m[1].matchAll(/@(\w+)/g)].map(x => x[1]) : [];
    const clause = m ? m[3] : '';
    const supers = [...clause.matchAll(/\b([A-Z]\w*)\s*(?:<[^>]*>)?/g)].map(x => x[1])
      .filter(n => !['extends', 'implements'].includes(n));
    const fields = [...text.matchAll(/^[ \t]*(?:@[\w.]+(?:\([^)]*\))?[ \t]*)*(?:public |protected |private )?(?:static )?(?:final )?[\w.<>,\[\]? ]+?\s+(\w+)\s*(?:=|;)/gm)].map(x => x[1]);
    // field-level Lombok: `@Getter private String x;` / `@Setter` above or inline
    const getterFields = [...text.matchAll(/@Getter(?:\([^)]*\))?[^;\n]*?\b(\w+)\s*(?:=|;)/g)].map(x => x[1]);
    const setterFields = [...text.matchAll(/@Setter(?:\([^)]*\))?[^;\n]*?\b(\w+)\s*(?:=|;)/g)].map(x => x[1]);
    types.set(t.name, {
      file: relative(ROOT, f), fqn: pkg ? `${pkg}.${t.name}` : t.name, kind: m ? m[2] : 'class',
      annotations: anns, lombok: anns.filter(a => LOMBOK_ANY.has(a)),
      methods: (t.methods || []).map(x => x.name), fields: [...new Set(fields)],
      getterFields: [...new Set(getterFields)], setterFields: [...new Set(setterFields)],
      supers,
    });
    byFqn.set(pkg ? `${pkg}.${t.name}` : t.name, types.get(t.name));
  }
}

// Walk the project type hierarchy from a simple type name.
// Returns { declaredIn, generatedIn, lombok, exitedProjectAt, chain }
// A text-level index of every method declared in a project .java file, built
// WITHOUT circle-ir, so "is the target inside the searched scope?" does not depend
// on the extractor being audited. Over-approximates (it cannot tell which type owns
// a name); used only as evidence that a name is declared *somewhere* in the tree.
const textDeclared = new Map();   // method name -> [files]
const textRecords = new Map();    // record simple name -> { file, components, fqn }
for (const f of files) {
  const rel = relative(ROOT, f);
  const text = readFileSync(f, 'utf8');
  const pkg = (text.match(/^\s*package\s+([\w.]+)\s*;/m) ?? [])[1] ?? '';
  for (const m of text.matchAll(/^[ \t]*(?:@[\w.]+(?:\([^)]*\))?[ \t]*\n)*[ \t]*(?:public |protected |private |static |final |abstract |synchronized |default |native |<[^>]+> )*[\w.$<>\[\], ?]+\s+(\w+)\s*\([^;{]*\)\s*(?:throws [\w., ]+)?[{;]/gm)) {
    const n = m[1];
    if (['if', 'for', 'while', 'switch', 'catch', 'return', 'new', 'synchronized', 'record', 'class', 'try'].includes(n)) continue;
    if (!textDeclared.has(n)) textDeclared.set(n, []);
    textDeclared.get(n).push(rel);
  }
  for (const m of text.matchAll(/\brecord\s+(\w+)\s*\(([^)]*)\)/g)) {
    const comps = m[2].split(',').map(c => c.trim().split(/\s+/).pop()).filter(Boolean);
    textRecords.set(m[1], { file: rel, components: comps, fqn: pkg ? `${pkg}.${m[1]}` : m[1] });
    for (const c of comps) {   // a record's accessors are declared by the header
      if (!textDeclared.has(c)) textDeclared.set(c, []);
      textDeclared.get(c).push(rel + ' (record component)');
    }
  }
}

function lookupThroughHierarchy(simpleName, method, preferFqn) {
  const chain = [];
  const seen = new Set();
  // when the file's import names a specific FQN, start from that type, not from
  // whichever same-simple-name type happened to be indexed last
  const start = (preferFqn && byFqn.has(preferFqn)) ? byFqn.get(preferFqn) : null;
  let queue = start ? [start.fqn] : [simpleName];
  let exitedProjectAt = null;
  while (queue.length) {
    const n = queue.shift();
    if (!n || seen.has(n)) continue;
    seen.add(n);
    const t = byFqn.get(n) ?? types.get(n);
    if (!t) { if (n !== simpleName) exitedProjectAt ??= n; continue; }
    chain.push(t.fqn);
    if (t.methods.includes(method)) return { declaredIn: t.fqn, chain, exitedProjectAt };
    // Lombok accessor/builder that annotation processing would add to this type
    const g = lombokWouldGenerate(t, method);
    if (g) return { generatedIn: t.fqn, lombok: g, chain, exitedProjectAt };
    queue.push(...t.supers);
  }
  return { chain, exitedProjectAt };
}
function lombokWouldGenerate(t, method) {
  const has = (s) => t.annotations.some(a => s.has(a));
  const field = (name) => t.fields.includes(name);
  const lower = (s) => s.charAt(0).toLowerCase() + s.slice(1);
  if (has(LOMBOK_BUILDER) && (method === 'builder' || method === 'toBuilder')) return '@Builder';
  if (has(LOMBOK_ACCESSOR)) {
    if (/^get[A-Z]/.test(method) && field(lower(method.slice(3)))) return '@Getter/@Data on the type';
    if (/^is[A-Z]/.test(method) && field(lower(method.slice(2)))) return '@Getter/@Data on the type';
    if (/^set[A-Z]/.test(method) && field(lower(method.slice(3)))) return '@Setter/@Data on the type';
  }
  // field-level @Getter / @Setter
  if (/^get[A-Z]/.test(method) && (t.getterFields ?? []).includes(lower(method.slice(3)))) return '@Getter on the field';
  if (/^is[A-Z]/.test(method) && (t.getterFields ?? []).includes(lower(method.slice(2)))) return '@Getter on the field';
  if (/^set[A-Z]/.test(method) && (t.setterFields ?? []).includes(lower(method.slice(3)))) return '@Setter on the field';
  if (t.annotations.includes('Data') && ['equals', 'hashCode', 'toString', 'canEqual'].includes(method)) return '@Data';
  if (t.annotations.includes('Slf4j') && ['info', 'warn', 'error', 'debug', 'trace'].includes(method)) return '@Slf4j';
  return null;
}
function importFor(file, simpleName) {
  const fi = fileInfo.get(file); if (!fi || !simpleName) return null;
  const hit = fi.normalImports.find(i => i.split('.').pop() === simpleName);
  if (hit) return hit;
  if (types.has(simpleName)) return types.get(simpleName).fqn;
  return null;
}
function staticImportFor(file, name) {
  const fi = fileInfo.get(file); if (!fi) return null;
  return fi.staticImports.find(i => i.split('.').pop() === name)
      ?? fi.staticImports.find(i => i.endsWith('.*'))
      ?? null;
}

// The declared type of a simple-identifier receiver, found by text in the file and
// in its project supertypes' files. Needed because circle-ir leaves receiver_type
// null for a field inherited from a supertype.
const fileText = new Map();
for (const f of files) fileText.set(relative(ROOT, f), readFileSync(f, 'utf8'));
function declaredTypeOf(name, file, depth = 0) {
  if (!name || !/^[a-z_]\w*$/.test(name) || depth > 3) return null;
  const text = fileText.get(file);
  if (!text) return null;
  const m = text.match(new RegExp(`\\b([A-Z]\\w*)(?:<[^>]*>)?\\s+${name}\\s*(?:=|;|\\)|,)`));
  if (m) return m[1];
  const pt = primaryType(file);
  for (const sup of pt?.supers ?? []) {
    const st = types.get(sup);
    if (st) { const r = declaredTypeOf(name, st.file, depth + 1); if (r) return r; }
  }
  return null;
}

// the file's primary type, used for an implicit-`this` receiver. The type name need
// not match the file name (WebGoat's PathTraversalIntegrationTest.java declares
// `PathTraversalIT`), so fall back to whatever type the file declares.
const typesByFile = new Map();
for (const t of byFqn.values()) {
  if (!typesByFile.has(t.file)) typesByFile.set(t.file, []);
  typesByFile.get(t.file).push(t);
}
function primaryType(file) {
  const base = file.split('/').pop().replace(/\.java$/, '');
  return byFqn.get((fileInfo.get(file)?.pkg ? fileInfo.get(file).pkg + '.' : '') + base)
      ?? types.get(base)
      ?? (typesByFile.get(file) ?? [])[0]
      ?? null;
}

const out = audit.sample.map(s => {
  const looksCtor = /^[A-Z]/.test(s.method_name) && new RegExp(`new\\s+${s.method_name}\\b`).test(s.src_line);
  const rtypeImport = importFor(s.file, s.receiver_type);
  const ctorImport = looksCtor ? importFor(s.file, s.method_name) : null;
  const statImport = s.receiver === null && !looksCtor ? staticImportFor(s.file, s.method_name) : null;
  const h = s.receiver_type ? lookupThroughHierarchy(s.receiver_type, s.method_name, rtypeImport) : null;
  // implicit `this`: no receiver, not a constructor, not a static import
  const encl = (s.receiver === null && !looksCtor && !staticImportFor(s.file, s.method_name)) ? primaryType(s.file) : null;
  const hThis = encl ? lookupThroughHierarchy(encl.fqn.split('.').pop(), s.method_name, encl.fqn) : null;
  // a fluent chain rooted at a project @Builder type: `X.builder().field(..)`
  const chainRoot = String(s.receiver ?? '').match(/^([A-Z]\w*)\s*\.\s*builder\s*\(/);
  const builderType = chainRoot ? (byFqn.get(importFor(s.file, chainRoot[1]) ?? '') ?? types.get(chainRoot[1])) : null;
  const builderField = builderType && (builderType.annotations.includes('Builder') || builderType.annotations.includes('SuperBuilder'))
    && builderType.fields.includes(s.method_name) ? builderType : null;
  // the target name as declared anywhere in the tree, per the text index
  const textDecl = textDeclared.get(s.method_name) ?? null;
  const recvDeclType = s.receiver_type ?? declaredTypeOf(s.receiver, s.file);
  const recordOwner = recvDeclType && textRecords.has(recvDeclType) ? textRecords.get(recvDeclType) : null;
  const recordHere = textRecords.get(s.method_name) ?? null;
  // the receiver as a reflective expression
  const reflectRecv = REFLECT_TYPES.has(s.receiver_type ?? '')
    || /\bgetClass\s*\(\s*\)\s*\.\s*$|\.class\s*\.\s*$|Class\.forName/.test(String(s.receiver ?? ''))
    || ['forName', 'setAccessible', 'getDeclaredMethod', 'getDeclaredField', 'getDeclaredConstructor'].includes(s.method_name);

  let reason = 'unknown', why = [], ambiguous = false;
  if (s.parse_ok === false) { reason = 'parse-error'; why.push('the file\'s parse_status.success is false'); }
  else if (reflectRecv) { reason = 'dynamic'; why.push(`reflective invocation (receiver type ${s.receiver_type ?? 'n/a'}, receiver ${JSON.stringify(s.receiver)?.slice(0, 50)})`); }
  else if (looksCtor && types.has(s.method_name)) { reason = 'unknown'; why.push(`constructor of project type ${types.get(s.method_name).fqn} — the target is inside the searched scope; the resolver has no constructor path`); }
  else if (looksCtor) { reason = 'external'; why.push(`constructor of ${ctorImport ?? s.method_name + ' (no project declaration, no matching import)'}`); }
  else if (builderField) { reason = 'generated'; why.push(`${s.method_name} is a builder setter that @Builder generates on the project type ${builderField.fqn}; no source declaration exists`); }
  else if (h?.generatedIn) { reason = 'generated'; why.push(`${h.generatedIn} is a project type whose ${h.lombok} would generate ${s.method_name}; no source declaration exists`); }
  else if (hThis?.generatedIn) { reason = 'generated'; why.push(`implicit this: ${hThis.generatedIn} is a project type whose ${hThis.lombok} would generate ${s.method_name}; no source declaration exists`); }
  else if (recordOwner) { reason = 'unknown'; why.push(`the receiver's type ${recordOwner.fqn} is a Java record declared at ${recordOwner.file}; circle-ir's Java extractor emits NO type for a record, so the target is inside the searched scope but invisible to the symbol table — extractor gap`); }
  else if (recordHere && s.receiver === null) { reason = 'unknown'; why.push(`${s.method_name} names a Java record (${recordHere.fqn}) inside the searched scope; the extractor emits no type for a record — extractor gap`); }
  else if (h?.declaredIn) { reason = 'unknown'; why.push(`${h.declaredIn}.${s.method_name} IS declared in the searched scope — resolver gap (hierarchy chain ${h.chain.join(' <- ')})`); }
  else if (hThis?.declaredIn) { reason = 'unknown'; why.push(`implicit this: ${hThis.declaredIn}.${s.method_name} IS declared in the searched scope — resolver gap`); }
  else if (h?.exitedProjectAt) { reason = 'external'; why.push(`${s.method_name} is declared in no project type on the chain ${h.chain.join(' <- ')}, which leaves the project at ${h.exitedProjectAt}`); }
  else if (rtypeImport && !isProjectPkg(rtypeImport)) { reason = 'external'; why.push(`receiver type imported from ${rtypeImport}`); }
  else if (statImport && !isProjectPkg(statImport)) { reason = 'external'; why.push(`statically imported from ${statImport}`); }
  else if (statImport && isProjectPkg(statImport)) { reason = 'unknown'; why.push(`statically imported from project ${statImport} — resolver gap`); }
  else if (s.name_declared_in_project) { reason = 'unknown'; why.push(`${s.method_name} IS declared somewhere in the searched scope — resolver gap (receiver un-typed: ${JSON.stringify(s.receiver)?.slice(0, 70)})`); }
  // The text index over-approximates: it cannot tell which type owns a name, and a
  // fluent call written across lines can look like a declaration. It is therefore
  // believed only where the target must be the project's: an implicit-`this` or
  // same-file static call in a file that declares the name.
  else if (textDecl && s.receiver === null && textDecl.some(f => f.startsWith(s.file))) {
    reason = 'unknown';
    why.push(`${s.method_name} is declared in this very file (${s.file}) yet is absent from circle-ir's symbol table — extractor gap`);
  }
  else if (textDecl) {
    reason = 'external';
    why.push(`the method name is absent from circle-ir's symbol table; the independent text index hits ${[...new Set(textDecl)].slice(0, 2).join(', ')}, but the receiver here is not of that type — adjudicated external`);
    ambiguous = true;
  }
  else { reason = 'external'; why.push('the method name is declared in no project file (circle-ir symbol table and the independent text index agree) and the receiver type is not a project type'); }

  return { ...s, looks_ctor: looksCtor, rtypeImport, ctorImport, statImport,
    hierarchy: h, hierarchy_this: hThis, text_declared_in: textDecl ? [...new Set(textDecl)] : null,
    receiver_declared_type: recvDeclType, record_owner: recordOwner,
    human_adjudicated: ambiguous, proposed: reason, why: why.join('; ') };
});

console.log(JSON.stringify({ meta: { ...audit.meta, project_pkgs: PROJECT_PKG }, sample: out }, null, 1));
