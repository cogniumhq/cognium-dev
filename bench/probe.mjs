import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
const { initAnalyzer, analyze, buildSymbolTable, buildCrossFileResolver, TypeHierarchyResolver } = await import(process.env.CIRCLE_IR);
const ROOT = process.argv[2];
function walk(d, out=[]) { for (const e of readdirSync(d)) { const p = join(d,e); const s = statSync(p); if (s.isDirectory()) { if (!['node_modules','.git','target'].includes(e)) walk(p,out); } else if (p.endsWith('.java')) out.push(p);} return out; }
const files = walk(ROOT);
let t=performance.now(); await initAnalyzer(); console.log('init ms', (performance.now()-t)|0);
t=performance.now(); const irs=[]; for (const f of files) irs.push({path:f, ir: await analyze(readFileSync(f,'utf8'), f, 'java')}); console.log('parse ms', (performance.now()-t)|0, 'files', files.length);
t=performance.now(); const st=buildSymbolTable(irs); const th=new TypeHierarchyResolver(); for (const {ir,path} of irs) th.addFromIR(ir,path); const res=buildCrossFileResolver(irs,st,th); console.log('index ms', (performance.now()-t)|0);
t=performance.now(); let total=0, resolved=0, byTarget=new Map(), resKinds={};
for (const {ir,path} of irs) for (const c of ir.calls||[]) { total++; const r=res.resolveCall(c,path); if (r){ resolved++; resKinds[r.resolution]=(resKinds[r.resolution]||0)+1; byTarget.set(r.targetMethod,(byTarget.get(r.targetMethod)||0)+1);} }
console.log('resolve-all ms', (performance.now()-t)|0, 'calls', total, 'resolved', resolved, resKinds);
console.log(JSON.stringify([...byTarget.entries()].sort((a,b)=>b[1]-a[1]).slice(0,40)));
