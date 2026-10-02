import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { execFileSync } from 'child_process';
const { initAnalyzer, analyze, buildSymbolTable, buildCrossFileResolver, TypeHierarchyResolver } = await import(process.env.CIRCLE_IR);
const ROOT = process.argv[2];
const RG = process.env.RG || 'rg';   // a ripgrep binary on PATH, or point RG at one
function walk(d, out=[]) { for (const e of readdirSync(d)) { const p = join(d,e); const s = statSync(p); if (s.isDirectory()) { if (!['node_modules','.git','target'].includes(e)) walk(p,out); } else if (p.endsWith('.java')) out.push(p);} return out; }
const files = walk(ROOT); await initAnalyzer();
const irs=[]; for (const f of files) irs.push({path:f, ir: await analyze(readFileSync(f,'utf8'), f, 'java')});
function build(){ const st=buildSymbolTable(irs); const th=new TypeHierarchyResolver(); for (const {ir,path} of irs) th.addFromIR(ir,path); return buildCrossFileResolver(irs,st,th); }
let res=build();
const big = irs.map(x=>({...x, n: x.ir.calls?.length||0})).sort((a,b)=>b.n-a.n)[0];
let tot=0; for (let i=0;i<10;i++){ const t=performance.now(); big.ir = await analyze(readFileSync(big.path,'utf8'), big.path, 'java'); res=build(); tot+=performance.now()-t; }
console.log('incremental re-parse(largest file, '+big.n+' calls)+rebuild index avg ms', (tot/10).toFixed(1));
const targets = ['org.owasp.webgoat.container.assignments.AttackResultBuilder.failed','org.owasp.webgoat.container.i18n.Messages.getMessage','org.owasp.webgoat.container.LessonDataSource.getConnection','org.owasp.webgoat.lessons.challenges.challenge7.MD5.decode','org.owasp.webgoat.container.users.WebGoatUser.equals','org.owasp.webgoat.lessons.clientsidefiltering.CheckoutCodes.get','org.owasp.webgoat.container.lessons.Lesson.getName','org.owasp.webgoat.container.session.LessonSession.getValue'];
const rows=[];
for (const fqn of targets){ const name=fqn.split('.').pop(); const cls=fqn.split('.').slice(-2)[0];
  let out=''; try{ out=execFileSync(RG,['-n','--no-heading',`\\b${name}\\s*\\(`,ROOT,'-g','*.java'],{encoding:'utf8',maxBuffer:1<<26}); }catch(e){out=e.stdout||'';}
  const rg=out.split('\n').filter(Boolean).length;
  const all=res.findCallers(fqn);
  const exact=all.filter(c=>c.resolution==='exact').length;
  const contradicted=all.filter(c=>c.call.receiver_type!=null && c.call.receiver_type!==cls && c.resolution!=='exact').length;
  rows.push({target:cls+'.'+name, rg_hits:rg, resolver_claims:all.length, exact, unverified_name_only:all.length-exact-contradicted, contradicted_by_receiver_type:contradicted});
}
console.table(rows);
