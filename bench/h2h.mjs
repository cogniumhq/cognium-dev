import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { execFileSync } from 'child_process';
const { initAnalyzer, analyze, buildSymbolTable, buildCrossFileResolver, TypeHierarchyResolver } = await import(process.env.CIRCLE_IR);
const ROOT = process.argv[2];
const RG = process.env.RG || 'rg';   // a ripgrep binary on PATH, or point RG at one
function walk(d, out=[]) { for (const e of readdirSync(d)) { const p = join(d,e); const s = statSync(p); if (s.isDirectory()) { if (!['node_modules','.git','target'].includes(e)) walk(p,out); } else if (p.endsWith('.java')) out.push(p);} return out; }
const files = walk(ROOT); await initAnalyzer();
const irs=[]; for (const f of files) irs.push({path:f, ir: await analyze(readFileSync(f,'utf8'), f, 'java')});
const st=buildSymbolTable(irs); const th=new TypeHierarchyResolver(); for (const {ir,path} of irs) th.addFromIR(ir,path); const res=buildCrossFileResolver(irs,st,th);
const targets = ['org.owasp.webgoat.container.assignments.AttackResultBuilder.failed','org.owasp.webgoat.container.i18n.Messages.getMessage','org.owasp.webgoat.integration.IntegrationTest.checkAssignment','org.owasp.webgoat.container.LessonDataSource.getConnection','org.owasp.webgoat.lessons.challenges.challenge7.MD5.decode','org.owasp.webgoat.webwolf.jwt.JWTToken.parse','org.owasp.webgoat.lessons.openredirect.OpenRedirectMitigationCheck.check','org.owasp.webgoat.container.users.UserProgressRepository.findByUser','org.owasp.webgoat.container.users.WebGoatUser.equals','org.owasp.webgoat.lessons.clientsidefiltering.CheckoutCodes.get','org.owasp.webgoat.container.session.LessonSession.getValue','org.owasp.webgoat.container.lessons.Lesson.getName'];
const rows=[];
for (const fqn of targets) {
  const name = fqn.split('.').pop(); const cls = fqn.split('.').slice(-2)[0];
  const t1=performance.now(); let out; try { out=execFileSync(RG,['-n','--no-heading',`\\b${name}\\s*\\(`,ROOT,'-g','*.java'],{encoding:'utf8',maxBuffer:1<<26}); } catch(e){out=e.stdout||'';} const rg_ms=performance.now()-t1;
  const lines=out.split('\n').filter(Boolean);
  const t2=performance.now(); const callers=res.findCallers(fqn); const q_ms=performance.now()-t2;
  const kinds={}; let recv_same=0, recv_unknown=0, recv_other=0;
  for (const c of callers){ kinds[c.resolution]=(kinds[c.resolution]||0)+1; const rt=c.call.receiver_type; if (rt==null) recv_unknown++; else if (rt===cls) recv_same++; else recv_other++; }
  const payload = callers.map(c=>`${c.sourceFile.replace(ROOT,'')}:${c.call.location?.line} ${c.resolution}`).join('\n');
  rows.push({target: cls+'.'+name, rg_hits: lines.length, rg_files: new Set(lines.map(l=>l.split(':')[0])).size, rg_KB:+(out.length/1024).toFixed(1), rg_ms: rg_ms|0, callers: callers.length, kinds, recv_same, recv_other, recv_unknown, q_ms:+q_ms.toFixed(1), out_KB:+(payload.length/1024).toFixed(1)});
}
console.table(rows);
