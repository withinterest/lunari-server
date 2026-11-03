import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {WalletAuthError} from '../lib/firebase-wallet-auth.js';
import {QA_PURCHASE_TARGET as t} from '../lib/purchase-qa-runtime.js';
import {createQaHttpDiagnostic,runHttpSelectOne,QA_HTTP_DIAGNOSTIC_QUERY,createQaHttpDeadline} from '../lib/qa-http-db-diagnostic.js';
import {createQaHttpDiagnosticHandler} from '../api/qa/diagnostics/db-http.js';
const roles={issuer:'lunari_wallet_v2_issuer_sql_qa',executor:'lunari_wallet_v2_exec_sql_qa'};
const preview='qa-diagnostic.example.test';
const url=role=>`postgresql://${role}:PUBLIC_TEST_PASSWORD@${t.host}/neondb?sslmode=verify-full&channel_binding=require`;
const env={VERCEL:'1',VERCEL_ENV:'preview',NODE_ENV:'production',VERCEL_URL:preview,WALLET_ENV:'qa',FIREBASE_PROJECT_ID:'lunari-dev',WALLET_V2_QA_READ_ENABLED:'1',WALLET_V2_QA_HTTP_DIAGNOSTIC_ENABLED:'1',WALLET_V2_QA_READ_ALLOWED_UIDS:'["public-fixture-user"]',NEON_API_KEY:'PUBLIC_TEST_API_KEY',WALLET_V2_QA_READ_ISSUER_DATABASE_URL:url(roles.issuer),WALLET_V2_QA_READ_EXECUTOR_DATABASE_URL:url(roles.executor)};
const req=()=>({method:'GET',url:'/api/qa/diagnostics/db-http',headers:{host:preview,'x-forwarded-proto':'https','x-vercel-forwarded-for':'192.0.2.1',authorization:'Bearer PUBLIC_TEST_TOKEN'}});
const res=()=>({headers:{},setHeader(k,v){this.headers[k]=v;},status(n){this.statusCode=n;return this;},json(body){this.body=body;return this;}});
const success={ok:true,issuer:{ok:true,code:'HTTP_DIAGNOSTIC_OK'},executor:{ok:true,code:'HTTP_DIAGNOSTIC_OK'}};
function handler(over={}){return createQaHttpDiagnosticHandler({env,verifyToken:async()=>({uid:'public-fixture-user'}),diagnose:async()=>success,...over});}
function fixture({change={},fault,slow=false}={}){
 const calls=[],queries=[],transportSignals=[];
 const fetcher=async u=>{
  const part=u.split('/projects/'+t.projectId)[1];calls.push(part);
  if(fault==='issuer-metadata'&&calls.length===1)throw Error('PRIVATE_SENTINEL');
  let body;
  if(part==='')body={project:{id:t.projectId,name:t.projectName}};
  else if(part==='/branches/'+t.branchId)body={branch:{id:t.branchId,name:t.branchName,project_id:t.projectId,parent_id:t.productionBranchId,default:false,protected:false}};
  else if(part==='/branches/'+t.productionBranchId)body={branch:{id:t.productionBranchId,name:'production',project_id:t.projectId,default:true}};
  else if(part==='/endpoints/'+t.endpointId)body={endpoint:{id:t.endpointId,branch_id:t.branchId,project_id:t.projectId,host:t.host,type:'read_write'}};
  else if(part==='/endpoints')body={endpoints:[{id:t.endpointId,branch_id:t.branchId,host:t.host},{id:t.productionEndpointId,branch_id:t.productionBranchId,host:'public-production-fixture.invalid'}]};
  else assert.fail('Unexpected metadata request');
  return{ok:true,json:async()=>body};
 };
 const driver={neonConfig:{fetchEndpoint:'https://'+t.host.replace(/^[^.]+\./,'api.')+'/sql'},neon(connection,options){
  const parsed=new URL(connection),kind=decodeURIComponent(parsed.username)===roles.issuer?'issuer':'executor';
  assert.equal(parsed.searchParams.get('sslmode'),'verify-full');assert.equal(parsed.searchParams.get('channel_binding'),'require');
  assert.equal(options.fetchOptions.redirect,'error');assert(options.fetchOptions.signal instanceof AbortSignal);transportSignals.push(options.fetchOptions.signal);
  const query={query(text,params){assert.equal(text,'SELECT 1');assert.deepEqual(params,[]);queries.push(kind);return{text,params};},async transaction(list,opts){
   assert.deepEqual(list,[{text:'SELECT 1',params:[]}]);assert.deepEqual(opts,{readOnly:true});
   if(slow&&kind==='issuer')return new Promise(()=>{});
   if(fault===kind)throw Object.assign(Error('PRIVATE_SENTINEL'),{detail:connection,stack:'PRIVATE_STACK'});
   return[[{'?column?':1}]];
  }};return query;
 }};
 return{driver,calls,queries,transportSignals,run:createQaHttpDiagnostic({env:{...env,...change},fetcher,loadHttp:async()=>driver,timeoutMs:10,metadataTimeoutMs:100})};
}
for(const change of [{WALLET_V2_QA_HTTP_DIAGNOSTIC_ENABLED:undefined},{VERCEL_ENV:'production'},{VERCEL:undefined},{WALLET_ENV:'production'},{WALLET_V2_QA_READ_ENABLED:undefined}])test('gate refuses '+Object.keys(change),async()=>{
 const r=res();await handler({env:{...env,...change},verifyToken:()=>assert.fail('No auth'),diagnose:()=>assert.fail('No query')})(req(),r);assert.equal(r.statusCode,503);
});
test('missing auth and rejected token never query',async()=>{
 let r=res(),request=req();delete request.headers.authorization;
 await handler({diagnose:()=>assert.fail('No query')})(request,r);assert.equal(r.statusCode,401);
 r=res();await handler({verifyToken:async()=>{throw new WalletAuthError('INVALID_AUTH_TOKEN',401);},diagnose:()=>assert.fail('No query')})(req(),r);assert.equal(r.statusCode,401);
});
test('UID allowlist retained',async()=>{const r=res();await handler({verifyToken:async()=>({uid:'not-allowed'}),diagnose:()=>assert.fail('No query')})(req(),r);assert.equal(r.statusCode,403);});
for(const change of [{headers:{host:'wrong.invalid'}},{query:{uid:'fixture'}},{body:{sql:'DELETE'}},{url:'/api/qa/diagnostics/db-http?role=owner'},{method:'POST'}])test('request inputs cannot choose query or role '+Object.keys(change),async()=>{const r=res();await handler({diagnose:()=>assert.fail('No query')})({...req(),...change},r);assert([400,403,405].includes(r.statusCode));});
for(const kind of ['ISSUER','EXECUTOR'])for(const transform of [s=>s.replace(t.host,'wrong.invalid'),s=>s.replace('lunari_wallet_v2_', 'owner_wallet_'),s=>s.replace('verify-full','require'),s=>s+'&sslrootcert=private',s=>s.replace('channel_binding=require','channel_binding=disable')])test('invalid target or options refused '+kind+' '+String(transform).length,async()=>{
 const key='WALLET_V2_QA_READ_'+kind+'_DATABASE_URL',f=fixture({change:{[key]:transform(env[key])}});await assert.rejects(f.run());assert.equal(f.calls.length,0);assert.equal(f.queries.length,0);
});
test('each role runs only SELECT 1 in read-only transaction',async()=>{const f=fixture();assert.deepEqual(await f.run(),success);assert.deepEqual(f.queries,['issuer','executor']);assert.equal(f.calls.length,10);assert.equal(QA_HTTP_DIAGNOSTIC_QUERY,'SELECT 1');});
for(const fault of ['issuer','executor'])test('role failure isolated '+fault,async()=>{const f=fixture({fault}),r=await f.run();assert.equal(r.ok,false);assert.equal(r[fault].code,'HTTP_DIAGNOSTIC_QUERY_FAILED');assert(r[fault==='issuer'?'executor':'issuer'].ok);assert(!JSON.stringify(r).includes('PRIVATE'));assert(!JSON.stringify(r).includes('postgres'));});
test('metadata failure prevents only affected role query',async()=>{const f=fixture({fault:'issuer-metadata'}),r=await f.run();assert.equal(r.issuer.code,'HTTP_DIAGNOSTIC_METADATA_REFUSED');assert(r.executor.ok);assert.deepEqual(f.queries,['executor']);});
test('timeout bounds one role and continues the other',async()=>{const keep=setTimeout(()=>{},200);try{const f=fixture({slow:true}),r=await f.run();assert.equal(r.issuer.code,'HTTP_DIAGNOSTIC_TIMEOUT');assert(r.executor.ok);}finally{clearTimeout(keep);}});
test('driver failures sanitized before query',async()=>{const f=fixture();const r=await createQaHttpDiagnostic({env,loadHttp:async()=>{throw Error('PRIVATE_SENTINEL');}})();assert.equal(r.issuer.code,'HTTP_DIAGNOSTIC_DRIVER_REFUSED');assert.equal(f.calls.length,0);});
test('HTTP endpoint override refused',async()=>{const f=fixture();f.driver.neonConfig.fetchEndpoint='https://untrusted.invalid/sql';const r=await f.run();assert.equal(r.issuer.ok,false);assert.equal(f.queries.length,0);});
test('result mismatch is not success',async()=>{const f=fixture();const original=f.driver.neon;f.driver.neon=(...args)=>{const q=original(...args);q.transaction=async()=>[[{'?column?':2}]];return q;};assert.equal((await f.run()).ok,false);});
test('per UID and overall execution caps plus Retry-After',async()=>{let n=0;const h=handler({diagnose:async()=>{n++;return success;}});for(let i=0;i<2;i++)await h(req(),res());const r=res();await h(req(),r);assert.equal(r.statusCode,429);assert.equal(r.headers['Retry-After'],'600');assert.equal(n,2);});
test('concurrent diagnostic cannot start another query batch',async()=>{let release;const pending=new Promise(r=>release=r);const h=handler({diagnose:async()=>{await pending;return success;}});const first=h(req(),res());await new Promise(r=>setImmediate(r));const r=res();await h(req(),r);assert.equal(r.statusCode,429);release();await first;});
test('raw thrown errors never appear in response',async()=>{const r=res();await handler({diagnose:async()=>{throw Error('PRIVATE_SENTINEL');}})(req(),r);assert.deepEqual(r.body,{ok:false,code:'QA_HTTP_DIAGNOSTIC_FAILED'});});
test('diagnostic implementation does not call wallet or payment functions',async()=>{
 const source=await readFile(new URL('../lib/qa-http-db-diagnostic.js',import.meta.url),'utf8');
 for(const forbidden of ['issue_context(', 'read_wallet(', 'credit_purchase(', 'credit_reward(', 'unlock_content(', 'console.', 'process.env.DATABASE_URL'])assert(!source.includes(forbidden));
});
test('actual installed HTTP driver preserves security URL options under mock fetch',async()=>{
 const {neon,neonConfig}=await import('@neondatabase/serverless');const old=neonConfig.fetchFunction;let calls=0;
 try{neonConfig.fetchFunction=async(endpoint,options)=>{
  calls++;assert.equal(options.redirect,'error');assert.equal(options.headers['Neon-Batch-Read-Only'],'true');
  const sent=new URL(options.headers['Neon-Connection-String']);assert.equal(sent.searchParams.get('sslmode'),'verify-full');assert.equal(sent.searchParams.get('channel_binding'),'require');
  const payload=JSON.parse(options.body);assert.deepEqual(payload,{queries:[{query:'SELECT 1',params:[]}]});
  return{ok:true,json:async()=>({results:[{fields:[{name:'?column?',dataTypeID:23}],rows:[['1']],command:'SELECT',rowCount:1}]})};
 };
 const sql=neon(url(roles.executor),{fetchOptions:{redirect:'error'}});const result=await sql.transaction([sql.query('SELECT 1',[])],{readOnly:true});assert.equal(result[0][0]['?column?'],1);assert.equal(calls,1);
 }finally{neonConfig.fetchFunction=old;}
});

const holdProcess=()=>setTimeout(()=>{},1000);
test('overall deadline includes auth; late authentication cannot start diagnosis',async()=>{
 const keep=holdProcess();let release,calls=0;
 try{const pending=new Promise(r=>release=r),r=res();
  const h=handler({requestTimeoutMs:10,verifyToken:async()=>pending,diagnose:async()=>{calls++;return success;}});
  await h(req(),r);assert.equal(r.statusCode,504);assert.deepEqual(r.body,{ok:false,code:'QA_HTTP_DIAGNOSTIC_DEADLINE'});
  release({uid:'public-fixture-user'});await new Promise(r=>setImmediate(r));assert.equal(calls,0);
 }finally{clearTimeout(keep);}
});
test('overall deadline aborts metadata and blocks subsequent metadata and DB work',async()=>{
 const keep=holdProcess();let release,signal,fetches=0;
 try{const f=fixture(),r=res();const diagnose=createQaHttpDiagnostic({env,loadHttp:async()=>f.driver,
  fetcher:async(_u,options)=>{fetches++;signal=options.signal;return new Promise(resolve=>release=resolve);}});
  await handler({requestTimeoutMs:10,diagnose})(req(),r);
  assert.equal(r.statusCode,504);assert.equal(signal.aborted,true);assert.equal(fetches,1);assert.equal(f.queries.length,0);
  release({ok:true,json:async()=>({project:{id:t.projectId,name:t.projectName}})});
  await new Promise(r=>setImmediate(r));assert.equal(fetches,1);assert.equal(f.queries.length,0);
 }finally{clearTimeout(keep);}
});
test('request deadline aborts query transport and never starts executor afterwards',async()=>{
 const keep=holdProcess();
 try{const f=fixture({slow:true}),r=res();
  // Fixture keeps its role timeout longer than this route deadline.
  let pendingSignal;
  // Use its validated metadata mock and run wrapper, sharing the route deadline.
  const wrapped=async({deadline})=>{const driver=f.driver;const originalNeon=driver.neon;
   driver.neon=(...args)=>{const q=originalNeon(...args);pendingSignal=args[1].fetchOptions.signal;q.transaction=async()=>new Promise(()=>{});return q;};
   return f.run({deadline});};
  await handler({requestTimeoutMs:5,diagnose:wrapped})(req(),r);
  assert.equal(r.statusCode,504);assert.equal(pendingSignal.aborted,true);assert.deepEqual(f.queries,['issuer']);
 }finally{clearTimeout(keep);}
});
test('already expired deadline prevents even driver construction or loading',async()=>{
 const deadline=createQaHttpDeadline();deadline.dispose();let calls=0;
 await assert.rejects(createQaHttpDiagnostic({env,loadHttp:async()=>{calls++;return fixture().driver;}})({deadline}));
 assert.equal(calls,0);
});
test('expired deadline cannot start SELECT 1',async()=>{
 const f=fixture(),deadline=createQaHttpDeadline();deadline.dispose();
 await assert.rejects(runHttpSelectOne(f.driver,new URL(env.WALLET_V2_QA_READ_ISSUER_DATABASE_URL),deadline.signal,deadline));
 assert.equal(f.queries.length,0);assert.equal(f.transportSignals.length,0);
});
test('completion cancels request scope and caps remain instance-local',async()=>{
 let signal;const h=handler({diagnose:async({deadline})=>{signal=deadline.signal;return success;}});
 await h(req(),res());assert.equal(signal.aborted,true);
 // A separate worker has separate counters: no global exactly-once claim.
 const second=handler();const r=res();await second(req(),r);assert.equal(r.statusCode,200);
});
