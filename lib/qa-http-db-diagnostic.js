// Independent Preview diagnostic. Never replaces the pg TCP wallet transport.
// HTTPS verifies the HTTP gateway certificate/hostname. This does NOT attest
// PostgreSQL SCRAM-PLUS or channel_binding=require, even though URL options stay.
import {readFile} from 'node:fs/promises';
import {qaReadConfiguration} from './qa-wallet-v2-reader.js';
import {verifyQaTarget} from './wallet-qa-target.js';
import {QA_PURCHASE_TARGET as target} from './purchase-qa-runtime.js';

export const QA_HTTP_DIAGNOSTIC_QUERY='SELECT 1';
export function httpDiagnosticConfiguration(env){
 if(env.VERCEL!=='1'||env.VERCEL_ENV!=='preview'||env.WALLET_V2_QA_HTTP_DIAGNOSTIC_ENABLED!=='1')throw Error('QA_HTTP_DIAGNOSTIC_DISABLED');
 return qaReadConfiguration(env);
}
async function loadDriver(signal){
 const pkg=JSON.parse(await readFile(new URL('../node_modules/@neondatabase/serverless/package.json',import.meta.url),{encoding:'utf8',signal}));
 if(pkg.version!=='1.2.0')throw Error('HTTP_DRIVER_VERSION_REFUSED');
 return import('@neondatabase/serverless');
}
function bounded(work,signal){
 return new Promise((resolve,reject)=>{
  const aborted=()=>reject(Error('HTTP_DIAGNOSTIC_TIMEOUT'));
  if(signal.aborted){aborted();return;}
  signal.addEventListener('abort',aborted,{once:true});
  Promise.resolve().then(()=>{if(signal.aborted)throw Error('HTTP_DIAGNOSTIC_TIMEOUT');return work();})
   .then(resolve,reject).finally(()=>signal.removeEventListener('abort',aborted));
 });
}
// Shared, monotonic request budget, including Firebase authentication. Aborting
// local HTTP waits cannot prove the remote PostgreSQL statement has stopped.
export function createQaHttpDeadline(timeoutMs=15000){
 if(!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>15000)throw Error('QA_HTTP_DEADLINE_CONFIGURATION');
 const controller=new AbortController(),until=performance.now()+timeoutMs;
 const timer=setTimeout(()=>controller.abort(),timeoutMs);timer.unref?.();
 function ensure(){if(performance.now()>=until)controller.abort();if(controller.signal.aborted)throw Error('QA_HTTP_DIAGNOSTIC_DEADLINE');}
 return Object.freeze({signal:controller.signal,ensure,
  async run(work){ensure();const value=await bounded(()=>{ensure();return work();},controller.signal);ensure();return value;},
  dispose(){clearTimeout(timer);controller.abort();}
 });
}
// No caller-supplied query, options, endpoints, credentials, or SQL parameters.
export async function runHttpSelectOne(driver,url,signal,deadline){
 deadline?.ensure();if(signal.aborted)throw Error('HTTP_DIAGNOSTIC_TIMEOUT');
 const expected='https://'+target.host.replace(/^[^.]+\./,'api.')+'/sql';
 const endpoint=driver.neonConfig.fetchEndpoint;
 if(driver.neonConfig.fetchFunction!==undefined||
    (typeof endpoint==='function'?endpoint(url.hostname,url.port||5432,{jwtAuth:false}):endpoint)!==expected)throw Error('HTTP_DRIVER_CONFIGURATION_REFUSED');
 const query=driver.neon(url.toString(),{fetchOptions:{redirect:'error',cache:'no-store',signal}});
 const result=await bounded(()=>{deadline?.ensure();if(signal.aborted)throw Error('HTTP_DIAGNOSTIC_TIMEOUT');return query.transaction([query.query(QA_HTTP_DIAGNOSTIC_QUERY,[])],{readOnly:true});},signal);
 deadline?.ensure();
 if(!Array.isArray(result)||result.length!==1||!Array.isArray(result[0])||result[0].length!==1||
    Object.keys(result[0][0]??{}).length!==1||Object.values(result[0][0])[0]!==1)throw Error('HTTP_DIAGNOSTIC_RESULT_REFUSED');
}
export function createQaHttpDiagnostic({env=process.env,fetcher=globalThis.fetch,loadHttp=loadDriver,timeoutMs=5000,metadataTimeoutMs=10000}={}){
 return async({deadline:providedDeadline}={})=>{
  const deadline=providedDeadline??createQaHttpDeadline();
  try{
  deadline.ensure();
  const c=httpDiagnosticConfiguration(env);
  let driver;try{driver=await deadline.run(()=>bounded(()=>loadHttp(deadline.signal),AbortSignal.any([deadline.signal,AbortSignal.timeout(metadataTimeoutMs)])));}
  catch{deadline.ensure();return{ok:false,issuer:{ok:false,code:'HTTP_DIAGNOSTIC_DRIVER_REFUSED'},executor:{ok:false,code:'HTTP_DIAGNOSTIC_DRIVER_REFUSED'}};}
  const results={};
  for(const kind of ['issuer','executor']){
   deadline.ensure();
   const u=c.urls[kind],pins={status:'approved',projectName:target.projectName,projectId:target.projectId,branchName:target.branchName,branchId:target.branchId,endpointId:target.endpointId,endpointHost:target.host,productionBranchId:target.productionBranchId,productionEndpointIds:[target.productionEndpointId],database:'neondb',migrationRole:decodeURIComponent(u.username),apiRole:'lunari_wallet_api_check'};
   const metadataSignal=AbortSignal.any([deadline.signal,AbortSignal.timeout(metadataTimeoutMs)]);
   try{await bounded(()=>verifyQaTarget(pins,{WALLET_QA_MODE:'qa',NEON_API_KEY:env.NEON_API_KEY,WALLET_QA_DATABASE_URL:u.toString()},
    (url,options)=>{deadline.ensure();return fetcher(url,{...options,signal:AbortSignal.any([metadataSignal,options.signal])});}),metadataSignal);}
   catch{deadline.ensure();results[kind]={ok:false,code:'HTTP_DIAGNOSTIC_METADATA_REFUSED'};continue;}
   deadline.ensure();
   const signal=AbortSignal.any([deadline.signal,AbortSignal.timeout(timeoutMs)]);
   try{await runHttpSelectOne(driver,u,signal,deadline);results[kind]={ok:true,code:'HTTP_DIAGNOSTIC_OK'};}
   catch{deadline.ensure();results[kind]={ok:false,code:signal.aborted?'HTTP_DIAGNOSTIC_TIMEOUT':'HTTP_DIAGNOSTIC_QUERY_FAILED'};}
  }
  deadline.ensure();
  return{ok:results.issuer.ok&&results.executor.ok,...results};
  }finally{if(!providedDeadline)deadline.dispose();}
 };
}
