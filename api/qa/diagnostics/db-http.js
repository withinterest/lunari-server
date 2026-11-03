// Default OFF. Preview-only, Firebase-authenticated and existing QA UID allowlist.
// HTTP diagnostic only: does not claim TCP TLS/SCRAM-PLUS policy equivalence.
import {WalletAuthError} from '../../../lib/firebase-wallet-auth.js';
import {qaFirebaseVerifier} from '../../../lib/qa-wallet-v2-reader.js';
import {httpDiagnosticConfiguration,createQaHttpDiagnostic,createQaHttpDeadline} from '../../../lib/qa-http-db-diagnostic.js';
export function createQaHttpDiagnosticHandler({env=process.env,verifyToken=qaFirebaseVerifier(env),diagnose=createQaHttpDiagnostic({env}),clock=Date.now,requestTimeoutMs=15000}={}){
 // Per warm instance: bounded memory, 1 active, max 4 requests/10 min total,
 // max 2/UID/10 min and 4/IP/10 min. Cold starts reset counters: not a global quota.
 // No external coordination: neither global concurrency nor exactly-once is guaranteed.
 // Activation requires a supervised single request, Protection kept ON, one QA UID,
 // an approved narrow access window, then disabling every active diagnostic deployment.
 const slots=new Map();let active=false,total=0,windowUntil=0;
 function limit(key,max){const now=clock();for(const[k,v]of slots)if(v.until<=now)slots.delete(k);
  if(!slots.has(key)){if(slots.size>=1000)return false;slots.set(key,{count:0,until:now+600000});}
  return ++slots.get(key).count<=max;
 }
 return async(req,res)=>{
  const deadline=createQaHttpDeadline(requestTimeoutMs);
  res.setHeader('Cache-Control','no-store, private');res.setHeader('Pragma','no-cache');res.setHeader('Vary','Authorization');let acquired=false;
  try{
   let c;try{c=httpDiagnosticConfiguration(env);}catch{return res.status(503).json({ok:false,code:'QA_HTTP_DIAGNOSTIC_DISABLED'});}
   if(req.method!=='GET'){res.setHeader('Allow','GET');return res.status(405).json({ok:false,code:'METHOD_NOT_ALLOWED'});}
   if(req.headers?.host!==c.origin.host||req.headers?.['x-forwarded-proto']!=='https')return res.status(403).json({ok:false,code:'QA_HTTPS_REQUIRED'});
   if(Object.keys(req.query??{}).length||new URL(req.url??'/','https://qa.invalid').search||![null,undefined,''].includes(req.body))return res.status(400).json({ok:false,code:'CLIENT_ACCOUNT_SELECTOR_FORBIDDEN'});
   const ip=req.headers?.['x-vercel-forwarded-for'];
   if(typeof ip!=='string'||!ip.length||ip.length>128||!limit('ip:'+ip,4))return limited(res);
   const h=req.headers?.authorization;if(typeof h!=='string'||h.length>16384||!/^Bearer [^\s]+$/.test(h))return res.status(401).json({ok:false,code:'AUTH_REQUIRED'});
   const {uid}=await deadline.run(()=>verifyToken(h.slice(7)));if(!c.allowed.has(uid))return res.status(403).json({ok:false,code:'QA_ACCOUNT_NOT_ALLOWED'});
   const now=clock();if(now>=windowUntil){total=0;windowUntil=now+600000;}
   if(active||total>=4||!limit('uid:'+uid,2))return limited(res);
   total++;active=true;acquired=true;
   return res.status(200).json(await deadline.run(()=>diagnose({deadline})));
  }catch(error){
   if(deadline.signal.aborted)return res.status(504).json({ok:false,code:'QA_HTTP_DIAGNOSTIC_DEADLINE'});
   if(error instanceof WalletAuthError&&error.status===401&&['AUTH_REQUIRED','INVALID_AUTH_TOKEN'].includes(error.code))return res.status(401).json({ok:false,code:error.code});
   return res.status(503).json({ok:false,code:'QA_HTTP_DIAGNOSTIC_FAILED'});
  }finally{deadline.dispose();if(acquired)active=false;}
 };
}
function limited(res){res.setHeader('Retry-After','600');return res.status(429).json({ok:false,code:'QA_RATE_LIMITED'});}
export default createQaHttpDiagnosticHandler();
