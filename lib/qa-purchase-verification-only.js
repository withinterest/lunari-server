// QA verification only. No DB adapter, claim, context, grant, consume or acknowledge calls.
import {WalletAuthError} from './firebase-wallet-auth.js';
import {qaReadConfiguration,qaFirebaseVerifier} from './qa-wallet-v2-reader.js';
import {purchaseAccountBinding,createQaTestPurchaseEvidence,parseQaPurchaseStart} from './qa-google-play-purchase-evidence.js';
import {parseServiceAccount,verifyPurchaseWithGoogle} from '../api/google-play/verify.js';
const refuse=(code,status=503)=>{throw new WalletAuthError(code,status);};
export function purchaseVerificationConfiguration(env){
 if(env.WALLET_SERVER_PURCHASE_VERIFY_ENABLED!=='1'||env.VERCEL!=='1'||env.VERCEL_ENV!=='preview'||env.VERCEL_GIT_COMMIT_REF!=='qa-wallet-v2-read')refuse('SERVER_PURCHASE_VERIFY_DISABLED');
 const c=qaReadConfiguration(env);let allowed;try{allowed=JSON.parse(env.WALLET_V2_QA_READ_ALLOWED_UIDS);}catch{refuse('SERVER_PURCHASE_CONFIGURATION');}
 if(!Array.isArray(allowed)||allowed.length!==1||c.allowed.size!==1)refuse('SERVER_PURCHASE_SINGLE_ACCOUNT_REQUIRED');
 for(const key of ['PURCHASE_ACCOUNT_HMAC_SECRET','PURCHASE_TOKEN_HMAC_SECRET'])if(typeof env[key]!=='string'||Buffer.byteLength(env[key])<32)refuse('SERVER_PURCHASE_CONFIGURATION');
 if(env.PURCHASE_ACCOUNT_HMAC_SECRET===env.PURCHASE_TOKEN_HMAC_SECRET)refuse('SERVER_PURCHASE_CONFIGURATION');
 const purchaseStartMs = parseQaPurchaseStart(env.WALLET_V2_QA_PURCHASE_START_UTC);
 if (!Number.isFinite(purchaseStartMs) || purchaseStartMs > Date.now()) refuse('SERVER_PURCHASE_CONFIGURATION');
 return {...c,purchaseStartMs};
}
export function createPurchaseVerificationHandler(operation,{env=process.env,verifyToken=qaFirebaseVerifier(env),verifyGoogle=verifyPurchaseWithGoogle,clock=Date.now,timeoutMs=15000}={}){
 if(!['prepare','verify'].includes(operation))throw Error('INVALID_VERIFICATION_OPERATION');
 let active=false;const attempts=new Map();
 return async(req,res)=>{
  res.setHeader('Cache-Control','no-store, private');res.setHeader('Vary','Authorization');let timer,acquired=false;
  const deadline=clock()+timeoutMs;
  const checkDeadline=()=>{if(clock()>=deadline)refuse('SERVER_PURCHASE_TIMEOUT');};
  const within=async task=>{checkDeadline();return Promise.race([Promise.resolve().then(()=>{checkDeadline();return task();}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new WalletAuthError('SERVER_PURCHASE_TIMEOUT',503)),Math.max(1,deadline-clock()));})]).finally(()=>clearTimeout(timer));};
  try{
   const c=purchaseVerificationConfiguration(env);
   if(req.method!=='POST')return res.status(405).json({ok:false,code:'METHOD_NOT_ALLOWED',grantApproved:false});
   if(req.headers?.host!==c.origin.host||req.headers?.['x-forwarded-proto']!=='https')refuse('QA_HTTPS_REQUIRED',403);
   if(Object.keys(req.query??{}).length||new URL(req.url??'/','https://qa.invalid').search)refuse('CLIENT_ACCOUNT_SELECTOR_FORBIDDEN',400);
   let body=req.body;try{if(typeof body==='string'){if(Buffer.byteLength(body)>16000)throw Error();body=JSON.parse(body);}}catch{refuse('SERVER_PURCHASE_REQUEST_REFUSED',400);}
   const fields=operation==='prepare'?['productId']:['productId','purchaseToken'];
   if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).sort().join(',')!==fields.sort().join(',')||body.productId!=='lunari_stars_30')refuse('SERVER_PURCHASE_REQUEST_REFUSED',400);
   if(operation==='verify'&&(typeof body.purchaseToken!=='string'||!body.purchaseToken.length||body.purchaseToken.length>8192||body.purchaseToken!==body.purchaseToken.trim()))refuse('SERVER_PURCHASE_REQUEST_REFUSED',400);
   const auth=req.headers?.authorization;if(typeof auth!=='string'||auth.length>16384||!/^Bearer [^\s]+$/.test(auth))refuse('AUTH_REQUIRED',401);
   const principal=await within(()=>verifyToken(auth.slice(7)));checkDeadline();
   if(!c.allowed.has(principal?.uid))refuse('QA_ACCOUNT_NOT_ALLOWED',403);
   const now=clock();for(const [uid,v]of attempts)if(v.until<=now)attempts.delete(uid);const count=attempts.get(principal.uid)??{until:now+60000,n:0};if(active||count.n>=6)refuse('QA_RATE_LIMITED',429);count.n++;attempts.set(principal.uid,count);active=true;acquired=true;
   if(operation==='prepare')return res.status(200).json({ok:true,productId:'lunari_stars_30',accountBinding:purchaseAccountBinding(principal.uid,env.PURCHASE_ACCOUNT_HMAC_SECRET),bindingVersion:'v1',verificationOnly:true,grantApproved:false});
   const evidenceVerifier=createQaTestPurchaseEvidence({purchaseStartMs:c.purchaseStartMs,accountSecret:env.PURCHASE_ACCOUNT_HMAC_SECRET,tokenSecret:env.PURCHASE_TOKEN_HMAC_SECRET,
    verifyGoogle:async input=>{checkDeadline();const raw=await verifyGoogle({...input,credentials:parseServiceAccount(env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON)});checkDeadline();return raw;}});
   try{await within(()=>evidenceVerifier({uid:principal.uid,mode:'google'},body));}catch(e){if(e instanceof WalletAuthError)throw e;refuse('PURCHASE_NOT_VERIFIED',422);}
   checkDeadline();
   // Google binding is evidence only. No durable ownership/claim or entitlement
   // is created here, including for consumed purchases returned during restore.
   return res.status(200).json({ok:true,verified:true,productId:'lunari_stars_30',status:'verified_held',bindingVersion:'v1',grantApproved:false,grantedStars:0});
  }catch(e){const safe=new Set(['SERVER_PURCHASE_VERIFY_DISABLED','SERVER_PURCHASE_CONFIGURATION','SERVER_PURCHASE_SINGLE_ACCOUNT_REQUIRED','SERVER_PURCHASE_REQUEST_REFUSED','SERVER_PURCHASE_TIMEOUT','QA_HTTPS_REQUIRED','CLIENT_ACCOUNT_SELECTOR_FORBIDDEN','AUTH_REQUIRED','INVALID_AUTH_TOKEN','AUTH_VERIFICATION_UNAVAILABLE','QA_ACCOUNT_NOT_ALLOWED','QA_RATE_LIMITED','PURCHASE_NOT_VERIFIED']);const known=e instanceof WalletAuthError&&safe.has(e.code)?e:new WalletAuthError('SERVER_PURCHASE_UNAVAILABLE',503);return res.status(known.status).json({ok:false,code:known.code,grantApproved:false});}
  finally{clearTimeout(timer);if(acquired)active=false;}
 };
}
// Limits are per warm instance, not global. Deadline stops new work/response,
// but cannot guarantee termination of an already-issued Google API request.
