import {WalletAuthError} from '../../../lib/firebase-wallet-auth.js';
import {qaFirebaseVerifier} from '../../../lib/qa-wallet-v2-reader.js';
import {qaPurchaseGrantConfiguration,createQaPurchaseGranter} from '../../../lib/qa-purchase-grant.js';
import {purchaseAccountBinding,createQaTestPurchaseEvidence} from '../../../lib/qa-google-play-purchase-evidence.js';
import {parseServiceAccount,verifyPurchaseWithGoogle} from '../../google-play/verify.js';
export function createQaPurchaseGrantHandler({operation='grant',env=process.env,verifyToken=qaFirebaseVerifier(env),verifyGoogle=verifyPurchaseWithGoogle,grant=createQaPurchaseGranter({env})}={}){
 if(!['grant','prepare'].includes(operation))throw Error('INVALID_OPERATION');
 let active=false;const attempts=new Map();
 return async(req,res)=>{
  res.setHeader('Cache-Control','no-store, private');res.setHeader('Vary','Authorization');let acquired=false,timer;
  const deadline=Date.now()+15000;
  const within=task=>{if(Date.now()>=deadline)throw new WalletAuthError('PURCHASE_VERIFICATION_TIMEOUT',503);return Promise.race([Promise.resolve().then(()=>{if(Date.now()>=deadline)throw new WalletAuthError('PURCHASE_VERIFICATION_TIMEOUT',503);return task();}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new WalletAuthError('PURCHASE_VERIFICATION_TIMEOUT',503)),Math.max(1,deadline-Date.now()));})]).finally(()=>clearTimeout(timer));};
  try{
   const c=qaPurchaseGrantConfiguration(env);
   if(req.method!=='POST')throw new WalletAuthError('METHOD_NOT_ALLOWED',405);
   if(req.headers?.host!==c.origin.host||req.headers?.['x-forwarded-proto']!=='https')throw new WalletAuthError('QA_HTTPS_REQUIRED',403);
   if(Object.keys(req.query??{}).length||new URL(req.url??'/','https://qa.invalid').search)throw new WalletAuthError('CLIENT_ACCOUNT_SELECTOR_FORBIDDEN',400);
   let b=req.body;try{if(typeof b==='string'){if(Buffer.byteLength(b)>16000)throw Error();b=JSON.parse(b);}}catch{throw new WalletAuthError('PURCHASE_REQUEST_REFUSED',400);}
   if(!b||typeof b!=='object'||Array.isArray(b)||Object.keys(b).sort().join(',')!==(operation==='prepare'?'productId':'productId,purchaseToken')||b.productId!=='lunari_stars_30'||(operation!=='prepare'&&(typeof b.purchaseToken!=='string'||!b.purchaseToken.length||b.purchaseToken.length>8192||b.purchaseToken!==b.purchaseToken.trim())))throw new WalletAuthError('PURCHASE_REQUEST_REFUSED',400);
   const h=req.headers?.authorization;if(typeof h!=='string'||h.length>16384||!/^Bearer [^\s]+$/.test(h))throw new WalletAuthError('AUTH_REQUIRED',401);
   const p=await within(()=>verifyToken(h.slice(7)));if(!c.allowed.has(p?.uid))throw new WalletAuthError('QA_ACCOUNT_NOT_ALLOWED',403);
   const now=Date.now();for(const [uid,v]of attempts)if(v.until<=now)attempts.delete(uid);const count=attempts.get(p.uid)??{until:now+60000,n:0};if(active||count.n>=3)throw new WalletAuthError('QA_RATE_LIMITED',429);count.n++;attempts.set(p.uid,count);active=true;acquired=true;
   if(operation==='prepare'){
    parseServiceAccount(env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON);
    return res.status(200).json({ok:true,productId:'lunari_stars_30',accountBinding:purchaseAccountBinding(p.uid,env.PURCHASE_ACCOUNT_HMAC_SECRET),bindingVersion:'v1',verificationOnly:false,grantApproved:false,testPurchaseOnly:true});
   }
   const verify=createQaTestPurchaseEvidence({purchaseStartMs:c.purchaseStartMs,tokenSecret:env.PURCHASE_TOKEN_HMAC_SECRET,accountSecret:env.PURCHASE_ACCOUNT_HMAC_SECRET,verifyGoogle:input=>verifyGoogle({...input,credentials:parseServiceAccount(env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON)})});
   let evidence;try{evidence=await within(()=>verify({uid:p.uid,mode:'google'},b));}catch(e){if(e instanceof WalletAuthError)throw e;throw new WalletAuthError('PURCHASE_NOT_VERIFIED',422);}
   if(Date.now()>=deadline)throw new WalletAuthError('PURCHASE_VERIFICATION_TIMEOUT',503);
   // No claim call outside this adapter. Financial changes are one executor
   // transaction; an HTTP disconnect is never a reason to retry automatically.
   return res.status(200).json(await grant(p.uid,evidence));
  }catch(e){const known=new Set(['PURCHASE_GRANT_DISABLED','SERVER_PURCHASE_VERIFY_DISABLED','SERVER_PURCHASE_CONFIGURATION','SERVER_PURCHASE_SINGLE_ACCOUNT_REQUIRED','METHOD_NOT_ALLOWED','QA_HTTPS_REQUIRED','CLIENT_ACCOUNT_SELECTOR_FORBIDDEN','PURCHASE_REQUEST_REFUSED','AUTH_REQUIRED','INVALID_AUTH_TOKEN','AUTH_VERIFICATION_UNAVAILABLE','QA_ACCOUNT_NOT_ALLOWED','QA_RATE_LIMITED','PURCHASE_NOT_VERIFIED','PURCHASE_VERIFICATION_TIMEOUT','PURCHASE_WALLET_REQUIRED','PURCHASE_OWNED_BY_OTHER_ACCOUNT','PURCHASE_CLAIM_REQUIRES_REVIEW','PURCHASE_ALREADY_CONSUMED','IDEMPOTENCY_CONFLICT','PURCHASE_COMMIT_UNCONFIRMED']);const safe=e instanceof WalletAuthError&&known.has(e.code)?e:new WalletAuthError('PURCHASE_GRANT_UNAVAILABLE',503);return res.status(safe.status).json({ok:false,code:safe.code,grantApproved:false});}
  finally{clearTimeout(timer);if(acquired)active=false;}
 };
}
export default createQaPurchaseGrantHandler();
