import {WalletAuthError} from '../../../lib/firebase-wallet-auth.js';
import {qaReadConfiguration,qaFirebaseVerifier,createQaBalanceReader,logQaReadEnvironmentFailure} from '../../../lib/qa-wallet-v2-reader.js';
// Separate /api/qa/wallet/me. No bootstrap, operation or payment route.
export function createQaWalletHandler({env=process.env,verifyToken=qaFirebaseVerifier(env),readWallet=createQaBalanceReader({env}),clock=Date.now,logger=console}={}){
 const slots=new Map();let active=0,queryNamesLogged=false;
 const limit=(key,max)=>{const now=clock();for(const [k,v] of slots)if(v.until<=now)slots.delete(k);if(!slots.has(key)){if(slots.size>=1000)return false;slots.set(key,{n:0,until:now+60000});}return ++slots.get(key).n<=max;};
 return async(req,res)=>{res.setHeader('Cache-Control','no-store, private');res.setHeader('Pragma','no-cache');res.setHeader('Vary','Authorization');let acquired=false;
 try{const c=qaReadConfiguration(env);
 if(req.method!=='GET'){res.setHeader('Allow','GET');return res.status(405).json({ok:false,code:'METHOD_NOT_ALLOWED'});}
 if(req.headers?.host!==c.origin.host||(env.VERCEL?req.headers?.['x-forwarded-proto']!=='https':req.socket?.encrypted!==true))throw new WalletAuthError('QA_HTTPS_REQUIRED',403);
 const queryBlocked=Object.keys(req.query??{}).length>0;
 const urlHasQuery=!!new URL(req.url??'/','https://qa.invalid').search;
 const body=req.body,bodyEmpty=body===null||body===undefined||body==='';
 if(queryBlocked||urlHasQuery||!bodyEmpty){
  const bodyType=body===null?'null':Buffer.isBuffer(body)?'buffer':Array.isArray(body)?'array':typeof body;
  // Fixed shape/type labels only. Never log request objects, keys or values.
  try{logger.warn(JSON.stringify({queryBlocked,urlHasQuery,bodyType,bodyEmpty}));}catch{/* Diagnostics cannot bypass rejection. */}
  // Temporary diagnostic: one attempt per handler instance (per warm worker).
  // Names only; cap work/output and redact malformed or credential-like names.
  if(!queryNamesLogged&&(queryBlocked||urlHasQuery)){
   queryNamesLogged=true;
   try{
    const safeName=name=>/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(name)&&!/[A-Za-z0-9]{20,}/.test(name)?name:'[REDACTED_NAME]';
    const parsedQueryNames=[...new Set(Object.keys(req.query??{}).slice(0,20).map(safeName))];
    const urlQueryNames=[];
    for(const name of new URL(req.url??'/','https://qa.invalid').searchParams.keys()){
     if(urlQueryNames.length>=20)break;const safe=safeName(name);if(!urlQueryNames.includes(safe))urlQueryNames.push(safe);
    }
    logger.info(JSON.stringify({parsedQueryNames,urlQueryNames}));
   }catch{/* No retry, no raw error logging and no change to rejection. */}
  }
  throw new WalletAuthError('CLIENT_ACCOUNT_SELECTOR_FORBIDDEN',400);
 }
 const ip=env.VERCEL?req.headers?.['x-vercel-forwarded-for']:req.socket?.remoteAddress;if(typeof ip!=='string'||!ip.length||ip.length>128||!limit('ip:'+ip,60))throw new WalletAuthError('QA_RATE_LIMITED',429);
 const h=req.headers?.authorization;if(typeof h!=='string'||h.length>16384||!/^Bearer [^\s]+$/.test(h))throw new WalletAuthError('AUTH_REQUIRED',401);
 const {uid}=await verifyToken(h.slice(7));if(!c.allowed.has(uid))throw new WalletAuthError('QA_ACCOUNT_NOT_ALLOWED',403);
 if(!limit('uid:'+uid,20)||active>=4)throw new WalletAuthError('QA_RATE_LIMITED',429);active++;acquired=true;
 const wallet=await readWallet(uid);if(wallet?.userUid!==uid||wallet.source!=='qa-wallet-v2')throw new WalletAuthError('QA_READ_IDENTITY_MISMATCH',503);
 return res.status(200).json(wallet);
 }catch(e){logQaReadEnvironmentFailure(e,logger);const safe=e instanceof WalletAuthError?e:new WalletAuthError('QA_WALLET_UNAVAILABLE',503);if(safe.status===429)res.setHeader('Retry-After','60');return res.status(safe.status).json({ok:false,code:safe.code});}
 finally{if(acquired)active--;}
 };
}
export default createQaWalletHandler();
