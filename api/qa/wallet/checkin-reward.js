import {WalletAuthError} from '../../../lib/firebase-wallet-auth.js';
import {qaFirebaseVerifier} from '../../../lib/qa-wallet-v2-reader.js';
import {qaCheckinConfiguration,createQaCheckinReward} from '../../../lib/qa-wallet-v2-checkin.js';
export function createQaCheckinHandler({env=process.env,verifyToken=qaFirebaseVerifier(env),reward=createQaCheckinReward({env}),clock=Date.now}={}){
 let active=false;const attempts=new Map();
 return async(req,res)=>{
  res.setHeader('Cache-Control','no-store, private');res.setHeader('Vary','Authorization');let acquired=false;
  try{
   const c=qaCheckinConfiguration(env);
   if(req.method!=='POST')return res.status(405).json({ok:false,code:'METHOD_NOT_ALLOWED'});
   if(req.headers?.host!==c.origin.host||req.headers?.['x-forwarded-proto']!=='https')throw new WalletAuthError('QA_HTTPS_REQUIRED',403);
   if(Object.keys(req.query??{}).length||new URL(req.url??'/','https://qa.invalid').search)throw new WalletAuthError('CLIENT_ACCOUNT_SELECTOR_FORBIDDEN',400);
   let p=req.body;try{if(typeof p==='string'){if(p.length>32)throw Error();p=p===''?{}:JSON.parse(p);}}catch{throw new WalletAuthError('QA_CHECKIN_REQUEST_REFUSED',400);}
   if(p==null)p={};
   if(typeof p!=='object'||Array.isArray(p)||Object.keys(p).length!==0)throw new WalletAuthError('QA_CHECKIN_REQUEST_REFUSED',400);
   const h=req.headers?.authorization;if(typeof h!=='string'||h.length>16384||!/^Bearer [^\s]+$/.test(h))throw new WalletAuthError('AUTH_REQUIRED',401);
   const {uid}=await verifyToken(h.slice(7));if(!c.allowed.has(uid))throw new WalletAuthError('QA_ACCOUNT_NOT_ALLOWED',403);
   const now=clock();for(const [u,a]of attempts)if(a.until<=now)attempts.delete(u);
   const a=attempts.get(uid)??{until:now+60000,n:0};if(active||a.n>=3)throw new WalletAuthError('QA_RATE_LIMITED',429);a.n++;attempts.set(uid,a);active=true;acquired=true;
   return res.status(200).json(await reward(uid));
  }catch(e){const known=new Set(['QA_CHECKIN_DISABLED','QA_CHECKIN_SINGLE_ACCOUNT_REQUIRED','QA_CHECKIN_REQUEST_REFUSED','QA_CHECKIN_COMMIT_UNCONFIRMED','QA_CHECKIN_WALLET_REQUIRED','QA_CHECKIN_WALLET_NOT_ACTIVE','QA_CHECKIN_DAY_CHANGED','AUTH_REQUIRED','INVALID_AUTH_TOKEN','AUTH_VERIFICATION_UNAVAILABLE','QA_ACCOUNT_NOT_ALLOWED','QA_HTTPS_REQUIRED','QA_RATE_LIMITED','CLIENT_ACCOUNT_SELECTOR_FORBIDDEN']);const safe=e instanceof WalletAuthError&&known.has(e.code)?e:new WalletAuthError('QA_CHECKIN_UNAVAILABLE',503);return res.status(safe.status).json({ok:false,code:safe.code});}
  finally{if(acquired)active=false;}
 };
}
export default createQaCheckinHandler();
