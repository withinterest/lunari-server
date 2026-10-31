import {WalletAuthError} from '../../../lib/firebase-wallet-auth.js';
import {qaReadConfiguration,qaFirebaseVerifier,createQaBalanceReader} from '../../../lib/qa-wallet-v2-reader.js';
// Separate /api/qa/wallet/me. No bootstrap, operation or payment route.
export function createQaWalletHandler({env=process.env,verifyToken=qaFirebaseVerifier(env),readWallet=createQaBalanceReader({env}),clock=Date.now}={}){
 const slots=new Map();let active=0;
 const limit=(key,max)=>{const now=clock();for(const [k,v] of slots)if(v.until<=now)slots.delete(k);if(!slots.has(key)){if(slots.size>=1000)return false;slots.set(key,{n:0,until:now+60000});}return ++slots.get(key).n<=max;};
 return async(req,res)=>{res.setHeader('Cache-Control','no-store, private');res.setHeader('Pragma','no-cache');res.setHeader('Vary','Authorization');let acquired=false;
 try{const c=qaReadConfiguration(env);
 if(req.method!=='GET'){res.setHeader('Allow','GET');return res.status(405).json({ok:false,code:'METHOD_NOT_ALLOWED'});}
 if(req.headers?.host!==c.origin.host||(env.VERCEL?req.headers?.['x-forwarded-proto']!=='https':req.socket?.encrypted!==true))throw new WalletAuthError('QA_HTTPS_REQUIRED',403);
 if(Object.keys(req.query??{}).length||new URL(req.url??'/','https://qa.invalid').search||req.body!=null&&(typeof req.body!=='object'||Object.keys(req.body).length))throw new WalletAuthError('CLIENT_ACCOUNT_SELECTOR_FORBIDDEN',400);
 const ip=env.VERCEL?req.headers?.['x-vercel-forwarded-for']:req.socket?.remoteAddress;if(typeof ip!=='string'||!ip.length||ip.length>128||!limit('ip:'+ip,60))throw new WalletAuthError('QA_RATE_LIMITED',429);
 const h=req.headers?.authorization;if(typeof h!=='string'||h.length>16384||!/^Bearer [^\s]+$/.test(h))throw new WalletAuthError('AUTH_REQUIRED',401);
 const {uid}=await verifyToken(h.slice(7));if(!c.allowed.has(uid))throw new WalletAuthError('QA_ACCOUNT_NOT_ALLOWED',403);
 if(!limit('uid:'+uid,20)||active>=4)throw new WalletAuthError('QA_RATE_LIMITED',429);active++;acquired=true;
 const wallet=await readWallet(uid);if(wallet?.userUid!==uid||wallet.source!=='qa-wallet-v2')throw new WalletAuthError('QA_READ_IDENTITY_MISMATCH',503);
 return res.status(200).json(wallet);
 }catch(e){const safe=e instanceof WalletAuthError?e:new WalletAuthError('QA_WALLET_UNAVAILABLE',503);if(safe.status===429)res.setHeader('Retry-After','60');return res.status(safe.status).json({ok:false,code:safe.code});}
 finally{if(acquired)active--;}
 };
}
export default createQaWalletHandler();
