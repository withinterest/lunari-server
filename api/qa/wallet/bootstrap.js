import {WalletAuthError} from '../../../lib/firebase-wallet-auth.js';
import {qaFirebaseVerifier} from '../../../lib/qa-wallet-v2-reader.js';
import {qaBootstrapConfiguration,createQaWalletBootstrap} from '../../../lib/qa-wallet-v2-bootstrap.js';
export function createQaBootstrapHandler({env=process.env,verifyToken=qaFirebaseVerifier(env),bootstrap=createQaWalletBootstrap({env}),clock=Date.now}={}){
 let active=false;const attempts=new Map();
 return async(req,res)=>{
  res.setHeader('Cache-Control','no-store, private');res.setHeader('Vary','Authorization');let acquired=false;
  try{
   const c=qaBootstrapConfiguration(env);
   if(req.method!=='POST')return res.status(405).json({ok:false,code:'METHOD_NOT_ALLOWED'});
   if(req.headers?.host!==c.origin.host||req.headers?.['x-forwarded-proto']!=='https')throw new WalletAuthError('QA_HTTPS_REQUIRED',403);
   if(Object.keys(req.query??{}).length||new URL(req.url??'/','https://qa.invalid').search)throw new WalletAuthError('CLIENT_ACCOUNT_SELECTOR_FORBIDDEN',400);
   let p=req.body;try{if(typeof p==='string'){if(p.length>200)throw Error();p=JSON.parse(p);}}catch{throw new WalletAuthError('QA_BOOTSTRAP_REQUEST_REFUSED',400);}
   if(!p||typeof p!=='object'||Array.isArray(p)||Object.keys(p).length!==1||typeof p.requestKey!=='string'||!/^qa-bootstrap:[a-f0-9]{32}$/.test(p.requestKey))throw new WalletAuthError('QA_BOOTSTRAP_REQUEST_REFUSED',400);
   const h=req.headers?.authorization;if(typeof h!=='string'||h.length>16384||!/^Bearer [^\s]+$/.test(h))throw new WalletAuthError('AUTH_REQUIRED',401);
   const {uid}=await verifyToken(h.slice(7));if(!c.allowed.has(uid))throw new WalletAuthError('QA_ACCOUNT_NOT_ALLOWED',403);
   const now=clock();for(const [u,a]of attempts)if(a.until<=now)attempts.delete(u);
   const a=attempts.get(uid)??{until:now+60000,n:0};if(active||a.n>=3)throw new WalletAuthError('QA_RATE_LIMITED',429);a.n++;attempts.set(uid,a);active=true;acquired=true;
   return res.status(200).json(await bootstrap(uid,p.requestKey));
  }catch(e){const known=new Set(['QA_BOOTSTRAP_DISABLED','QA_BOOTSTRAP_SINGLE_ACCOUNT_REQUIRED','QA_BOOTSTRAP_REQUEST_REFUSED','QA_BOOTSTRAP_COMMIT_UNCONFIRMED','AUTH_REQUIRED','INVALID_AUTH_TOKEN','AUTH_VERIFICATION_UNAVAILABLE','QA_ACCOUNT_NOT_ALLOWED','QA_HTTPS_REQUIRED','QA_RATE_LIMITED','CLIENT_ACCOUNT_SELECTOR_FORBIDDEN']);const safe=e instanceof WalletAuthError&&known.has(e.code)?e:new WalletAuthError('QA_BOOTSTRAP_UNAVAILABLE',503);return res.status(safe.status).json({ok:false,code:safe.code});}
  finally{if(acquired)active=false;}
 };
}
export default createQaBootstrapHandler();
