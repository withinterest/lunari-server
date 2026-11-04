// Preview-only zero-balance bootstrap. No direct wallet writes or financial calls.
import {createHash} from 'node:crypto';
import tls from 'node:tls';
import {WalletAuthError} from './firebase-wallet-auth.js';
import {qaReadConfiguration,qaDatabaseChecks as checks,createQaBalanceReader} from './qa-wallet-v2-reader.js';
import {loadStrictPgClient} from './purchase-direct-tls.js';
import {QA_PURCHASE_TARGET as target} from './purchase-qa-runtime.js';
import {verifyQaTarget} from './wallet-qa-target.js';
const roles={issuer:'lunari_wallet_v2_issuer_sql_qa',executor:'lunari_wallet_v2_exec_sql_qa'};
const extraPins={"bootstrap":"94f6e3bcd99f2c601bf465a9994b1d172cfb2e0a16576a4c873d0a64500765ec","begin_request":"92ff8cba87d47ec9d01f831fa5c73b28a8a55ad573e229b4ef1c0404a36b46bf","finish_request":"a8c611c06a0a9aa80d988d4861600c165d34aa42f88c661f797d41ff3e060051"};
const refuse=(code='QA_BOOTSTRAP_UNAVAILABLE',status=503)=>{throw new WalletAuthError(code,status);};
export function qaBootstrapConfiguration(env){
 if(env.WALLET_V2_QA_BOOTSTRAP_ENABLED!=='1')refuse('QA_BOOTSTRAP_DISABLED');
 if(env.VERCEL!=='1'||env.VERCEL_ENV!=='preview')refuse('QA_BOOTSTRAP_DISABLED');
 const c=qaReadConfiguration(env);let raw;try{raw=JSON.parse(env.WALLET_V2_QA_READ_ALLOWED_UIDS);}catch{refuse();}
 if(!Array.isArray(raw)||raw.length!==1||c.allowed.size!==1)refuse('QA_BOOTSTRAP_SINGLE_ACCOUNT_REQUIRED');
 return c;
}
function result(wallet,uid,status){
 if(wallet?.userUid!==uid||wallet.source!=='qa-wallet-v2')refuse();
 return {ok:true,status,walletExists:wallet.walletExists,balance:wallet.balance};
}
export function createQaWalletBootstrap({env=process.env,fetcher=globalThis.fetch,loadClient=loadStrictPgClient,readWallet=createQaBalanceReader({env,fetcher,loadClient})}={}){
 return async(uid,requestKey)=>{
 const c=qaBootstrapConfiguration(env);
 if(!c.allowed.has(uid))refuse('QA_ACCOUNT_NOT_ALLOWED',403);
 if(typeof requestKey!=='string'||!/^qa-bootstrap:[a-f0-9]{32}$/.test(requestKey))refuse('QA_BOOTSTRAP_REQUEST_REFUSED',400);
 const existing=await readWallet(uid);if(existing.walletExists)return result(existing,uid,'already_exists');
 const pins={status:'approved',projectName:target.projectName,projectId:target.projectId,branchName:target.branchName,branchId:target.branchId,endpointId:target.endpointId,endpointHost:target.host,productionBranchId:target.productionBranchId,productionEndpointIds:[target.productionEndpointId],database:'neondb',migrationRole:roles.issuer,apiRole:'lunari_wallet_api_check'};
 await verifyQaTarget(pins,{WALLET_QA_MODE:'qa',NEON_API_KEY:env.NEON_API_KEY,WALLET_QA_DATABASE_URL:c.urls.issuer.toString()},fetcher);
 const Client=await loadClient();const connections=[];let commitSent=false;
 async function open(kind){
  const role=roles[kind],url=c.urls[kind];const db=new Client({host:target.host,port:5432,database:'neondb',user:role,password:()=>decodeURIComponent(url.password),ssl:{rejectUnauthorized:true,minVersion:'TLSv1.2',servername:target.host,checkServerIdentity:tls.checkServerIdentity},enableChannelBinding:true,connectionTimeoutMillis:10000,query_timeout:15000,options:'-c default_transaction_read_only=on'});
  const state={db,begun:false};connections.push(state);db.on('error',()=>{});db.on('notice',()=>{});
  await db.connect();checks.checkTransport(db,role);await db.query('BEGIN READ ONLY');state.begun=true;
  const id=(await db.query(checks.identitySQL)).rows[0];if(id?.database!=='neondb'||id.role!==role||id.session_role!==role||id.version!==180006||id.read_only!==true)refuse();
  const b=(await db.query(checks.boundarySQL,[role])).rows[0];if(!b||['safe_role','no_memberships','no_create','no_direct_access','safe_owner'].some(k=>b[k]!==true))refuse();
  const fs=(await db.query(checks.functionSQL,[role])).rows,allowed=kind==='issuer'?['issue_context']:['bootstrap','credit_purchase','credit_reward','history','read_wallet','restore_wallet','unlock_content'];
  if(fs.some(f=>f.public_execute!==false||f.executable!==allowed.includes(f.name))||allowed.some(n=>fs.filter(f=>f.name===n&&f.executable).length!==1))refuse();
  for(const [name,pin] of Object.entries({...checks.bodyPins,...Object.fromEntries(Object.entries(extraPins).map(([n,h])=>[n,{bodyHash:h,definer:n==='bootstrap'}]))})){
   const list=fs.filter(f=>f.name===name),f=list[0];if(list.length!==1||f.owner!=='lunari_wallet_v2_fn_owner_qa'||f.prokind!=='f'||f.lanname!=='plpgsql'||f.definer!==pin.definer||createHash('sha256').update(f.body).digest('hex')!==pin.bodyHash||JSON.stringify(f.proconfig)!==JSON.stringify(['search_path=pg_catalog, pg_temp']))refuse();
   if(name==='bootstrap'&&f.args!=='token text, p jsonb')refuse();
  }
  await db.query('ROLLBACK');state.begun=false;return state;
 }
 async function begin(s){await s.db.query('BEGIN READ WRITE');s.begun=true;await s.db.query('SET LOCAL search_path=pg_catalog,pg_temp');await s.db.query("SET LOCAL statement_timeout='10s'");await s.db.query("SET LOCAL lock_timeout='3s'");}
 async function commit(s){commitSent=true;const r=await s.db.query('COMMIT');if(r.command!=='COMMIT')refuse('QA_BOOTSTRAP_COMMIT_UNCONFIRMED');s.begun=false;commitSent=false;}
 try{
  // Validate BOTH minimum-privilege connections before issuing any write context.
  const issuer=await open('issuer'),executor=await open('executor');const payload={requestKey};
  await begin(issuer);
  const issue=async(op,p)=>{const r=(await issuer.db.query('SELECT wallet_v2_secure.issue_context($1,$2,$3,$4::jsonb) AS token',[uid,'google',op,JSON.stringify(p)])).rows[0];if(!/^[a-f0-9]{64}$/.test(r?.token??''))refuse();return r.token;};
  const readToken=await issue('read',{}),bootstrapToken=await issue('bootstrap',payload);await commit(issuer);
  await begin(executor);
  await executor.db.query('SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))',['wallet:'+uid]);
  const before=checks.validateSnapshot((await executor.db.query('SELECT wallet_v2_secure.read_wallet($1,$2::jsonb) AS result',[readToken,'{}'])).rows[0]?.result,uid);
  if(before.walletExists){await executor.db.query('ROLLBACK');executor.begun=false;return result(before,uid,'already_exists');}
  const raw=(await executor.db.query('SELECT wallet_v2_secure.bootstrap($1,$2::jsonb) AS result',[bootstrapToken,JSON.stringify(payload)])).rows[0]?.result;
  const wallet=checks.validateSnapshot(raw,uid);
  if(!wallet.walletExists||wallet.fundingState!=='active'||wallet.balance?.free!==0||wallet.balance?.paid!==0||wallet.balance?.total!==0||raw.status!=='committed'||!Array.isArray(raw.unlocks)||raw.unlocks.length)refuse();
  await commit(executor);return result(wallet,uid,'created');
 }catch(error){if(commitSent)refuse('QA_BOOTSTRAP_COMMIT_UNCONFIRMED');throw error;}
 finally{for(const s of connections){if(s.begun)await s.db.query('ROLLBACK').catch(()=>{});await s.db.end().catch(()=>{});}}
 };
}
