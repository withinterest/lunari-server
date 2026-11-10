// QA-only authenticated purchase grant transport. Default OFF; original SQL unchanged.
import {createHash} from 'node:crypto';
import tls from 'node:tls';
import {WalletAuthError} from './firebase-wallet-auth.js';
import {qaReadConfiguration,qaDatabaseChecks as checks} from './qa-wallet-v2-reader.js';
import {loadStrictPgClient} from './purchase-direct-tls.js';
import {QA_PURCHASE_TARGET as target} from './purchase-qa-runtime.js';
import {verifyQaTarget} from './wallet-qa-target.js';
import {purchaseVerificationConfiguration} from './qa-purchase-verification-only.js';
import {commitVerifiedPurchase} from './purchase-grant-transaction.js';
const roles={issuer:'lunari_wallet_v2_issuer_sql_qa',executor:'lunari_wallet_v2_exec_sql_qa'};
const extraPins={"credit_purchase":"61996032dbf0a892c0775ebc82b92df0d87065af2a3a89dc3c099c6536a53064","begin_request":"92ff8cba87d47ec9d01f831fa5c73b28a8a55ad573e229b4ef1c0404a36b46bf","finish_request":"a8c611c06a0a9aa80d988d4861600c165d34aa42f88c661f797d41ff3e060051","assert_active":"42bb7e343b99fbc8014de90b17d13cc29a67402d12d794fb9aa1f003f8fe0271","move":"3449db414c149e4ee5ee996d0eec6488a5ab734d87143be4890b7fc132d20d9b"};
const refuse=(code='PURCHASE_GRANT_UNAVAILABLE',status=503)=>{throw new WalletAuthError(code,status);};
export function qaPurchaseGrantConfiguration(env){
 if(env.WALLET_V2_QA_PURCHASE_GRANT_ENABLED!=='1')refuse('PURCHASE_GRANT_DISABLED');
 return purchaseVerificationConfiguration(env);
}
// Catalog-only: verify real unique arbiters, not names or a JS-only daily counter.
export const PURCHASE_CONSTRAINT_SQL=`SELECT c.conrelid::regclass::text AS relation,c.contype,c.convalidated,c.condeferrable,
 i.indisunique,i.indisvalid,i.indisready,
 ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(attnum,n) JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum ORDER BY k.n) AS columns
 FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class t ON t.oid=c.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace JOIN pg_catalog.pg_index i ON i.indexrelid=c.conindid
 WHERE n.nspname='public' AND t.relname IN('purchase_claims','star_wallet_transactions','star_wallet_transaction_funding','star_wallet_paid_lots','star_wallet_paid_lot_movements','star_wallet_v2_requests') AND c.contype IN('p','u')`;
export function createQaPurchaseGranter({env=process.env,fetcher=globalThis.fetch,loadClient=loadStrictPgClient}={}){
 return async(uid,evidence)=>{
 const c=qaPurchaseGrantConfiguration(env);
 if(!c.allowed.has(uid))refuse('QA_ACCOUNT_NOT_ALLOWED',403);
 const pins={status:'approved',projectName:target.projectName,projectId:target.projectId,branchName:target.branchName,branchId:target.branchId,endpointId:target.endpointId,endpointHost:target.host,productionBranchId:target.productionBranchId,productionEndpointIds:[target.productionEndpointId],database:'neondb',migrationRole:roles.issuer,apiRole:'lunari_wallet_api_check'};
 await verifyQaTarget(pins,{WALLET_QA_MODE:'qa',NEON_API_KEY:env.NEON_API_KEY,WALLET_QA_DATABASE_URL:c.urls.issuer.toString()},fetcher);
 const Client=await loadClient();const connections=[];
 async function open(kind){
  const role=roles[kind],url=c.urls[kind];const db=new Client({host:target.host,port:5432,database:'neondb',user:role,password:()=>decodeURIComponent(url.password),ssl:{rejectUnauthorized:true,minVersion:'TLSv1.2',servername:target.host,checkServerIdentity:tls.checkServerIdentity},enableChannelBinding:true,connectionTimeoutMillis:10000,query_timeout:15000,options:'-c default_transaction_read_only=on'});
  const state={db,begun:false};connections.push(state);db.on('error',()=>{});db.on('notice',()=>{});
  await db.connect();checks.checkTransport(db,role);await db.query('BEGIN READ ONLY');state.begun=true;
  const id=(await db.query(checks.identitySQL)).rows[0];if(id?.database!=='neondb'||id.role!==role||id.session_role!==role||id.version!==180006||id.read_only!==true)refuse();
  const b=(await db.query(checks.boundarySQL,[role])).rows[0];if(!b||['safe_role','no_memberships','no_create','no_direct_access','safe_owner'].some(k=>b[k]!==true))refuse();
  const fs=(await db.query(checks.functionSQL,[role])).rows,allowed=kind==='issuer'?['issue_context']:['bootstrap','credit_purchase','credit_reward','history','read_wallet','restore_wallet','unlock_content'];
  if(fs.some(f=>f.public_execute!==false||f.executable!==allowed.includes(f.name))||allowed.some(n=>fs.filter(f=>f.name===n&&f.executable).length!==1))refuse();
  for(const [name,pin] of Object.entries({...checks.bodyPins,...Object.fromEntries(Object.entries(extraPins).map(([n,h])=>[n,{bodyHash:h,definer:n==='credit_purchase'}]))})){
   const list=fs.filter(f=>f.name===name),f=list[0];if(list.length!==1||f.owner!=='lunari_wallet_v2_fn_owner_qa'||f.prokind!=='f'||f.lanname!=='plpgsql'||f.definer!==pin.definer||createHash('sha256').update(f.body).digest('hex')!==pin.bodyHash||JSON.stringify(f.proconfig)!==JSON.stringify(['search_path=pg_catalog, pg_temp']))refuse();
   if(name==='credit_purchase'&&f.args!=='token text, p jsonb')refuse();
  }
  const constraints=(await db.query(PURCHASE_CONSTRAINT_SQL)).rows;
  for(const [relation,columns] of [['purchase_claims',['token_hash']],['purchase_claims',['claim_id']],['star_wallet_transactions',['purchase_claim_id']],['star_wallet_transaction_funding',['transaction_id']],['star_wallet_transaction_funding',['user_uid','revision']],['star_wallet_paid_lots',['claim_id']],['star_wallet_paid_lots',['transaction_id']],['star_wallet_paid_lot_movements',['transaction_id','lot_id','kind']],['star_wallet_v2_requests',['request_key']]]){
   if(!constraints.some(v=>[relation,'public.'+relation].includes(v.relation)&&['p','u'].includes(v.contype)&&v.convalidated===true&&v.condeferrable===false&&v.indisunique===true&&v.indisvalid===true&&v.indisready===true&&JSON.stringify(v.columns)===JSON.stringify(columns)))refuse();
  }
  await db.query('ROLLBACK');state.begun=false;return state;
 }
 try{
  const issuer=await open('issuer'),executor=await open('executor');
  return await commitVerifiedPurchase({issuer:issuer.db,executor:executor.db,uid,evidence});
 }finally{for(const s of connections){if(s.begun)await s.db.query('ROLLBACK').catch(()=>{});await s.db.end().catch(()=>{});}}
 };
}
