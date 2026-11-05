// Preview-only free-only test unlock. Formal 50-star functions remain unchanged.
import {createHash,randomBytes} from 'node:crypto';
import tls from 'node:tls';
import {WalletAuthError} from './firebase-wallet-auth.js';
import {qaReadConfiguration,qaDatabaseChecks as checks} from './qa-wallet-v2-reader.js';
import {loadStrictPgClient} from './purchase-direct-tls.js';
import {QA_PURCHASE_TARGET as target} from './purchase-qa-runtime.js';
import {verifyQaTarget} from './wallet-qa-target.js';
import {QA_UNLOCK_CONTENT,QA_UNLOCK_COST,QA_UNLOCK_FUNCTION_SQL,QA_UNLOCK_SCHEMA_SQL,assertQaUnlockFunctions} from './qa-wallet-v2-unlock-policy.js';
const roles={issuer:'lunari_wallet_v2_issuer_sql_qa',executor:'lunari_wallet_v2_exec_sql_qa'};
const extraPins={"begin_request":"92ff8cba87d47ec9d01f831fa5c73b28a8a55ad573e229b4ef1c0404a36b46bf","finish_request":"a8c611c06a0a9aa80d988d4861600c165d34aa42f88c661f797d41ff3e060051","assert_active":"42bb7e343b99fbc8014de90b17d13cc29a67402d12d794fb9aa1f003f8fe0271","move":"3449db414c149e4ee5ee996d0eec6488a5ab734d87143be4890b7fc132d20d9b"};
const refuse=(code='QA_UNLOCK_UNAVAILABLE',status=503)=>{throw new WalletAuthError(code,status);};
export function qaUnlockConfiguration(env){
 if(env.WALLET_V2_QA_UNLOCK_ENABLED!=='1')refuse('QA_UNLOCK_DISABLED');
 if(env.VERCEL!=='1'||env.VERCEL_ENV!=='preview')refuse('QA_UNLOCK_DISABLED');
 const c=qaReadConfiguration(env);let raw;try{raw=JSON.parse(env.WALLET_V2_QA_READ_ALLOWED_UIDS);}catch{refuse();}
 if(!Array.isArray(raw)||raw.length!==1||c.allowed.size!==1)refuse('QA_UNLOCK_SINGLE_ACCOUNT_REQUIRED');
 return c;
}
export const QA_UNLOCK_CONSTRAINT_SQL=`SELECT c.conrelid::regclass::text AS relation,c.contype,c.convalidated,c.condeferrable,i.indisunique,i.indisvalid,i.indisready,
 ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(attnum,n) JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum ORDER BY k.n) AS columns
 FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class t ON t.oid=c.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace JOIN pg_catalog.pg_index i ON i.indexrelid=c.conindid
 WHERE n.nspname='public' AND t.relname IN('star_wallet_v2_requests','star_wallet_unlocks') AND c.contype IN('p','u')`;
export function createQaUnlock({env=process.env,fetcher=globalThis.fetch,loadClient=loadStrictPgClient}={}){
 return async uid=>{
 const c=qaUnlockConfiguration(env);
 if(!c.allowed.has(uid))refuse('QA_ACCOUNT_NOT_ALLOWED',403);
 // Server-generated identifier; no client amount, date, account or key is trusted.
 const requestKey='qa-unlock:'+randomBytes(16).toString('hex');
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
  for(const [name,pin] of Object.entries({...checks.bodyPins,...Object.fromEntries(Object.entries(extraPins).map(([n,h])=>[n,{bodyHash:h,definer:false}]))})){
   const list=fs.filter(f=>f.name===name),f=list[0];if(list.length!==1||f.owner!=='lunari_wallet_v2_fn_owner_qa'||f.prokind!=='f'||f.lanname!=='plpgsql'||f.definer!==pin.definer||createHash('sha256').update(f.body).digest('hex')!==pin.bodyHash||JSON.stringify(f.proconfig)!==JSON.stringify(['search_path=pg_catalog, pg_temp']))refuse();

  }
  const schema=(await db.query(QA_UNLOCK_SCHEMA_SQL,[role])).rows[0];if(schema?.owner!=='neondb_owner'||schema.usable!==true||schema.public_access!==false)refuse('QA_UNLOCK_BOUNDARY_REFUSED');
  assertQaUnlockFunctions((await db.query(QA_UNLOCK_FUNCTION_SQL,[role])).rows,kind);
  const constraints=(await db.query(QA_UNLOCK_CONSTRAINT_SQL)).rows;
  for(const [relation,columns] of [['star_wallet_v2_requests',['request_key']],['star_wallet_unlocks',['user_uid','content_id']]]){
   if(!constraints.some(v=>[relation,'public.'+relation].includes(v.relation)&&['p','u'].includes(v.contype)&&v.convalidated===true&&v.condeferrable===false&&v.indisunique===true&&v.indisvalid===true&&v.indisready===true&&JSON.stringify(v.columns)===JSON.stringify(columns)))refuse();
  }
  await db.query('ROLLBACK');state.begun=false;return state;
 }
 async function begin(s){await s.db.query('BEGIN READ WRITE');s.begun=true;await s.db.query('SET LOCAL search_path=pg_catalog,pg_temp');await s.db.query("SET LOCAL statement_timeout='10s'");await s.db.query("SET LOCAL lock_timeout='3s'");}
 async function commit(s){commitSent=true;const r=await s.db.query('COMMIT');if(r.command!=='COMMIT')refuse('QA_UNLOCK_COMMIT_UNCONFIRMED');s.begun=false;commitSent=false;}
 try{
  // Validate BOTH minimum-privilege connections before issuing any write context.
  const issuer=await open('issuer'),executor=await open('executor');const payload={requestKey,contentId:QA_UNLOCK_CONTENT};
  await begin(issuer);
  const readRow=(await issuer.db.query("SELECT wallet_v2_secure.issue_context($1,'google','read','{}'::jsonb) AS token",[uid])).rows[0];
  const unlockRow=(await issuer.db.query('SELECT wallet_v2_qa_test.issue_unlock_context($1,$2::jsonb) AS token',[uid,JSON.stringify(payload)])).rows[0];
  const readToken=readRow?.token,unlockToken=unlockRow?.token;if(!/^[a-f0-9]{64}$/.test(readToken??'')||!/^[a-f0-9]{64}$/.test(unlockToken??''))refuse();await commit(issuer);
  await begin(executor);
  await executor.db.query('SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))',['wallet:'+uid]);
  const read=async()=>{const r=(await executor.db.query("SELECT wallet_v2_secure.read_wallet($1,'{}'::jsonb) AS result",[readToken])).rows[0]?.result;const wallet=checks.validateSnapshot(r,uid);if(!Array.isArray(r?.unlocks)||r.unlocks.some(v=>typeof v!=='string'))refuse();return{wallet,unlocks:r.unlocks};};
  const before=await read();if(!before.wallet.walletExists||before.wallet.fundingState!=='active')refuse('QA_UNLOCK_WALLET_REQUIRED',409);
  if(before.unlocks.includes(QA_UNLOCK_CONTENT)){await executor.db.query('ROLLBACK');executor.begun=false;return{ok:true,status:'already_unlocked',contentId:QA_UNLOCK_CONTENT,cost:QA_UNLOCK_COST,balance:before.wallet.balance};}
  if(before.wallet.balance.free<QA_UNLOCK_COST)refuse('QA_UNLOCK_INSUFFICIENT_STARS',409);
  const raw=(await executor.db.query('SELECT wallet_v2_qa_test.unlock_content_2stars($1,$2::jsonb) AS result',[unlockToken,JSON.stringify(payload)])).rows[0]?.result;
  const after=await read();if(raw?.ok!==true||raw.status!=='committed'||raw.free!==-QA_UNLOCK_COST||raw.paid!==0||raw.total!==-QA_UNLOCK_COST||raw.contentId!==QA_UNLOCK_CONTENT||raw.replay!==false||after.wallet.balance.free!==before.wallet.balance.free-QA_UNLOCK_COST||after.wallet.balance.paid!==before.wallet.balance.paid||after.wallet.balance.total!==before.wallet.balance.total-QA_UNLOCK_COST||BigInt(after.wallet.revision)!==BigInt(before.wallet.revision)+1n||!after.unlocks.includes(QA_UNLOCK_CONTENT)||JSON.stringify(after.unlocks.filter(v=>v!==QA_UNLOCK_CONTENT).sort())!==JSON.stringify([...before.unlocks].sort()))refuse();
  await commit(executor);return{ok:true,status:'unlocked',contentId:QA_UNLOCK_CONTENT,cost:QA_UNLOCK_COST,balance:after.wallet.balance};
 }catch(error){if(commitSent)refuse('QA_UNLOCK_COMMIT_UNCONFIRMED');throw error;}
 finally{for(const s of connections){if(s.begun)await s.db.query('ROLLBACK').catch(()=>{});await s.db.end().catch(()=>{});}}
 };
}
