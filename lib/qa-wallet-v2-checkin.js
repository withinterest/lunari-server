// Preview-only attendance reward. No direct wallet writes, purchases or paid credits.
import {createHash,randomBytes} from 'node:crypto';
import tls from 'node:tls';
import {WalletAuthError} from './firebase-wallet-auth.js';
import {qaReadConfiguration,qaDatabaseChecks as checks} from './qa-wallet-v2-reader.js';
import {loadStrictPgClient} from './purchase-direct-tls.js';
import {QA_PURCHASE_TARGET as target} from './purchase-qa-runtime.js';
import {verifyQaTarget} from './wallet-qa-target.js';
const roles={issuer:'lunari_wallet_v2_issuer_sql_qa',executor:'lunari_wallet_v2_exec_sql_qa'};
const extraPins={"credit_reward":"89dcaa054246082f46f7eb0d7861d9a0b5182924b63bb97a954c9fc7c8fc1f33","begin_request":"92ff8cba87d47ec9d01f831fa5c73b28a8a55ad573e229b4ef1c0404a36b46bf","finish_request":"a8c611c06a0a9aa80d988d4861600c165d34aa42f88c661f797d41ff3e060051","assert_active":"42bb7e343b99fbc8014de90b17d13cc29a67402d12d794fb9aa1f003f8fe0271","move":"3449db414c149e4ee5ee996d0eec6488a5ab734d87143be4890b7fc132d20d9b"};
const refuse=(code='QA_CHECKIN_UNAVAILABLE',status=503)=>{throw new WalletAuthError(code,status);};
export function qaCheckinConfiguration(env){
 if(env.WALLET_V2_QA_CHECKIN_REWARD_ENABLED!=='1')refuse('QA_CHECKIN_DISABLED');
 if(env.VERCEL!=='1'||env.VERCEL_ENV!=='preview')refuse('QA_CHECKIN_DISABLED');
 const c=qaReadConfiguration(env);let raw;try{raw=JSON.parse(env.WALLET_V2_QA_READ_ALLOWED_UIDS);}catch{refuse();}
 if(!Array.isArray(raw)||raw.length!==1||c.allowed.size!==1)refuse('QA_CHECKIN_SINGLE_ACCOUNT_REQUIRED');
 return c;
}
export const CHECKIN_STARS=2;
export const CHECKIN_DAY_SQL="SELECT to_char(clock_timestamp() AT TIME ZONE 'Asia/Seoul','YYYY-MM-DD') AS day";
// Catalog-only: verify real unique arbiters, not names or a JS-only daily counter.
export const CHECKIN_CONSTRAINT_SQL=`SELECT c.conrelid::regclass::text AS relation,c.contype,c.convalidated,c.condeferrable,
 i.indisunique,i.indisvalid,i.indisready,
 ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(attnum,n) JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum ORDER BY k.n) AS columns
 FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class t ON t.oid=c.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace JOIN pg_catalog.pg_index i ON i.indexrelid=c.conindid
 WHERE n.nspname='public' AND t.relname IN('star_wallet_v2_requests','star_wallet_v2_rewards','star_wallet_reward_claims') AND c.contype IN('p','u')`;
function dayValid(day){return typeof day==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(day)&&Number.isFinite(Date.parse(day+'T00:00:00Z'))&&new Date(day+'T00:00:00Z').toISOString().slice(0,10)===day;}
export function createQaCheckinReward({env=process.env,fetcher=globalThis.fetch,loadClient=loadStrictPgClient}={}){
 return async uid=>{
 const c=qaCheckinConfiguration(env);
 if(!c.allowed.has(uid))refuse('QA_ACCOUNT_NOT_ALLOWED',403);
 // Server-generated identifier; no client amount, date, account or key is trusted.
 const requestKey='qa-checkin:'+randomBytes(16).toString('hex');
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
  for(const [name,pin] of Object.entries({...checks.bodyPins,...Object.fromEntries(Object.entries(extraPins).map(([n,h])=>[n,{bodyHash:h,definer:n==='credit_reward'}]))})){
   const list=fs.filter(f=>f.name===name),f=list[0];if(list.length!==1||f.owner!=='lunari_wallet_v2_fn_owner_qa'||f.prokind!=='f'||f.lanname!=='plpgsql'||f.definer!==pin.definer||createHash('sha256').update(f.body).digest('hex')!==pin.bodyHash||JSON.stringify(f.proconfig)!==JSON.stringify(['search_path=pg_catalog, pg_temp']))refuse();
   if(name==='credit_reward'&&f.args!=='token text, p jsonb')refuse();
  }
  const constraints=(await db.query(CHECKIN_CONSTRAINT_SQL)).rows;
  for(const [relation,columns] of [['star_wallet_v2_requests',['request_key']],['star_wallet_v2_rewards',['event_key']],['star_wallet_v2_rewards',['user_uid','kind','scope']],['star_wallet_reward_claims',['user_uid','reward_code','reward_scope']]]){
   if(!constraints.some(v=>[relation,'public.'+relation].includes(v.relation)&&['p','u'].includes(v.contype)&&v.convalidated===true&&v.condeferrable===false&&v.indisunique===true&&v.indisvalid===true&&v.indisready===true&&JSON.stringify(v.columns)===JSON.stringify(columns)))refuse();
  }
  await db.query('ROLLBACK');state.begun=false;return state;
 }
 async function begin(s){await s.db.query('BEGIN READ WRITE');s.begun=true;await s.db.query('SET LOCAL search_path=pg_catalog,pg_temp');await s.db.query("SET LOCAL statement_timeout='10s'");await s.db.query("SET LOCAL lock_timeout='3s'");}
 async function commit(s){commitSent=true;const r=await s.db.query('COMMIT');if(r.command!=='COMMIT')refuse('QA_CHECKIN_COMMIT_UNCONFIRMED');s.begun=false;commitSent=false;}
 try{
  // Validate BOTH minimum-privilege connections before issuing any write context.
  const issuer=await open('issuer'),executor=await open('executor');const payload={requestKey,kind:'attendance'};
  await begin(issuer);
  const issue=async(op,p)=>{const r=(await issuer.db.query('SELECT wallet_v2_secure.issue_context($1,$2,$3,$4::jsonb) AS token',[uid,'google',op,JSON.stringify(p)])).rows[0];if(!/^[a-f0-9]{64}$/.test(r?.token??''))refuse();return r.token;};
  const readToken=await issue('read',{}),rewardToken=await issue('reward',payload);await commit(issuer);
  await begin(executor);
  await executor.db.query('SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))',['wallet:'+uid]);
  const read=async()=>checks.validateSnapshot((await executor.db.query('SELECT wallet_v2_secure.read_wallet($1,$2::jsonb) AS result',[readToken,'{}'])).rows[0]?.result,uid);
  const before=await read();if(!before.walletExists)refuse('QA_CHECKIN_WALLET_REQUIRED',409);if(before.fundingState!=='active')refuse('QA_CHECKIN_WALLET_NOT_ACTIVE',409);
  const day=(await executor.db.query(CHECKIN_DAY_SQL)).rows[0]?.day;if(!dayValid(day))refuse();
  const raw=(await executor.db.query('SELECT wallet_v2_secure.credit_reward($1,$2::jsonb) AS result',[rewardToken,JSON.stringify(payload)])).rows[0]?.result;
  if(raw?.ok!==true||raw.status!=='committed'||typeof raw.transactionId!=='string'||!/^[a-f0-9-]{36}$/.test(raw.transactionId)||typeof raw.replay!=='boolean'||(raw.alreadyApplied!==undefined&&raw.alreadyApplied!==true))refuse();
  const duplicate=raw.alreadyApplied===true||raw.replay===true,credited=duplicate?0:CHECKIN_STARS;
  if(!duplicate&&(raw.free!==CHECKIN_STARS||raw.paid!==0||raw.total!==CHECKIN_STARS))refuse();
  const after=await read();const afterDay=(await executor.db.query(CHECKIN_DAY_SQL)).rows[0]?.day;
  // Midnight during execution is rolled back, never silently attributed to another day.
  if(day!==afterDay)refuse('QA_CHECKIN_DAY_CHANGED',409);
  if(!after.walletExists||after.fundingState!=='active'||after.balance.free!==before.balance.free+credited||after.balance.paid!==before.balance.paid||after.balance.total!==before.balance.total+credited||BigInt(after.revision)!==BigInt(before.revision)+(duplicate?0n:1n))refuse();
  await commit(executor);
  return{ok:true,status:duplicate?'already_applied':'credited',rewardStars:CHECKIN_STARS,creditedStars:credited,day,balance:after.balance};
 }catch(error){if(commitSent)refuse('QA_CHECKIN_COMMIT_UNCONFIRMED');throw error;}
 finally{for(const s of connections){if(s.begun)await s.db.query('ROLLBACK').catch(()=>{});await s.db.end().catch(()=>{});}}
 };
}
