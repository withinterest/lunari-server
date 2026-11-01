// QA-only composition. Existing development/production handlers are unchanged.
import tls from 'node:tls';
import {createHash,randomBytes} from 'node:crypto';
import {WalletAuthError,createFirebaseTokenVerifier} from './firebase-wallet-auth.js';
import {QA_PURCHASE_TARGET as target} from './purchase-qa-runtime.js';
import {verifyQaTarget} from './wallet-qa-target.js';
import {loadStrictPgClient} from './purchase-direct-tls.js';
const roles=Object.freeze({issuer:'lunari_wallet_v2_issuer_sql_qa',executor:'lunari_wallet_v2_exec_sql_qa'});
const owner='lunari_wallet_v2_fn_owner_qa';
const fail=(code='QA_WALLET_UNAVAILABLE',status=503)=>{throw new WalletAuthError(code,status);};
// Internal-only diagnostics: never attach environment details to API errors.
const environmentFailures=new WeakMap();
function environmentRefused(condition,blockedVariables){
 const error=new WalletAuthError('QA_READ_ENVIRONMENT_REFUSED',503);
 environmentFailures.set(error,Object.freeze({condition,blockedVariables:Object.freeze([...blockedVariables])}));throw error;
}
export function logQaReadEnvironmentFailure(error,logger=console){
 const diagnostic=environmentFailures.get(error);if(!diagnostic)return;
 // Only fixed condition/variable names enter the logger; never error/env objects.
 try{logger.warn(JSON.stringify(diagnostic));}catch{/* Logging cannot bypass rejection. */}
}
// Private diagnostic annotations: only fixed stages/codes can enter QA logs.
const readFailures=new WeakMap();
const safeSyscalls=new Set(['open','openat','stat','lstat','access','read','readlink','realpath','scandir','connect','getaddrinfo','getnameinfo']);
const safeInternalCodes=new Set([
 'QA_METADATA_UNAVAILABLE','QA_METADATA_MISMATCH','QA_METADATA_INCOMPLETE','QA_PRODUCTION_SEPARATION_FAILED',
 'QA_TARGET_NOT_APPROVED','QA_ENVIRONMENT_REFUSED','QA_CREDENTIALS_MISSING','QA_DATABASE_URL_REFUSED',
 'PURCHASE_PG_INTEGRITY_MANIFEST','PURCHASE_PG_SOURCE_INTEGRITY','PURCHASE_PG_VERSION_REFUSED',
 'PURCHASE_CHANNEL_BINDING_REQUIRED','MODULE_NOT_FOUND','ENOENT',
 'ENOTFOUND','ECONNREFUSED','ECONNRESET','ETIMEDOUT','ERR_TLS_CERT_ALTNAME_INVALID',
 'UNABLE_TO_VERIFY_LEAF_SIGNATURE','CERT_HAS_EXPIRED','DEPTH_ZERO_SELF_SIGNED_CERT',
 '28P01','28000','42501','42883','42809','42P01','42703','25006','23505','23514','40001','40P01','57014','08001','08006'
]);
export function logQaReadFailure(error,logger=console){
 const diagnostic=readFailures.get(error);if(!diagnostic)return;
 try{logger.warn(JSON.stringify(diagnostic));}catch{/* Diagnostics cannot alter the response. */}
}
// BODY_PINS: generated from the already-installed, checksum-verified QA SQL.
const bodyPins={"check_payload":{"bodyHash":"a08437e64da1371657f09cebeeb3d492d36c9631f44d6976965573244cddb7b6","definer":false},"issue_context":{"bodyHash":"03451f1dadd0f42a40a4fd4daae51e725100a4f9dc80b65c5ee18e37f9de0f5d","definer":true},"take_context":{"bodyHash":"ff9981d9ad862821667373751c92e320234a432327141dcefcbee54aaf360936","definer":false},"snapshot":{"bodyHash":"a82af01def6230d1d6a29a07b40220b757d3b336a2db43d7636e220d155f3138","definer":false},"read_wallet":{"bodyHash":"972e8f620d2ebb66265ef384f2ee248ea498cf4d9ca3b1b6ec433d0218648efa","definer":true}};
export function qaReadConfiguration(env){
 if(env.WALLET_V2_QA_READ_ENABLED!=='1'||env.WALLET_ENV!=='qa'||env.FIREBASE_PROJECT_ID!=='lunari-dev'||env.FIREBASE_AUTH_EMULATOR_HOST)fail('QA_READ_DISABLED');
 if(env.VERCEL?env.VERCEL!=='1'||env.VERCEL_ENV!=='preview':!['development','test'].includes(env.NODE_ENV)){
  const blocked=env.VERCEL?[...(env.VERCEL!=='1'?['VERCEL']:[]),...(env.VERCEL_ENV!=='preview'?['VERCEL_ENV']:[])]:['VERCEL','NODE_ENV'];
  environmentRefused(env.VERCEL?'VERCEL_PREVIEW_REQUIRED':'LOCAL_NODE_ENV_REQUIRED',blocked);
 }
 const blocked=['NODE_TLS_REJECT_UNAUTHORIZED','NODE_OPTIONS','NODE_EXTRA_CA_CERTS','SSLKEYLOGFILE','PGOPTIONS','PGSERVICE','PGSERVICEFILE','PGPASSFILE','NODE_USE_ENV_PROXY','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY'].filter(k=>!!env[k]);
 if(blocked.length)environmentRefused('RISKY_ENVIRONMENT_VARIABLE_PRESENT',blocked);
 // Preview authority comes only from Vercel's deployment environment, never
 // request headers or a manually copied origin from a previous deployment.
 const deploymentHost=env.VERCEL==='1'?env.VERCEL_URL:null;
 if(env.VERCEL==='1'&&(typeof deploymentHost!=='string'||!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(deploymentHost)))fail('QA_READ_CONFIGURATION_REQUIRED');
 let origin,uids;try{origin=new URL(env.VERCEL==='1'?'https://'+deploymentHost:env.WALLET_V2_QA_READ_ORIGIN);uids=JSON.parse(env.WALLET_V2_QA_READ_ALLOWED_UIDS);}catch{fail('QA_READ_CONFIGURATION_REQUIRED');}
 if(origin.protocol!=='https:'||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash||origin.hostname==='lunari-server.vercel.app'||env.VERCEL&&origin.host!==env.VERCEL_URL||!Array.isArray(uids)||!uids.length||uids.length>20||uids.some(u=>typeof u!=='string'||!u.length||u.length>128||u!==u.trim()||/[\x00-\x1f\x7f]/u.test(u)))fail('QA_READ_CONFIGURATION_REQUIRED');
 const urls={};for(const kind of Object.keys(roles)){let u;try{u=new URL(env[kind==='issuer'?'WALLET_V2_QA_READ_ISSUER_DATABASE_URL':'WALLET_V2_QA_READ_EXECUTOR_DATABASE_URL']);}catch{fail('QA_READ_DATABASE_CONFIGURATION');}
 if(!['postgres:','postgresql:'].includes(u.protocol)||u.hostname!==target.host||u.pathname!=='/neondb'||(u.port&&u.port!=='5432')||decodeURIComponent(u.username)!==roles[kind]||!u.password||u.hash||u.searchParams.getAll('sslmode').length!==1||u.searchParams.get('sslmode')!=='verify-full'||u.searchParams.getAll('channel_binding').length!==1||u.searchParams.get('channel_binding')!=='require'||[...u.searchParams.keys()].some(k=>!['sslmode','channel_binding'].includes(k)))fail('QA_READ_DATABASE_CONFIGURATION');urls[kind]=u;}
 if(!env.NEON_API_KEY)fail('QA_READ_METADATA_CONFIGURATION');return{origin,allowed:new Set(uids),urls};
}
async function qaAdminAuth(env){
 try{let raw=JSON.parse(env.FIREBASE_ADMIN_SERVICE_ACCOUNT_JSON??'');if(raw.project_id!=='lunari-dev')throw Error();
 const {getApps,initializeApp,cert}=await import('firebase-admin/app');const {getAuth}=await import('firebase-admin/auth');
 const app=getApps().find(a=>a.name==='lunari-wallet-qa-read')??initializeApp({projectId:'lunari-dev',credential:cert(raw)},'lunari-wallet-qa-read');return getAuth(app);
 }catch{fail('QA_READ_FIREBASE_CONFIGURATION');}
}
export function qaFirebaseVerifier(env,getAuth=()=>qaAdminAuth(env)){
 // Separate QA environment gate, then reuse the existing revoked-token, Google,
 // audience/issuer/expiry/UID verifier. No old development gate is modified.
 return async token=>{qaReadConfiguration(env);return createFirebaseTokenVerifier({env:{WALLET_AUTH_DEV_ENABLED:'1',WALLET_ENV:'development',FIREBASE_PROJECT_ID:'lunari-dev'},getAuth})(token);};
}
const identitySQL=`SELECT current_database() AS database,current_user AS role,session_user AS session_role,current_setting('server_version_num')::int AS version,current_setting('transaction_read_only')='on' AS read_only`;
const boundarySQL=`SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=$1 AND r.rolcanlogin AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR r.rolinherit)) AS safe_role,
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.member WHERE r.rolname=$1) AS no_memberships,
 NOT has_database_privilege($1,current_database(),'CREATE') AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE has_schema_privilege($1,n.oid,'CREATE')) AS no_create,
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN('public','wallet_v2_secure') AND c.relkind IN('r','S') AND (pg_catalog.pg_get_userbyid(c.relowner)::text=$1 OR CASE WHEN c.relkind='S' THEN has_sequence_privilege($1,c.oid,'USAGE,SELECT,UPDATE') ELSE has_table_privilege($1,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND has_column_privilege($1,c.oid,a.attnum,'SELECT,INSERT,UPDATE,REFERENCES')) END)) AS no_direct_access,
 EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname='lunari_wallet_v2_fn_owner_qa' AND NOT(r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR r.rolinherit)) AS safe_owner`;
const functionSQL=`SELECT p.proname AS name,p.prosrc AS body,p.prosecdef AS definer,p.proconfig,p.prokind,l.lanname,pg_catalog.pg_get_function_identity_arguments(p.oid) AS args,pg_catalog.pg_get_userbyid(p.proowner)::text AS owner,
 has_function_privilege($1,p.oid,'EXECUTE') AS executable,EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_language l ON l.oid=p.prolang WHERE n.nspname='wallet_v2_secure'`;
function checkTransport(db,role){const s=db.connection?.stream,o=db.connectionParameters;
 if(o?.host!==target.host||o.database!=='neondb'||o.user!==role||o.port!==5432||o.ssl?.rejectUnauthorized!==true||db.bindingFinished!==true||s?.authorized!==true||s.encrypted!==true||s.servername!==target.host||!['TLSv1.2','TLSv1.3'].includes(s.getProtocol?.())||tls.checkServerIdentity(target.host,s.getPeerCertificate?.()??{}))fail('QA_READ_TLS_REQUIRED');
}
function validateSnapshot(r,uid){
 if(r?.ok!==true||r.userUid!==uid||r.accountMode!=='google'||typeof r.walletExists!=='boolean')fail('QA_READ_IDENTITY_MISMATCH');
 const integer=n=>Number.isSafeInteger(n)&&n>=0&&n<=2147483647;
 if(!r.walletExists){if(r.balance!==null||r.revision!==null||r.fundingState!==null)fail();}
 else{const b=r.balance;if(!b||!integer(b.total)||typeof r.revision!=='string'||!/^\d+$/.test(r.revision)||!['active','legacy_pending','review_hold'].includes(r.fundingState))fail();if(r.fundingState==='legacy_pending'){if(b.free!==null||b.paid!==null)fail();}else if(!integer(b.free)||!integer(b.paid)||b.free+b.paid!==b.total)fail();}
 // Balance-only contract: context, unlocks, purchase evidence and raw rows stay private.
 return{ok:true,source:'qa-wallet-v2',userUid:uid,walletExists:r.walletExists,fundingState:r.fundingState,balance:r.balance===null?null:{free:r.balance.free,paid:r.balance.paid,total:r.balance.total},revision:r.revision};
}
export function createQaBalanceReader({env=process.env,fetcher=globalThis.fetch,loadClient=loadStrictPgClient}={}){
 return async uid=>{
 // Random ID is independent of request headers, credentials and account data.
 const diagnosticId=randomBytes(6).toString('hex');
 let currentStage='metadata';
 async function run(stage,work){currentStage=stage;try{return await work();}catch(thrown){
  const error=thrown instanceof Error?thrown:new Error('QA_READ_INTERNAL_FAILURE');
  if(!readFailures.has(error))readFailures.set(error,Object.freeze({diagnosticId,stage,
   internalCode:safeInternalCodes.has(error.code)?error.code:stage==='result-validation'?'SNAPSHOT_INVALID':'UNCLASSIFIED_ERROR',
   syscall:safeSyscalls.has(error.syscall)?error.syscall:'unspecified'}));
  throw error;
 }}
 try{
 const c=qaReadConfiguration(env);if(!c.allowed.has(uid))fail('QA_ACCOUNT_NOT_ALLOWED',403);
 const pins={status:'approved',projectName:target.projectName,projectId:target.projectId,branchName:target.branchName,branchId:target.branchId,endpointId:target.endpointId,endpointHost:target.host,productionBranchId:target.productionBranchId,productionEndpointIds:[target.productionEndpointId],database:'neondb',migrationRole:roles.issuer,apiRole:'lunari_wallet_api_check'};
 // Reuse exact metadata/production separation guard; only QA-specific inputs are
 // projected, never an existing owner's URL or production connection setting.
 await run('metadata',()=>verifyQaTarget(pins,{WALLET_QA_MODE:'qa',NEON_API_KEY:env.NEON_API_KEY,WALLET_QA_DATABASE_URL:c.urls.issuer.toString()},fetcher));
 const Client=await run('driver',()=>loadClient());
 async function connection(kind,work){const u=c.urls[kind],role=roles[kind],db=await run('client-construction',()=>new Client({host:target.host,port:5432,database:'neondb',user:role,password:()=>decodeURIComponent(u.password),ssl:{rejectUnauthorized:true,minVersion:'TLSv1.2',servername:target.host,checkServerIdentity:tls.checkServerIdentity},enableChannelBinding:true,connectionTimeoutMillis:10000,query_timeout:15000,options:'-c default_transaction_read_only=on'}));let begun=false;
 const query=(...args)=>run('sql-execution',()=>db.query(...args));db.on('error',()=>{});db.on('notice',()=>{});
 try{await run('connection-handshake',async()=>{await db.connect();checkTransport(db,role);});await query('BEGIN READ ONLY');begun=true;
 const id=(await query(identitySQL)).rows[0];if(id?.database!=='neondb'||id.role!==role||id.session_role!==role||id.version!==180006||id.read_only!==true)fail('QA_READ_SESSION_REFUSED');
 const b=(await query(boundarySQL,[role])).rows[0];if(!b||['safe_role','no_memberships','no_create','no_direct_access','safe_owner'].some(k=>b[k]!==true))fail('QA_READ_ROLE_UNSAFE');
 const fs=(await query(functionSQL,[role])).rows,allowed=kind==='issuer'?['issue_context']:['bootstrap','credit_purchase','credit_reward','history','read_wallet','restore_wallet','unlock_content'];
 if(fs.some(f=>f.public_execute!==false||f.executable!==allowed.includes(f.name))||allowed.some(name=>fs.filter(f=>f.name===name&&f.executable).length!==1))fail('QA_READ_EXECUTE_UNSAFE');
 for(const [name,pin] of Object.entries(bodyPins)){const f=fs.filter(f=>f.name===name);if(f.length!==1||f[0].owner!==owner||f[0].prokind!=='f'||f[0].lanname!=='plpgsql'||f[0].definer!==pin.definer||createHash('sha256').update(f[0].body).digest('hex')!==pin.bodyHash||JSON.stringify(f[0].proconfig)!==JSON.stringify(['search_path=pg_catalog, pg_temp']))fail('QA_READ_FUNCTION_UNSAFE');}
 await query('ROLLBACK');begun=false;
 await query(kind==='issuer'?'BEGIN READ WRITE':'BEGIN READ ONLY ISOLATION LEVEL REPEATABLE READ');begun=true;await query('SET LOCAL search_path=pg_catalog,pg_temp');await query("SET LOCAL statement_timeout='10s'");await query("SET LOCAL lock_timeout='3s'");
 const value=await work({query});if(kind==='issuer'){const commit=await query('COMMIT');if(commit.command!=='COMMIT')fail('QA_READ_CONTEXT_COMMIT_UNCONFIRMED');}else await query('ROLLBACK');begun=false;return value;
 }finally{if(begun)await query('ROLLBACK').catch(()=>{});await db.end().catch(()=>{});}}
 // Never retry context COMMIT or reuse a context across HTTP requests. Existing
 // DB read contexts remain read-only/reusable until their DB-enforced 2m expiry.
 let token;try{token=await connection('issuer',async db=>{const r=(await db.query("SELECT wallet_v2_secure.issue_context($1,'google','read','{}'::jsonb) AS token",[uid])).rows[0];if(!/^[0-9a-f]{64}$/.test(r?.token??''))fail('QA_READ_CONTEXT_REFUSED');return r.token;});
 return await connection('executor',async db=>{const result=await db.query("SELECT wallet_v2_secure.read_wallet($1,'{}'::jsonb) AS result",[token]);return run('result-validation',()=>validateSnapshot(result.rows[0]?.result,uid));});
 }finally{token=undefined;}
 }catch(error){return run(currentStage,()=>{throw error;});}
 };
}
