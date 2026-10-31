import {assertQaDdlPermissions} from './wallet-qa-ddl-permissions.js';
import {readFile,realpath} from 'node:fs/promises';
import {resolve,dirname,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {bytesDigest,digest,assertQaIdentity,assertApiSafety,assertFreshPublic,inspectPrototype,validatePrototype,safePrototypeSummary,verifyInstalledBaseline} from './wallet-qa-catalog.js';
import {WalletQaError,qaFail,assertQaTarget,verifyQaTarget,openQaClient} from './wallet-qa-target.js';
const ROOT=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const BASE='migrations/wallet-baseline-v1/';
const ORIGINALS=['001_create_purchase_claims.sql','002_create_star_wallet.sql','003_wallet_rewards.sql','004_wallet_security.sql','005_wallet_runtime_role.sql','006_wallet_lease_guard.sql'];
const EXECUTION=[
 ['qa-baseline-v1:security-prerequisites',BASE+'005_security_prerequisites.sql','derived'],
 ['qa-baseline-v1:prototype-archive',BASE+'000_archive_prototype.sql','derived'],
 ['001','migrations/'+ORIGINALS[0],'original'],['002','migrations/'+ORIGINALS[1],'original'],
 ['003','migrations/'+ORIGINALS[2],'original'],['004','migrations/'+ORIGINALS[3],'original'],
 ['qa-baseline-v1:lease-objects',BASE+'006_lease_objects.sql','derived'],
];
async function localRead(root,relative){
 const wanted=resolve(root,relative),actual=await realpath(wanted);
 if(actual!==wanted||!actual.startsWith((await realpath(root))+sep))qaFail('QA_PLAN_PATH_REFUSED');
 return readFile(wanted);
}
export async function loadQaPlan({root=ROOT}={}){
 try{
  const raw=await localRead(root,BASE+'manifest.json');const manifest=JSON.parse(raw.toString('utf8'));
  const pins=JSON.parse((await localRead(root,BASE+'target.qa.json')).toString('utf8'));
  const approval=JSON.parse((await localRead(root,BASE+'prototype-approval.json')).toString('utf8'));
  if(manifest.planId!=='wallet-qa-baseline-v1'||manifest.schemaVersion!==1||manifest.apiWritesEnabled!==false||
     !Array.isArray(manifest.sources)||manifest.sources.length!==6||!Array.isArray(manifest.steps)||manifest.steps.length!==EXECUTION.length)qaFail('QA_MANIFEST_INVALID');
  for(let i=0;i<ORIGINALS.length;i++){
   const source=manifest.sources[i],path='migrations/'+ORIGINALS[i];
   if(source.path!==path||source.version!==String(i+1).padStart(3,'0')||!/^[a-f0-9]{64}$/u.test(source.sha256??''))qaFail('QA_SOURCE_MANIFEST_INVALID');
   if(bytesDigest(await localRead(root,path))!==source.sha256)qaFail('QA_ORIGINAL_CHECKSUM_MISMATCH');
  }
  const steps=[];
  for(let i=0;i<EXECUTION.length;i++){
   const [version,path,kind]=EXECUTION[i],step=manifest.steps[i];
   if(step.version!==version||step.path!==path||step.kind!==kind||!/^[a-f0-9]{64}$/u.test(step.sha256??''))qaFail('QA_EXECUTION_ORDER_REFUSED');
   const bytes=await localRead(root,path);if(bytesDigest(bytes)!==step.sha256)qaFail('QA_SQL_CHECKSUM_MISMATCH');
   if(kind==='original'&&step.sha256!==manifest.sources.find(s=>s.path===path)?.sha256)qaFail('QA_PROVENANCE_MISMATCH');
   if(version==='qa-baseline-v1:lease-objects'&&(step.derivedFrom?.path!==manifest.sources[5].path||step.derivedFrom?.sha256!==manifest.sources[5].sha256))qaFail('QA_PROVENANCE_MISMATCH');
   const sql=bytes.toString('utf8');
   if(/^\s*(CREATE|ALTER|DROP)\s+ROLE\b/im.test(sql)||/^\s*GRANT\b/im.test(sql)||/^\s*(DROP\s+(TABLE|SCHEMA)|TRUNCATE)\b/im.test(sql))qaFail('QA_SQL_POLICY_REFUSED');
   steps.push({...step,sql});
  }
  return {manifest,pins,approval,steps,manifestSha256:bytesDigest(raw)};
 }catch(e){if(e instanceof WalletQaError)throw e;qaFail('QA_PLAN_UNAVAILABLE');}
}
export function assertApprovalReady(approval){
 if(approval?.status!=='approved'||!/^[a-f0-9]{64}$/u.test(approval.catalogSha256??'')||
    typeof approval.reviewReference!=='string'||!approval.reviewReference.trim())qaFail('QA_PROTOTYPE_REVIEW_REQUIRED');
}
export function assertPrototypeApproval(approval,snapshot){
 assertApprovalReady(approval);
 if(approval.catalogSha256!==digest(snapshot))qaFail('QA_PROTOTYPE_DRIFT');
}
export function assertMaterializedPlan(plan){
 if(plan?.steps?.length!==EXECUTION.length||plan.manifest?.apiWritesEnabled!==false)qaFail('QA_EXECUTION_ORDER_REFUSED');
 for(let i=0;i<EXECUTION.length;i++){
  const s=plan.steps[i],m=plan.manifest.steps[i],[version,path,kind]=EXECUTION[i];
  if(s.version!==version||s.path!==path||s.kind!==kind||s.sha256!==m?.sha256||bytesDigest(s.sql)!==s.sha256)qaFail('QA_SQL_CHECKSUM_MISMATCH');
 }
}
async function inspectTransaction(db,pins){
 await assertQaIdentity(db,pins,true);await assertApiSafety(db);await assertFreshPublic(db);
 const snapshot=await inspectPrototype(db);validatePrototype(snapshot);const ddlPermissions=await assertQaDdlPermissions(db,pins,snapshot);return {snapshot,ddlPermissions};
}
export async function preflightQa({plan,env,inspectOnly=false,inspectionApproval,verifyTarget=verifyQaTarget,openClient=openQaClient}){
 assertMaterializedPlan(plan);
 if(env.WALLET_QA_PREFLIGHT_ENABLED!=='1')qaFail('QA_PREFLIGHT_NOT_ENABLED');
 if(typeof inspectOnly!=='boolean')qaFail('QA_ACCESS_SCOPE_REFUSED');
 if(!inspectOnly)assertApprovalReady(plan.approval);
 if(!inspectOnly&&inspectionApproval!==undefined)qaFail('QA_ACCESS_SCOPE_REFUSED');
 const access=inspectOnly?{purpose:'inspect-prototype',inspectionApproval}:undefined;
 assertQaTarget(plan.pins,env,access);
 await verifyTarget(plan.pins,env,undefined,access);let db;
 try{
  db=await openClient(plan.pins,env,access);assertQaTarget(plan.pins,env,access);await db.query('BEGIN READ ONLY ISOLATION LEVEL REPEATABLE READ');
  await db.query("SET LOCAL search_path=public,pg_catalog");await db.query("SET LOCAL statement_timeout='10s'");
  const {snapshot,ddlPermissions}=await inspectTransaction(db,plan.pins);
  if(inspectOnly)assertQaTarget(plan.pins,env,access);
  if(!inspectOnly)assertPrototypeApproval(plan.approval,snapshot);
  return {ok:true,mode:'read-only-inspection',applyApproved:!inspectOnly,manifestSha256:plan.manifestSha256,prototype:safePrototypeSummary(snapshot),ddlPermissions};
 }catch(e){if(e instanceof WalletQaError)throw e;qaFail('QA_PREFLIGHT_FAILED');}
 finally{if(db){await db.query('ROLLBACK').catch(()=>{});await db.end().catch(()=>{});}}
}
export async function migrateQa(options){
 if(['inspectOnly','inspectionApproval','access','purpose'].some(k=>Object.hasOwn(options,k)))qaFail('QA_MIGRATION_INSPECTION_SCOPE_REFUSED');
 const {plan,env,verifyTarget=verifyQaTarget,openClient=openQaClient,verifyInstalled=verifyInstalledBaseline}=options;
 assertMaterializedPlan(plan);
 if(env.WALLET_QA_MIGRATION_ENABLED!=='1'||env.WALLET_QA_PREFLIGHT_ENABLED!=='1')qaFail('QA_MIGRATION_NOT_ENABLED');
 // Approval is required before any network call. Inspect mode never reaches here.
 assertApprovalReady(plan.approval);
 assertQaTarget(plan.pins,env);
 await preflightQa({plan,env,verifyTarget,openClient});
 await verifyTarget(plan.pins,env);let db,begun=false,commitSent=false;
 try{
  db=await openClient(plan.pins,env);await db.query('BEGIN');begun=true;
  await db.query("SET LOCAL search_path=public,pg_catalog");await db.query("SET LOCAL lock_timeout='5s'");await db.query("SET LOCAL statement_timeout='20s'");
  await assertQaIdentity(db,plan.pins,false);await assertApiSafety(db);
  await db.query("SELECT pg_advisory_xact_lock(hashtextextended('lunari-qa-baseline-v1',0))");
  await assertFreshPublic(db);
  await db.query('LOCK TABLE public.star_wallets,public.star_transactions IN ACCESS EXCLUSIVE MODE NOWAIT');
  const before=await inspectPrototype(db);validatePrototype(before);assertPrototypeApproval(plan.approval,before);
  await assertQaDdlPermissions(db,plan.pins,before);
  assertMaterializedPlan(plan);
  await db.query(`CREATE TABLE public.star_wallet_schema_migrations(version TEXT PRIMARY KEY,checksum CHAR(64) NOT NULL,applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)`);
  const applied=[];
  for(const step of plan.steps){
   await db.query(step.sql);
   await db.query('INSERT INTO public.star_wallet_schema_migrations(version,checksum) VALUES($1,$2)',[step.version,step.sha256]);
   applied.push(step.version);
  }
  const verification=await verifyInstalled(db,before);
  const history=(await db.query('SELECT version,checksum FROM public.star_wallet_schema_migrations ORDER BY version')).rows;
  if(digest(history)!==digest(plan.steps.map(s=>({version:s.version,checksum:s.sha256}))))qaFail('QA_HISTORY_VERIFICATION_FAILED');
  commitSent=true;await db.query('COMMIT');begun=false;
  return {ok:true,mode:'qa-baseline-applied',manifestSha256:plan.manifestSha256,applied,verification};
 }catch(e){
  if(commitSent)qaFail('QA_COMMIT_OUTCOME_UNCONFIRMED_DO_NOT_RETRY');
  if(begun){try{await db.query('ROLLBACK');begun=false;}catch{qaFail('QA_ROLLBACK_UNCONFIRMED_DO_NOT_RETRY');}}
  if(e instanceof WalletQaError)throw e;qaFail('QA_MIGRATION_FAILED_ROLLED_BACK');
 }finally{await db?.end().catch(()=>{});}
}
export function safeQaFailure(error){return {ok:false,code:error instanceof WalletQaError?error.code:'QA_UNEXPECTED_FAILURE_REDACTED'};}
