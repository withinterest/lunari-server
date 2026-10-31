import {readFile,realpath} from 'node:fs/promises';
import {resolve,dirname,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {loadQaPlan} from './wallet-baseline-plan.js';
import {qaFail} from './wallet-qa-target.js';
import {prototypeFunctionSpecs} from './wallet-qa-security-v2.js';
const ROOT=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const hash=s=>createHash('sha256').update(s).digest('hex');
const B='migrations/wallet-baseline-v2/';
const ORDER=[B+'010_security_prerequisites.sql','migrations/wallet-baseline-v1/000_archive_prototype.sql',
 'migrations/001_create_purchase_claims.sql','migrations/002_create_star_wallet.sql',
 'migrations/003_wallet_rewards.sql','migrations/004_wallet_security.sql',
 'migrations/wallet-baseline-v1/006_lease_objects.sql',B+'020_harden_function_paths.sql'];
const VERSIONS=['qa-baseline-v2:security-prerequisites','qa-baseline-v2:prototype-archive','001','002','003','004','qa-baseline-v2:lease-objects','qa-baseline-v2:function-paths'];
const SHAPES={star_wallet_reject_ledger_mutation:['','2279','plpgsql',false],star_wallet_reserve_event_key:['','2279','plpgsql',true],
 star_wallet_acquire_limit:['25 25 2950','2249','plpgsql',true],star_wallet_release_limit:['2950 25','2278','sql',true],
 star_wallet_verified_welcome_approval:['25','2249','sql',true],star_wallet_assert_active_lease:['2950 25','2278','plpgsql',true]};
async function checkedRead(root,path){
 const wanted=resolve(root,path),actual=await realpath(wanted),base=await realpath(root);
 if(actual!==wanted||!actual.startsWith(base+sep))qaFail('QA_V2_PLAN_PATH_REFUSED');return readFile(actual);
}
export async function loadQaV2DraftPlan({root=ROOT}={}){
 // Reuse original source/provenance checks, not v1's executable security policy.
 const v1=await loadQaPlan({root});
 const manifest=JSON.parse((await checkedRead(root,B+'manifest.json')).toString('utf8'));
 if(manifest.schemaVersion!==2||manifest.planId!=='wallet-qa-baseline-v2'||manifest.policy!=='qa-permanent-wallet-boundary-v2'||
 manifest.status!=='draft-review-required'||manifest.executionEnabled!==false||manifest.apiWritesEnabled!==false||
 JSON.stringify(manifest.sources)!==JSON.stringify(v1.manifest.sources)||manifest.steps?.length!==ORDER.length)qaFail('QA_V2_DRAFT_MANIFEST_INVALID');
 const steps=[];
 for(let i=0;i<ORDER.length;i++){
  const s=manifest.steps[i];if(s.path!==ORDER[i]||s.version!==VERSIONS[i]||s.kind!==(/^\d+$/u.test(s.version)?'original':'derived-or-preserved')||!/^([a-f0-9]{64})$/u.test(s.sha256??''))qaFail('QA_V2_DRAFT_ORDER_INVALID');
  const bytes=await checkedRead(root,s.path);if(hash(bytes)!==s.sha256)qaFail('QA_V2_DRAFT_CHECKSUM_MISMATCH');
  const sql=bytes.toString('utf8');
  if(/^\s*(CREATE|ALTER|DROP)\s+ROLE\b/im.test(sql)||/^\s*GRANT\b/im.test(sql)||/^\s*(DROP\s+(TABLE|SCHEMA)|TRUNCATE)\b/im.test(sql))qaFail('QA_V2_DRAFT_SQL_REFUSED');
  steps.push({...s,sql});
 }
 const expectedFunctions=[];
 for(const path of ['migrations/002_create_star_wallet.sql','migrations/004_wallet_security.sql','migrations/wallet-baseline-v1/006_lease_objects.sql']){
  const sql=(await checkedRead(root,path)).toString('utf8');
  const rx=/CREATE FUNCTION\s+public\.(\w+)\([\s\S]*?\bAS\s*\$\$([\s\S]*?)\$\$\s*;/g;
  for(const match of sql.matchAll(rx)){
   const shape=SHAPES[match[1]];if(!shape||expectedFunctions.some(f=>f.name===match[1]))qaFail('QA_V2_FUNCTION_SOURCE_UNEXPECTED');
   expectedFunctions.push({schema:'public',name:match[1],args:shape[0],returns:shape[1],language:shape[2],securityDefiner:shape[3],
    proconfig:['search_path=pg_catalog, pg_temp'],bodySha256:hash(match[2])});
  }
 }
 if(expectedFunctions.length!==6)qaFail('QA_V2_FUNCTION_SOURCE_INCOMPLETE');
 return {manifest,steps,expectedFunctions,pins:v1.pins,prototypeApproval:v1.approval,executionEnabled:false};
}
export function refuseQaV2Apply(){qaFail('QA_V2_APPLY_NOT_IMPLEMENTED_OR_APPROVED');}
export function installedQaV2Options(plan,reviewedPrototype){
 if(plan?.manifest?.planId!=='wallet-qa-baseline-v2'||plan.executionEnabled!==false||plan.expectedFunctions?.length!==6)qaFail('QA_V2_DRAFT_MANIFEST_INVALID');
 return {phase:'installed',migrationRole:plan.pins.migrationRole,
  expectedFunctions:[...plan.expectedFunctions,...prototypeFunctionSpecs(reviewedPrototype).map(s=>({...s,schema:'wallet_prototype_v1'}))],
  expectedSequences:['public.star_wallet_transactions_ledger_sequence_seq',...reviewedPrototype.sequences.map(s=>'wallet_prototype_v1.'+s.relname)]};
}
