import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {QA_V2_SQL} from './wallet-qa-security-v2.js';
import {digest} from './wallet-qa-catalog.js';
import {collectInstalledShapeV2} from './wallet-qa-installed-v2.js';
import {loadQaV2DraftPlan} from './wallet-qa-plan-v2.js';
export const PURCHASE_API='lunari_purchase_api_qa', PURCHASE_OWNER='lunari_purchase_fn_owner_qa';
export const PURCHASE_FUNCTION='wallet_purchase_api.apply_verified_google_purchase';
export const sha=s=>createHash('sha256').update(s).digest('hex');
export const refuse=code=>{throw Object.assign(new Error(code),{code});};
export async function loadPurchasePlan(){
 const root=new URL('../migrations/wallet-purchase-qa-v1/',import.meta.url);
 const manifest=JSON.parse(await readFile(new URL('manifest.json',root),'utf8'));
 if(manifest.status!=='draft-local-only'||manifest.executionEnabled!==false||manifest.files.length!==4)refuse('PURCHASE_PLAN_UNAPPROVED');
 const names=['010_roles.sql','020_function.sql','030_activate.sql','040_disable.sql'];
 const files=[];for(let i=0;i<names.length;i++){if(manifest.files[i].name!==names[i])refuse('PURCHASE_PLAN_ORDER');const sql=await readFile(new URL(names[i],root),'utf8');if(sha(sql)!==manifest.files[i].sha256)refuse('PURCHASE_PLAN_CHECKSUM');files.push(sql);}
 const body=files[1].split('$purchase$')[1];if(!body)refuse('PURCHASE_BODY_MISSING');
 const bytes=await readFile(new URL('../migrations/wallet-baseline-v2/installed-reference-pg18.json',import.meta.url));
 if(sha(bytes)!==manifest.baselinePg18ReferenceSha256)refuse('PURCHASE_BASE_REFERENCE_CHECKSUM');
 const baselineShape=JSON.parse(bytes).shape;
 const base=await loadQaV2DraftPlan();return{manifest,files,bodySha256:sha(body),baseFunctions:base.expectedFunctions,baselineShape};
}
const allowedColumns={
 'public.purchase_claims':{SELECT:['token_hash','claim_id','claimant_id','product_id','grant_stars','package_name','purchase_state'],INSERT:['token_hash','package_name','product_id','claimant_id','grant_stars','purchase_state','google_order_id','claim_id']},
 'public.star_wallets':{SELECT:['user_uid','balance'],UPDATE:['balance','updated_at']},
 'public.star_wallet_transactions':{SELECT:['purchase_claim_id','transaction_key','transaction_id','user_uid','delta','balance_after','request_fingerprint'],INSERT:['transaction_id','user_uid','transaction_key','request_fingerprint','transaction_type','delta','balance_after','reason_code','purchase_claim_id']}
};
function validateRole(r,owner){
 if(!r||r.rolname!==(owner?PURCHASE_OWNER:PURCHASE_API)||r.rolcanlogin!==!owner||r.memberships!==0||r.inbound_memberships!==0||r.permanent_owned_objects!==(owner?1:0)||r.public_temp!==true||r.effective_temp!==true)refuse('PURCHASE_ROLE_UNSAFE');
 for(const k of ['rolsuper','rolcreatedb','rolcreaterole','rolreplication','rolbypassrls','rolinherit','database_create','direct_temp','permanent_schema_create','future_grants','unsafe_public_defaults','public_schema_create','untrusted_public_creator','archive_usage'])if(r[k]!==false)refuse('PURCHASE_ROLE_UNSAFE');
}
function validatePrivileges(rows,owner){
 if(!Array.isArray(rows))refuse('PURCHASE_ACL_MISSING');const seen=new Set();
 for(const p of rows){
  const schema=p.kind==='schema'&&p.name===p.schema&&['public','wallet_purchase_api'].includes(p.schema)&&p.column===''&&p.privilege==='USAGE'&&(p.schema==='public'||p.principal==='API');
  const col=owner&&p.principal==='API'&&p.kind==='column'&&allowedColumns[p.schema+'.'+p.name]?.[p.privilege]?.includes(p.column);
  if(p.grantable!==false||!(schema||col))refuse('PURCHASE_ACL_UNSAFE');
  if(col)seen.add(p.schema+'.'+p.name+':'+p.privilege+':'+p.column);
 }
 if(owner)for(const [table,privs] of Object.entries(allowedColumns))for(const [priv,cols] of Object.entries(privs))for(const c of cols)if(!seen.has(table+':'+priv+':'+c))refuse('PURCHASE_ACL_INCOMPLETE');
 if(!rows.some(p=>p.principal==='API'&&p.kind==='schema'&&p.schema==='wallet_purchase_api'&&p.privilege==='USAGE'))refuse('PURCHASE_SCHEMA_USAGE_MISSING');
}
export async function collectPurchaseBoundary(db){
 const out={};for(const [tag,role] of [['api',PURCHASE_API],['owner',PURCHASE_OWNER]]){
 out[tag]={role:(await db.query(QA_V2_SQL.role,[role,'neondb_owner'])).rows[0],privileges:(await db.query(QA_V2_SQL.privileges,[role])).rows,functions:(await db.query(QA_V2_SQL.functions,[role])).rows};
 }
 for(const [tag,role] of [['api',PURCHASE_API],['owner',PURCHASE_OWNER]]){
  const r=(await db.query('SELECT count(*)::int AS n FROM pg_catalog.pg_auth_members WHERE roleid=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1)',[role])).rows[0];
  if(out[tag].role)out[tag].role.inbound_memberships=r?.n;
 }
 out.functionAcl=(await db.query(`SELECT pg_catalog.pg_get_userbyid(a.grantee)::text AS grantee,a.privilege_type,a.is_grantable
  FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
  WHERE n.nspname='wallet_purchase_api' AND p.proname='apply_verified_google_purchase'`)).rows;
 out.allFunctionAcl=(await db.query(`SELECT n.nspname AS schema,p.proname AS name,p.proargtypes::text AS args,
 pg_catalog.pg_get_userbyid(a.grantee)::text AS grantee,a.privilege_type,a.is_grantable
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
 WHERE n.nspname IN('public','wallet_prototype_v1')`)).rows;
 out.schemaAcl=(await db.query(`SELECT pg_catalog.pg_get_userbyid(a.grantee)::text AS grantee,a.privilege_type,a.is_grantable
 FROM pg_catalog.pg_namespace n CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
 WHERE n.nspname='wallet_purchase_api'`)).rows;
 out.schema=(await db.query("SELECT pg_catalog.pg_get_userbyid(nspowner)::text AS owner FROM pg_catalog.pg_namespace WHERE nspname='wallet_purchase_api'")).rows;
 // Match the immutable baseline's deparser context, for catalog reflection ONLY.
 // All reflection queries use pg_catalog-qualified functions/relations. Restore the
 // original path before returning; caller discards the connection on any failure.
 const previous=(await db.query("SELECT current_setting('search_path') AS path")).rows[0]?.path;
 if(typeof previous!=='string')refuse('PURCHASE_REFLECTION_CONTEXT');
 try{await db.query("SELECT pg_catalog.set_config('search_path','public,pg_catalog,pg_temp',false)");out.baselineShape=await collectInstalledShapeV2(db);}
 finally{await db.query("SELECT pg_catalog.set_config('search_path',$1,false)",[previous]);}
 return out;
}
export function validatePurchaseBoundary(e,plan,{archiveFunctions=[],active=true}={}){
 if(!e||!plan?.baseFunctions||!Array.isArray(archiveFunctions))refuse('PURCHASE_EVIDENCE_MISSING');
 if(!Array.isArray(e.schema)||e.schema.length!==1||e.schema[0].owner!=='neondb_owner'||!Array.isArray(e.functionAcl))refuse('PURCHASE_SCHEMA_OWNER_UNSAFE');
 if(!Array.isArray(e.allFunctionAcl)||e.allFunctionAcl.some(a=>a.grantee!=='neondb_owner'||a.privilege_type!=='EXECUTE'))refuse('PURCHASE_BASE_EXECUTE_ACL_UNSAFE');
 if(!Array.isArray(e.schemaAcl)||e.schemaAcl.some(a=>a.grantee==='neondb_owner'?!['USAGE','CREATE'].includes(a.privilege_type):![PURCHASE_API,PURCHASE_OWNER].includes(a.grantee)||a.privilege_type!=='USAGE'||a.is_grantable!==false))refuse('PURCHASE_SCHEMA_ACL_UNSAFE');
 const acl=e.functionAcl;
 if(acl.some(a=>![PURCHASE_OWNER,...(active?[PURCHASE_API]:[])].includes(a.grantee)||a.privilege_type!=='EXECUTE'||a.grantee===PURCHASE_API&&a.is_grantable!==false)||!acl.some(a=>a.grantee===PURCHASE_OWNER)||active&&!acl.some(a=>a.grantee===PURCHASE_API))refuse('PURCHASE_EXECUTE_ACL_UNSAFE');
 validateRole(e.api?.role,false);validateRole(e.owner?.role,true);validatePrivileges(e.api.privileges,false);validatePrivileges(e.owner.privileges,true);
 if(!plan.baselineShape||digest(e.baselineShape)!==digest(plan.baselineShape))refuse('PURCHASE_BASE_SCHEMA_DRIFT');
 const expected=[...plan.baseFunctions,...archiveFunctions];
 for(const tag of ['api','owner']){
 const fs=e[tag].functions;if(!Array.isArray(fs)||fs.length!==expected.length+1)refuse('PURCHASE_FUNCTION_SET');
 const seen=new Set();for(const f of fs){
 const id=f.schema+'.'+f.name+'('+f.args+')';if(seen.has(id))refuse('PURCHASE_FUNCTION_SET');seen.add(id);
 const own=f.schema+'.'+f.name===PURCHASE_FUNCTION&&f.args==='25 25 25 25';
 const spec=expected.find(s=>s.schema===f.schema&&s.name===f.name&&s.args===f.args);
 if(own){
  if(f.owner!==PURCHASE_OWNER||f.language!=='plpgsql'||f.prokind!=='f'||f.returns!=='2249'||f.prosecdef!==true||sha(f.prosrc)!==plan.bodySha256||JSON.stringify(f.proconfig)!==JSON.stringify(['search_path=pg_catalog, pg_temp'])||f.public_execute!==false||f.api_execute!==(tag==='owner'||active))refuse('PURCHASE_FUNCTION_UNSAFE');
 }else if(!spec||f.owner!=='neondb_owner'||f.prokind!=='f'||f.language!==spec.language||f.returns!==spec.returns||f.prosecdef!==spec.securityDefiner||sha(f.prosrc)!==spec.bodySha256||JSON.stringify(f.proconfig)!==JSON.stringify(spec.proconfig)||f.public_execute!==false||f.api_execute!==false)refuse('PURCHASE_BASE_FUNCTION_DRIFT');
 }
 }
 return{ok:true,policy:'purchase-qa-function-boundary-v1',active,apiDirectWrites:false,publicTempRetained:true};
}
