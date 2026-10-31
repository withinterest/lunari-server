import {createHash} from 'node:crypto';
import {qaFail} from './wallet-qa-target.js';
import {CANONICAL_TABLES} from './wallet-qa-catalog.js';
export const QA_V2_POLICY='qa-permanent-wallet-boundary-v2';
export const FUNCTION_PATH='search_path=pg_catalog, pg_temp';
const hash=s=>createHash('sha256').update(s).digest('hex');
const userSchema="n.nspname!~'^pg_' AND n.nspname<>'information_schema'";
export const QA_V2_SQL=Object.freeze({
 role:`SELECT /* qa-v2:role */ r.rolname,r.rolcanlogin,r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolreplication,r.rolbypassrls,r.rolinherit,
 (SELECT count(*)::int FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid) AS memberships,
 pg_catalog.has_database_privilege(r.oid,current_database(),'CREATE') AS database_create,
 pg_catalog.has_database_privilege(r.oid,current_database(),'TEMP') AS effective_temp,
 CASE WHEN pg_catalog.to_regnamespace('wallet_prototype_v1') IS NULL THEN false ELSE pg_catalog.has_schema_privilege(r.oid,'wallet_prototype_v1','USAGE') END AS archive_usage,
 EXISTS(SELECT 1 FROM pg_catalog.pg_database d CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(d.datacl,pg_catalog.acldefault('d',d.datdba))) a WHERE d.datname=current_database() AND a.grantee=0 AND a.privilege_type='TEMPORARY') AS public_temp,
 EXISTS(SELECT 1 FROM pg_catalog.pg_database d CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(d.datacl,pg_catalog.acldefault('d',d.datdba))) a WHERE d.datname=current_database() AND a.grantee=r.oid AND a.privilege_type='TEMPORARY') AS direct_temp,
 (SELECT count(*)::int FROM pg_catalog.pg_class c WHERE c.relowner=r.oid AND c.relpersistence<>'t')+
 (SELECT count(*)::int FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE p.proowner=r.oid AND n.nspname!~'^pg_(toast_)?temp_[0-9]+$')+
 (SELECT count(*)::int FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace WHERE t.typowner=r.oid AND n.nspname!~'^pg_(toast_)?temp_[0-9]+$')+
 (SELECT count(*)::int FROM pg_catalog.pg_namespace n WHERE n.nspowner=r.oid AND n.nspname!~'^pg_(toast_)?temp_[0-9]+$')+
 (SELECT count(*)::int FROM pg_catalog.pg_database d WHERE d.datdba=r.oid) AS permanent_owned_objects,
 EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname!~'^pg_(toast_)?temp_[0-9]+$' AND pg_catalog.has_schema_privilege(r.oid,n.oid,'CREATE')) AS permanent_schema_create,
 EXISTS(SELECT 1 FROM pg_catalog.pg_default_acl d CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a WHERE a.grantee=r.oid) AS future_grants,
 EXISTS(SELECT 1 FROM pg_catalog.pg_default_acl d CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a WHERE a.grantee=0 AND d.defaclobjtype<>'f') AS unsafe_public_defaults,
 EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a WHERE n.nspname='public' AND a.grantee=0 AND a.privilege_type='CREATE') AS public_schema_create,
 EXISTS(SELECT 1 FROM pg_catalog.pg_roles other WHERE other.rolname NOT IN($2,'neon_superuser','pg_database_owner') AND NOT other.rolsuper
 AND NOT pg_catalog.pg_has_role(other.oid,'neon_superuser','USAGE') AND pg_catalog.has_schema_privilege(other.oid,'public','CREATE')) AS untrusted_public_creator
 FROM pg_catalog.pg_roles r WHERE r.rolname=$1`,
 relations:`SELECT /* qa-v2:relations */ n.nspname AS schema,c.relname AS name,c.relkind,c.relpersistence
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE ${userSchema} AND c.relkind IN('r','p','v','m','f','S') ORDER BY n.nspname,c.relname`,
 privileges:`SELECT /* qa-v2:privileges */ CASE WHEN c.relkind='S' THEN 'sequence' ELSE 'table' END AS kind,n.nspname AS schema,c.relname AS name,''::text AS column,
 CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE 'API' END AS principal,a.privilege_type AS privilege,a.is_grantable AS grantable
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault(CASE WHEN c.relkind='S' THEN 's'::"char" ELSE 'r'::"char" END,c.relowner))) a
 WHERE ${userSchema} AND c.relkind IN('r','p','v','m','f','S') AND a.grantee IN(0,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1))
 UNION ALL SELECT 'column',n.nspname,c.relname,att.attname,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE 'API' END,a.privilege_type,a.is_grantable
 FROM pg_catalog.pg_attribute att JOIN pg_catalog.pg_class c ON c.oid=att.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(att.attacl) a WHERE ${userSchema} AND att.attnum>0 AND NOT att.attisdropped AND a.grantee IN(0,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1))
 UNION ALL SELECT 'schema',n.nspname,n.nspname,'',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE 'API' END,a.privilege_type,a.is_grantable
 FROM pg_catalog.pg_namespace n CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
 WHERE ${userSchema} AND a.grantee IN(0,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1))`,
 functions:`SELECT /* qa-v2:functions */ n.nspname AS schema,p.proname AS name,p.proargtypes::text AS args,p.prorettype::text AS returns,
 pg_catalog.pg_get_userbyid(p.proowner)::text AS owner,l.lanname AS language,p.prokind,p.prosecdef,p.proconfig,p.prosrc,
 pg_catalog.has_function_privilege($1,p.oid,'EXECUTE') AS api_execute,
 EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_language l ON l.oid=p.prolang WHERE ${userSchema} ORDER BY n.nspname,p.proname,p.oid`,
 session:`SELECT /* qa-v2:session */ current_user=$1 AND session_user=current_user AS identity_ok,
 current_setting('transaction_read_only')='on' AS read_only,pg_catalog.pg_my_temp_schema()=0 AS no_temp_namespace,
 current_setting('search_path')='pg_catalog, pg_temp' AS safe_path`
});
function requireArray(value){if(!Array.isArray(value))qaFail('QA_V2_EVIDENCE_INCOMPLETE');return value;}
const key=o=>`${o.schema}.${o.name}`;
export function validateQaV2Role(r){
 if(!r||r.rolname!=='lunari_wallet_api_check'||r.rolcanlogin!==true||
 ['rolsuper','rolcreatedb','rolcreaterole','rolreplication','rolbypassrls','rolinherit','database_create','direct_temp','permanent_schema_create','future_grants','unsafe_public_defaults','public_schema_create','untrusted_public_creator','archive_usage'].some(k=>r[k]!==false)||
 r.memberships!==0||r.permanent_owned_objects!==0||r.public_temp!==true||r.effective_temp!==true)qaFail('QA_V2_API_PRIVILEGES_UNSAFE');
}
export function validateQaV2Session(r){
 if(!r||!['identity_ok','read_only','no_temp_namespace','safe_path'].every(k=>r[k]===true))qaFail('QA_V2_SESSION_UNSAFE_DISCARD_CONNECTION');
}
export function validateQaV2Security(e,{phase,migrationRole,expectedFunctions,expectedSequences=[]}={}){
 if(!['prototype','installed'].includes(phase)||migrationRole!=='neondb_owner')qaFail('QA_V2_SCOPE_UNSUPPORTED');
 validateQaV2Role(e.role);
 const expectedTables=phase==='prototype'?['public.star_wallets','public.star_transactions']:
 [...CANONICAL_TABLES.map(n=>'public.'+n),'public.star_wallet_schema_migrations','wallet_prototype_v1.star_wallets','wallet_prototype_v1.star_transactions'];
 const relations=requireArray(e.relations),tables=relations.filter(r=>r.relkind==='r').map(key).sort();
 if(JSON.stringify(tables)!==JSON.stringify([...expectedTables].sort())||relations.some(r=>r.relpersistence!=='p'||!['r','S'].includes(r.relkind)))qaFail('QA_V2_RELATION_SET_MISMATCH');
 if(JSON.stringify(relations.filter(r=>r.relkind==='S').map(key).sort())!==JSON.stringify([...expectedSequences].sort()))qaFail('QA_V2_SEQUENCE_SET_MISMATCH');
 for(const p of requireArray(e.privileges)){
  const schemaUsage=p.kind==='schema'&&p.schema==='public'&&p.name==='public'&&p.column===''&&p.privilege==='USAGE'&&['API','PUBLIC'].includes(p.principal);
  const prototypeSelect=phase==='prototype'&&p.kind==='table'&&expectedTables.includes(key(p))&&p.column===''&&p.principal==='API'&&p.privilege==='SELECT';
  // Existing prototype table ACLs are preserved; schema USAGE is denied above.
  const quarantinedSelect=phase==='installed'&&p.kind==='table'&&['wallet_prototype_v1.star_wallets','wallet_prototype_v1.star_transactions'].includes(key(p))&&p.column===''&&p.principal==='API'&&p.privilege==='SELECT';
  if(p.grantable!==false||!(schemaUsage||prototypeSelect||quarantinedSelect))qaFail('QA_V2_PRIVILEGE_NOT_ALLOWLISTED');
 }
 const functions=requireArray(e.functions),expected=requireArray(expectedFunctions);
 if(!expected.length||functions.length!==expected.length)qaFail('QA_V2_FUNCTION_SET_MISMATCH');
 const seen=new Set();
 for(const f of functions){
  const id=`${key(f)}(${f.args})`,spec=expected.find(s=>`${key(s)}(${s.args})`===id);
  if(!spec||seen.has(id))qaFail('QA_V2_FUNCTION_SET_MISMATCH');seen.add(id);
  if(f.owner!==migrationRole||f.prokind!=='f'||f.language!==spec.language||f.returns!==spec.returns||
  f.prosecdef!==spec.securityDefiner||typeof f.prosrc!=='string'||hash(f.prosrc)!==spec.bodySha256||
  f.api_execute!==false||f.public_execute!==false||JSON.stringify(f.proconfig)!==JSON.stringify(spec.proconfig))qaFail('QA_V2_FUNCTION_BOUNDARY_UNSAFE');
 }
 return {policy:QA_V2_POLICY,phase,catalogChecksPassed:true,publicTempRetained:true,apiWritesEnabled:false,
 functionCount:functions.length,liveTempAttackVerified:false,runtimeEnabled:false};
}
export async function collectQaV2Security(db,{apiRole,migrationRole}){
 if(apiRole!=='lunari_wallet_api_check'||migrationRole!=='neondb_owner')qaFail('QA_V2_SCOPE_UNSUPPORTED');
 const result={};
 for(const [name,sql] of Object.entries(QA_V2_SQL)){
  if(name==='session')continue;
  const args=name==='role'?[apiRole,migrationRole]:name==='relations'?[]:[apiRole];
  const rows=requireArray((await db.query(sql,args)).rows);
  if(name==='role'){if(rows.length!==1)qaFail('QA_V2_EVIDENCE_INCOMPLETE');result.role=rows[0];}else result[name]=rows;
 }
 return result;
}
export function prototypeFunctionSpecs(snapshot){
 return requireArray(snapshot.functions).map(f=>({schema:'public',name:f.proname,args:f.argument_type_oids,returns:f.return_type_oid,
 language:f.lanname,securityDefiner:false,proconfig:f.proconfig,bodySha256:hash(f.prosrc)}));
}
// A separate READ ONLY probe, never wired into the existing runtime. Every probe
// connection is destroyed, including success: unexamined session GUCs/prepared
// statements must never survive and reach another account via this helper.
export async function withQaV2CleanReadOnlySession(pool,work){
 let db,begun=false;
 try{
  db=await pool.connect();await db.query('BEGIN READ ONLY');begun=true;
  await db.query('SET LOCAL search_path=pg_catalog, pg_temp');
  const rows=(await db.query(QA_V2_SQL.session,['lunari_wallet_api_check'])).rows;
  if(!Array.isArray(rows)||rows.length!==1)qaFail('QA_V2_SESSION_UNSAFE_DISCARD_CONNECTION');
  validateQaV2Session(rows[0]);return await work(db);
 }finally{if(db){try{if(begun){try{await db.query('ROLLBACK');}catch{qaFail('QA_V2_ROLLBACK_UNCONFIRMED');}}}finally{db.release(true);}}}
}
