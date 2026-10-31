import {createHash} from 'node:crypto';
import {qaFail} from './wallet-qa-target.js';
export const CANONICAL_TABLES = Object.freeze(['purchase_claims','star_wallets','star_wallet_transactions',
 'star_wallet_unlocks','star_wallet_local_migrations','star_wallet_reward_eligibilities','star_wallet_reward_claims',
 'star_wallet_operation_requests','star_wallet_event_keys','star_wallet_rate_state','star_wallet_rate_leases',
 'star_wallet_welcome_approvals','star_wallet_welcome_grant_evidence']);
export const CANONICAL_FUNCTIONS = Object.freeze(['star_wallet_reject_ledger_mutation','star_wallet_reserve_event_key',
 'star_wallet_acquire_limit','star_wallet_release_limit','star_wallet_verified_welcome_approval','star_wallet_assert_active_lease']);
function canonical(value) {
 if (Array.isArray(value)) return value.map(canonical).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b),'en'));
 if (value && typeof value==='object') return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])]));
 return value;
}
export const digest = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
export const bytesDigest = value => createHash('sha256').update(value).digest('hex');
export async function assertQaIdentity(db,pins,readonly) {
 const r=(await db.query(`SELECT current_database()=$1 AS database_ok,
 current_user=$2 AND session_user=current_user AS role_ok,
 current_setting('transaction_read_only')=$3 AS transaction_ok`,[pins.database,pins.migrationRole,readonly?'on':'off'])).rows[0];
 if (!r || !['database_ok','role_ok','transaction_ok'].every(k=>r[k]===true)) qaFail('QA_DATABASE_IDENTITY_FAILED');
}
export async function assertApiSafety(db) {
 const rows=(await db.query(`SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolinherit,
 (SELECT count(*)::int FROM pg_auth_members m WHERE m.member=r.oid) AS memberships,
 (SELECT count(*)::int FROM pg_class c WHERE c.relowner=r.oid)+(SELECT count(*)::int FROM pg_proc p WHERE p.proowner=r.oid)+(SELECT count(*)::int FROM pg_namespace n WHERE n.nspowner=r.oid) AS owned_objects,
 has_database_privilege(r.oid,current_database(),'CREATE,TEMP') AS database_ddl,
 EXISTS(SELECT 1 FROM pg_namespace n WHERE has_schema_privilege(r.oid,n.oid,'CREATE')) AS schema_create,
 EXISTS(SELECT 1 FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a WHERE a.grantee=r.oid) AS future_grants
 FROM pg_roles r WHERE rolname='lunari_wallet_api_check'`)).rows;
 const r=rows[0];
 if(rows.length!==1||r.rolcanlogin!==true||['rolsuper','rolcreatedb','rolcreaterole','rolreplication','rolbypassrls','rolinherit','database_ddl','schema_create','future_grants'].some(k=>r[k]!==false)||r.memberships!==0||r.owned_objects!==0) qaFail('QA_API_PRIVILEGES_UNSAFE');
 return r;
}
export async function inspectPrototype(db,schema='public') {
 if(!['public','wallet_prototype_v1'].includes(schema)) qaFail('QA_SCHEMA_REFUSED');
 const relations=(await db.query(`SELECT c.oid::text AS oid,c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,c.relispartition,c.relowner::text AS owner_oid,c.relacl::text AS acl
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname IN('star_wallets','star_transactions') ORDER BY c.relname`,[schema])).rows;
 const columns=(await db.query(`SELECT c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod) AS type,
 a.atttypid::text AS type_oid,a.atttypmod,a.attnotnull,a.attidentity,a.attgenerated,
 pg_get_expr(d.adbin,d.adrelid) AS default_sql,d.adbin::text AS default_tree,a.attacl::text AS acl
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
 WHERE n.nspname=$1 AND c.relname IN('star_wallets','star_transactions') AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum`,[schema])).rows;
 const constraints=(await db.query(`SELECT c.relname,k.oid::text AS oid,k.conname,k.contype,k.conkey,k.confkey,k.confrelid::text AS referenced_oid,k.condeferrable,k.condeferred,k.convalidated,
 pg_get_constraintdef(k.oid,true) AS definition,k.conbin::text AS expression_tree
 FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname IN('star_wallets','star_transactions') ORDER BY c.relname,k.conname`,[schema])).rows;
 const indexes=(await db.query(`SELECT c.relname,i.indexrelid::text AS oid,ic.relname AS index_name,i.indisunique,i.indisprimary,i.indisvalid,i.indkey::text AS keys,i.indclass::text AS classes,i.indpred::text AS predicate_tree,i.indexprs::text AS expression_tree,pg_get_indexdef(i.indexrelid) AS definition
 FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_class ic ON ic.oid=i.indexrelid WHERE n.nspname=$1 AND c.relname IN('star_wallets','star_transactions') ORDER BY c.relname,ic.relname`,[schema])).rows;
 const triggers=(await db.query(`SELECT c.relname,t.oid::text AS oid,t.tgname,t.tgisinternal,t.tgfoid::text AS function_oid,pg_get_triggerdef(t.oid,true) AS definition
 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname IN('star_wallets','star_transactions') ORDER BY c.relname,t.tgname`,[schema])).rows;
 const sequences=(await db.query(`SELECT sc.oid::text AS oid,sc.relname,sc.relowner::text AS owner_oid,sc.relacl::text AS acl,
 s.seqstart::text,s.seqincrement::text,s.seqmax::text,s.seqmin::text,s.seqcache::text,s.seqcycle,d.refobjid::text AS owner_table_oid,d.refobjsubid AS owner_column
 FROM pg_sequence s JOIN pg_class sc ON sc.oid=s.seqrelid JOIN pg_depend d ON d.classid='pg_class'::regclass AND d.objid=sc.oid AND d.refclassid='pg_class'::regclass AND d.deptype IN('a','i')
 JOIN pg_class t ON t.oid=d.refobjid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=$1 AND t.relname IN('star_wallets','star_transactions') ORDER BY sc.oid`,[schema])).rows;
 const functions=(await db.query(`SELECT p.oid::text AS oid,p.proname,p.prokind,p.prosecdef,p.proowner::text AS owner_oid,
 l.lanname,p.prosrc,p.probin,p.proconfig,p.provolatile,p.proparallel,p.prorettype::text AS return_type_oid,p.proargtypes::text AS argument_type_oids,
 pg_get_function_identity_arguments(p.oid) AS identity_arguments,pg_get_functiondef(p.oid) AS definition,p.proacl::text AS acl,
 has_function_privilege('lunari_wallet_api_check',p.oid,'EXECUTE') AS api_execute,
 EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname=$1 AND p.proname='process_star_transaction' ORDER BY p.oid`,[schema])).rows;
 const dependencies=(await db.query(`WITH targets AS (
 SELECT 'pg_class'::regclass::oid AS classid,c.oid AS objid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname IN('star_wallets','star_transactions')
 UNION ALL SELECT 'pg_proc'::regclass::oid,p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1 AND p.proname='process_star_transaction')
 SELECT d.classid::text,d.objid::text,d.objsubid,d.refclassid::text,d.refobjid::text,d.refobjsubid,d.deptype,
 pg_describe_object(d.classid,d.objid,d.objsubid) AS dependent,pg_describe_object(d.refclassid,d.refobjid,d.refobjsubid) AS referenced
 FROM pg_depend d WHERE EXISTS(SELECT 1 FROM targets t WHERE (t.classid=d.classid AND t.objid=d.objid) OR (t.classid=d.refclassid AND t.objid=d.refobjid))
 ORDER BY d.classid,d.objid,d.objsubid,d.refclassid,d.refobjid,d.refobjsubid`,[schema])).rows;
 const unsupported=(await db.query(`WITH targets AS (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname IN('star_wallets','star_transactions'))
 SELECT EXISTS(SELECT 1 FROM pg_constraint k WHERE k.contype='f' AND ((k.conrelid IN(SELECT oid FROM targets))<>(k.confrelid IN(SELECT oid FROM targets)))) AS external_fk,
 EXISTS(SELECT 1 FROM pg_inherits i WHERE i.inhrelid IN(SELECT oid FROM targets) OR i.inhparent IN(SELECT oid FROM targets)) AS inheritance,
 EXISTS(SELECT 1 FROM pg_depend d JOIN pg_rewrite r ON d.classid='pg_rewrite'::regclass AND r.oid=d.objid WHERE d.refclassid='pg_class'::regclass AND d.refobjid IN(SELECT oid FROM targets)) AS dependent_view,
 EXISTS(SELECT 1 FROM pg_depend d WHERE d.deptype='e' AND ((d.classid='pg_class'::regclass AND d.objid IN(SELECT oid FROM targets)) OR (d.classid='pg_proc'::regclass AND d.objid IN(SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1 AND p.proname='process_star_transaction')))) AS extension_owned`,[schema])).rows[0];
 const privileges=(await db.query(`SELECT c.relname,
 has_table_privilege('lunari_wallet_api_check',c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') OR has_any_column_privilege('lunari_wallet_api_check',c.oid,'INSERT,UPDATE') AS api_write
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname IN('star_wallets','star_transactions') ORDER BY c.relname`,[schema])).rows;
 const counts={};
 if(relations.length===2&&relations.every(r=>r.relkind==='r')) {
  for(const table of ['star_wallets','star_transactions']) counts[table]=Number((await db.query('SELECT count(*)::text AS count FROM '+schema+'.'+table)).rows[0].count);
 }
 return {relations,columns,constraints,indexes,triggers,sequences,functions,dependencies,unsupported,privileges,counts};
}
export function validatePrototype(s) {
 if(s.relations.length!==2||s.relations.some(r=>r.relkind!=='r'||r.relpersistence!=='p'||r.relrowsecurity||r.relforcerowsecurity||r.relispartition)||
    s.functions.length!==1||s.functions[0].prokind!=='f'||s.functions[0].prosecdef!==false||s.functions[0].api_execute!==false||s.functions[0].public_execute!==false||
    !s.unsupported||Object.values(s.unsupported).some(v=>v!==false)||s.triggers.some(t=>!t.tgisinternal)||s.privileges.length!==2||s.privileges.some(p=>p.api_write!==false)||
    s.counts.star_wallets!==0||s.counts.star_transactions!==0) qaFail('QA_PROTOTYPE_UNSUPPORTED');
 const cols=s.columns.filter(c=>c.relname==='star_wallets');
 const uid=cols.find(c=>c.attname==='user_id'),balance=cols.find(c=>c.attname==='balance');
 if(cols.length!==4||uid?.type!=='uuid'||uid.attnotnull!==true||balance?.type!=='integer'||
    !cols.some(c=>c.attname==='created_at')||!cols.some(c=>c.attname==='updated_at')||
    !s.constraints.some(c=>c.relname==='star_wallets'&&c.contype==='p'&&JSON.stringify(c.conkey)===JSON.stringify([uid.attnum]))) qaFail('QA_PROTOTYPE_IDENTITY_MISMATCH');
}
export function preservationStamp(s) {
 return digest({relations:s.relations,columns:s.columns.map(({default_sql,...v})=>v),
 constraints:s.constraints.map(({definition,...v})=>v),indexes:s.indexes.map(({definition,...v})=>v),sequences:s.sequences,
 triggers:s.triggers.map(({definition,...v})=>v),functions:s.functions.map(({definition,identity_arguments,...v})=>v),counts:s.counts});
}
export function safePrototypeSummary(s) {
 return {catalogSha256:digest(s),counts:s.counts,dependencyCount:s.dependencies.length,unsupported:s.unsupported,
  columns:s.columns.map(c=>({table:c.relname,name:c.attname,type:c.type,notNull:c.attnotnull,defaultSha256:digest(c.default_sql)})),
  constraintCount:s.constraints.length,indexCount:s.indexes.length,triggerCount:s.triggers.length,ownedSequenceCount:s.sequences.length,
  functions:s.functions.map(f=>({name:f.proname,signatureSha256:digest(f.identity_arguments),definitionSha256:digest(f.definition),securityInvoker:f.prosecdef===false,apiExecute:f.api_execute,publicExecute:f.public_execute}))};
}
export async function assertFreshPublic(db) {
 const r=(await db.query(`SELECT to_regclass('public.star_wallet_schema_migrations') IS NOT NULL AS history_exists,
 to_regnamespace('wallet_prototype_v1') IS NOT NULL AS archive_exists,
  ARRAY(SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY($1::text[]) AND c.relname<>'star_wallets') AS conflicts,
  ARRAY(SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname=ANY($2::text[])) AS function_conflicts`,[CANONICAL_TABLES,CANONICAL_FUNCTIONS])).rows[0];
 if(!r||r.history_exists||r.archive_exists||r.conflicts?.length||r.function_conflicts?.length) qaFail('QA_BASELINE_NOT_FRESH');
}
export async function verifyInstalledBaseline(db,before) {
 const after=await inspectPrototype(db,'wallet_prototype_v1');validatePrototype(after);
 if(preservationStamp(after)!==preservationStamp(before)) qaFail('QA_ARCHIVE_PRESERVATION_FAILED');
 const quarantine=(await db.query(`SELECT to_regclass('public.star_transactions') IS NULL AS old_table_absent,
 NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname='process_star_transaction') AS old_function_absent,
 NOT has_schema_privilege('lunari_wallet_api_check','wallet_prototype_v1','USAGE') AS api_quarantined`)).rows[0];
 if(!quarantine||!['old_table_absent','old_function_absent','api_quarantined'].every(k=>quarantine[k]===true))qaFail('QA_ARCHIVE_ACCESS_FAILED');
 const tables=(await db.query(`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND c.relname=ANY($1::text[]) ORDER BY c.relname`,[CANONICAL_TABLES])).rows.map(r=>r.relname).sort();
 if(JSON.stringify(tables)!==JSON.stringify([...CANONICAL_TABLES].sort())) qaFail('QA_CANONICAL_TABLES_MISSING');
 const columns=(await db.query(`SELECT a.attname,format_type(a.atttypid,a.atttypmod) AS type,a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.star_wallets'::regclass AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`)).rows;
 if(columns.length!==4||columns[0]?.attname!=='user_uid'||columns[0]?.type!=='character varying(128)'||columns.some(c=>!c.attnotnull)) qaFail('QA_CANONICAL_WALLET_INVALID');
 const functions=(await db.query(`SELECT p.proname,p.prosecdef,p.proconfig,
 has_function_privilege('lunari_wallet_api_check',p.oid,'EXECUTE') AS api_execute,
 EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname=ANY($1::text[]) ORDER BY p.proname`,[CANONICAL_FUNCTIONS])).rows;
 if(functions.length!==6||new Set(functions.map(f=>f.proname)).size!==6||functions.some(f=>f.api_execute!==false||f.public_execute!==false||
   (f.proname==='star_wallet_reject_ledger_mutation'?f.prosecdef!==false:f.prosecdef!==true||JSON.stringify(f.proconfig)!=='["search_path=pg_catalog"]'))) qaFail('QA_CANONICAL_FUNCTION_POLICY_FAILED');
 const writes=(await db.query(`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY($1::text[]) AND (has_table_privilege('lunari_wallet_api_check',c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') OR has_any_column_privilege('lunari_wallet_api_check',c.oid,'INSERT,UPDATE'))`,[CANONICAL_TABLES])).rows;
 if(writes.length) qaFail('QA_API_WRITE_GRANT_DETECTED');
 for(const table of CANONICAL_TABLES) if(Number((await db.query('SELECT count(*)::text AS count FROM public.'+table)).rows[0].count)!==0) qaFail('QA_UNEXPECTED_CANONICAL_DATA');
 await assertApiSafety(db);
 return {canonicalTableCount:tables.length,prototypePreserved:true,apiWritesEnabled:false,legacyFunctionEnabled:false};
}
